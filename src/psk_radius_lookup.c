/*
 * Copyright (C) 2026 Francisco A. Lozano
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "psk_radius_lookup.h"

#include <daemon.h>
#include <collections/hashtable.h>
#include <threading/mutex.h>
#include <threading/rwlock.h>
#include <pen/pen.h>

#include <radius_client.h>
#include <radius_config.h>
#include <radius_message.h>

#define PREFIX "%s.plugins.psk-radius"

/** default RADIUS authentication port */
#define RADIUS_PORT_DEFAULT 1812

/** RFC 5176 Service-Type Authorize-Only */
#define SERVICE_TYPE_AUTHORIZE_ONLY 17

/** RFC 2865 NAS-Port-Type Virtual */
#define NAS_PORT_TYPE_VIRTUAL 5

/** RFC 2548 Microsoft vendor-specific attributes */
#define MS_PRIMARY_DNS_SERVER 28
#define MS_SECONDARY_DNS_SERVER 29

typedef struct private_psk_radius_lookup_t private_psk_radius_lookup_t;

struct private_psk_radius_lookup_t {

	/** public interface */
	psk_radius_lookup_t public;

	/** RADIUS servers, server_t */
	linked_list_t *servers;

	/** lock for servers */
	rwlock_t *lock;

	/** identity patterns to look up, identification_t, empty for all */
	linked_list_t *identities;

	/** send printable ID_KEY_ID identities as plain strings */
	bool key_id_as_string;

	/** include the port in Calling-Station-Id and Called-Station-Id */
	bool station_id_with_port;

	/** lifetime of cached entries, in seconds */
	uint32_t cache_ttl;

	/** lifetime of cached rejections, in seconds */
	uint32_t negative_cache_ttl;

	/** User-Name => cache_entry_t */
	hashtable_t *cache;

	/** lock for cache */
	mutex_t *mutex;
};

/**
 * A RADIUS server, with its secret to decrypt Tunnel-Password.
 */
typedef struct {

	/** server configuration */
	radius_config_t *config;

	/** shared secret */
	chunk_t secret;
} server_t;

static void server_destroy(server_t *this)
{
	this->config->destroy(this->config);
	chunk_clear(&this->secret);
	free(this);
}

/**
 * A cached lookup result, with an entry or a rejection.
 */
typedef struct {

	/** User-Name, the hashtable key */
	char *name;

	/** entry, NULL for a rejection */
	psk_radius_entry_t *entry;

	/** monotonic time this expires */
	time_t expires;
} cache_entry_t;

static void cache_entry_destroy(cache_entry_t *this)
{
	if (this->entry)
	{
		psk_radius_entry_destroy(this->entry);
	}
	free(this->name);
	free(this);
}

static psk_radius_entry_t *entry_create()
{
	psk_radius_entry_t *entry;

	INIT(entry,
		.attributes = linked_list_create(),
	);
	return entry;
}

static void add_attribute(psk_radius_entry_t *entry,
						  configuration_attribute_type_t type, chunk_t data)
{
	psk_radius_attribute_t *attribute;

	INIT(attribute,
		.type = type,
		.data = chunk_clone(data),
	);
	entry->attributes->insert_last(entry->attributes, attribute);
}

static void attribute_destroy(psk_radius_attribute_t *this)
{
	chunk_free(&this->data);
	free(this);
}

/*
 * Described in header
 */
psk_radius_entry_t *psk_radius_entry_clone(psk_radius_entry_t *entry)
{
	psk_radius_entry_t *clone;
	psk_radius_attribute_t *attribute;
	enumerator_t *enumerator;

	clone = entry_create();
	clone->psk = chunk_clone(entry->psk);
	clone->vip4 = entry->vip4 ? entry->vip4->clone(entry->vip4) : NULL;
	clone->vip6 = entry->vip6 ? entry->vip6->clone(entry->vip6) : NULL;
	enumerator = entry->attributes->create_enumerator(entry->attributes);
	while (enumerator->enumerate(enumerator, &attribute))
	{
		add_attribute(clone, attribute->type, attribute->data);
	}
	enumerator->destroy(enumerator);
	return clone;
}

/*
 * Described in header
 */
void psk_radius_entry_destroy(psk_radius_entry_t *entry)
{
	chunk_clear(&entry->psk);
	DESTROY_IF(entry->vip4);
	DESTROY_IF(entry->vip6);
	entry->attributes->destroy_function(entry->attributes,
										(void*)attribute_destroy);
	free(entry);
}

/**
 * Whether an identity is in scope.
 */
static bool in_scope(private_psk_radius_lookup_t *this, identification_t *id)
{
	identification_t *pattern;
	enumerator_t *enumerator;
	bool match;

	if (this->identities->get_count(this->identities) == 0)
	{
		return TRUE;
	}
	match = FALSE;
	enumerator = this->identities->create_enumerator(this->identities);
	while (enumerator->enumerate(enumerator, &pattern))
	{
		if (id->matches(id, pattern) > ID_MATCH_NONE)
		{
			match = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return match;
}

/**
 * The identity as RADIUS User-Name.
 */
static void get_user_name(private_psk_radius_lookup_t *this,
						  identification_t *id, char *buf, size_t len)
{
	chunk_t data = id->get_encoding(id);

	if (this->key_id_as_string && id->get_type(id) == ID_KEY_ID &&
		data.len && data.len < len && chunk_printable(data, NULL, 0))
	{
		memcpy(buf, data.ptr, data.len);
		buf[data.len] = '\0';
		return;
	}
	snprintf(buf, len, "%Y", id);
}

/**
 * Select the RADIUS server with the best preference, as eap-radius does, and
 * return a client for it and a copy of its secret.
 */
static radius_client_t *create_client(private_psk_radius_lookup_t *this,
									  chunk_t *secret)
{
	server_t *server, *selected = NULL;
	radius_client_t *client = NULL;
	enumerator_t *enumerator;
	int current, best = -1;

	this->lock->read_lock(this->lock);
	enumerator = this->servers->create_enumerator(this->servers);
	while (enumerator->enumerate(enumerator, &server))
	{
		current = server->config->get_preference(server->config);
		if (current > best || (current == best && random() % 2 == 0))
		{
			best = current;
			selected = server;
		}
	}
	enumerator->destroy(enumerator);
	if (selected)
	{
		client = radius_client_create(
							selected->config->get_ref(selected->config));
		if (client)
		{
			*secret = chunk_clone(selected->secret);
		}
	}
	this->lock->unlock(this->lock);
	return client;
}

/**
 * Decrypt a Tunnel-Password attribute: Tag (1), Salt (2) and a String whose
 * first decrypted octet is the password length (RFC 2868, 3.5).
 */
static bool decrypt_tunnel_password(radius_message_t *request,
									chunk_t secret, hasher_t *hasher,
									chunk_t data, chunk_t *psk)
{
	chunk_t salt, in, out;
	bool ok;

	if (data.len < 3 + HASH_SIZE_MD5 || (data.len - 3) % HASH_SIZE_MD5)
	{
		return FALSE;
	}
	salt = chunk_create(data.ptr + 1, 2);
	in = chunk_create(data.ptr + 3, data.len - 3);
	out = chunk_alloca(in.len);

	ok = request->crypt(request, salt, in, out, secret, hasher) &&
		 out.ptr[0] > 0 && out.ptr[0] < out.len;
	if (ok)
	{
		chunk_clear(psk);
		*psk = chunk_clone(chunk_create(out.ptr + 1, out.ptr[0]));
	}
	memwipe(out.ptr, out.len);
	return ok;
}

/**
 * Read the attributes we use from an Access-Accept.
 */
static void process_accept(radius_message_t *request,
						   radius_message_t *response, chunk_t secret,
						   psk_radius_entry_t *entry, char *name)
{
	enumerator_t *enumerator;
	hasher_t *hasher;
	chunk_t data;
	int type, vendor;

	hasher = lib->crypto->create_hasher(lib->crypto, HASH_MD5);
	enumerator = response->create_enumerator(response);
	while (enumerator->enumerate(enumerator, &type, &data))
	{
		switch (type)
		{
			case RAT_TUNNEL_PASSWORD:
				if (!hasher ||
					!decrypt_tunnel_password(request, secret, hasher, data,
											 &entry->psk))
				{
					DBG1(DBG_CFG, "psk-radius: invalid Tunnel-Password for "
						 "'%s'", name);
				}
				break;
			case RAT_FRAMED_IP_ADDRESS:
				if (data.len == 4)
				{
					DESTROY_IF(entry->vip4);
					entry->vip4 = host_create_from_chunk(AF_INET, data, 0);
				}
				break;
			case RAT_FRAMED_IPV6_ADDRESS:
				if (data.len == 16)
				{
					DESTROY_IF(entry->vip6);
					entry->vip6 = host_create_from_chunk(AF_INET6, data, 0);
				}
				break;
			case RAT_FRAMED_IPV6_DNS_SERVER:
				if (data.len == 16)
				{
					add_attribute(entry, INTERNAL_IP6_DNS, data);
				}
				break;
			default:
				break;
		}
	}
	enumerator->destroy(enumerator);

	enumerator = response->create_vendor_enumerator(response);
	while (enumerator->enumerate(enumerator, &vendor, &type, &data))
	{
		if (vendor == PEN_MICROSOFT && data.len == 4 &&
			(type == MS_PRIMARY_DNS_SERVER || type == MS_SECONDARY_DNS_SERVER))
		{
			add_attribute(entry, INTERNAL_IP4_DNS, data);
		}
	}
	enumerator->destroy(enumerator);
	DESTROY_IF(hasher);
}

/**
 * Send an Access-Request for an identity.
 */
static psk_radius_entry_t *query(private_psk_radius_lookup_t *this,
								 char *name, ike_sa_t *ike_sa)
{
	radius_client_t *client;
	radius_message_t *request, *response;
	psk_radius_entry_t *entry = NULL;
	uint32_t service = htonl(SERVICE_TYPE_AUTHORIZE_ONLY);
	uint32_t port_type = htonl(NAS_PORT_TYPE_VIRTUAL);
	chunk_t secret = chunk_empty;
	char station[BUF_LEN];

	client = create_client(this, &secret);
	if (!client)
	{
		DBG1(DBG_CFG, "psk-radius: no RADIUS server available");
		return NULL;
	}
	request = radius_message_create(RMC_ACCESS_REQUEST);
	request->add(request, RAT_USER_NAME, chunk_from_str(name));
	request->add(request, RAT_SERVICE_TYPE, chunk_from_thing(service));
	request->add(request, RAT_NAS_PORT_TYPE, chunk_from_thing(port_type));
	if (ike_sa)
	{
		snprintf(station, sizeof(station), this->station_id_with_port ?
				 "%#H" : "%H", ike_sa->get_other_host(ike_sa));
		request->add(request, RAT_CALLING_STATION_ID, chunk_from_str(station));
		snprintf(station, sizeof(station), this->station_id_with_port ?
				 "%#H" : "%H", ike_sa->get_my_host(ike_sa));
		request->add(request, RAT_CALLED_STATION_ID, chunk_from_str(station));
	}

	response = client->request(client, request);
	if (response && response->get_code(response) == RMC_ACCESS_ACCEPT)
	{
		entry = entry_create();
		process_accept(request, response, secret, entry, name);
		if (!entry->psk.len)
		{
			DBG1(DBG_CFG, "psk-radius: no Tunnel-Password for '%s'", name);
			psk_radius_entry_destroy(entry);
			entry = NULL;
		}
	}
	else if (response)
	{
		DBG1(DBG_CFG, "psk-radius: no pre-shared key for '%s'", name);
	}
	DESTROY_IF(response);
	request->destroy(request);
	client->destroy(client);
	chunk_clear(&secret);
	return entry;
}

METHOD(psk_radius_lookup_t, lookup, psk_radius_entry_t*,
	private_psk_radius_lookup_t *this, identification_t *id, ike_sa_t *ike_sa)
{
	cache_entry_t *cached;
	psk_radius_entry_t *entry;
	char name[BUF_LEN];
	time_t now;

	if (!in_scope(this, id))
	{
		return NULL;
	}
	get_user_name(this, id, name, sizeof(name));
	now = time_monotonic(NULL);

	this->mutex->lock(this->mutex);
	cached = this->cache->get(this->cache, name);
	if (cached && cached->expires > now)
	{
		entry = cached->entry ? psk_radius_entry_clone(cached->entry) : NULL;
		this->mutex->unlock(this->mutex);
		return entry;
	}
	this->mutex->unlock(this->mutex);

	entry = query(this, name, ike_sa);

	INIT(cached,
		.name = strdup(name),
		.entry = entry ? psk_radius_entry_clone(entry) : NULL,
		.expires = now + (entry ? this->cache_ttl : this->negative_cache_ttl),
	);
	this->mutex->lock(this->mutex);
	cached = this->cache->put(this->cache, cached->name, cached);
	this->mutex->unlock(this->mutex);
	if (cached)
	{
		cache_entry_destroy(cached);
	}
	return entry;
}

/**
 * Create the configuration of a RADIUS server, falling back to the global
 * options for anything a server section does not set.
 */
static server_t *load_server(char *name, char *section)
{
	server_t *server;
	radius_config_t *config;
	char *address, *source, *secret, *nas_identifier;
	int auth_port, sockets, preference;
	u_int tries;
	double timeout, base;

#define GET(type, key, def) lib->settings->get_##type(lib->settings, \
		section ? PREFIX ".servers.%s." key : PREFIX "." key, \
		lib->settings->get_##type(lib->settings, PREFIX "." key, def, \
								  lib->ns), lib->ns, section)

	address = section ? lib->settings->get_str(lib->settings,
							PREFIX ".servers.%s.address", NULL, lib->ns, section)
					  : lib->settings->get_str(lib->settings,
							PREFIX ".server", NULL, lib->ns);
	secret = GET(str, "secret", NULL);
	if (!address || !secret)
	{
		DBG1(DBG_CFG, "psk-radius: RADIUS server '%s' needs an address and a "
			 "secret", name);
		return NULL;
	}
	source = GET(str, "source", NULL);
	nas_identifier = GET(str, "nas_identifier", "strongSwan");
	auth_port = lib->settings->get_int(lib->settings,
					section ? PREFIX ".servers.%s.auth_port" : PREFIX ".port",
					lib->settings->get_int(lib->settings,
					section ? PREFIX ".servers.%s.port" : PREFIX ".port",
					RADIUS_PORT_DEFAULT, lib->ns, section), lib->ns, section);
	sockets = GET(int, "sockets", 1);
	preference = section ? lib->settings->get_int(lib->settings,
					PREFIX ".servers.%s.preference", 0, lib->ns, section) : 0;
	tries = GET(int, "retransmit_tries", 3);
	timeout = GET(double, "retransmit_timeout", 1.0);
	base = GET(double, "retransmit_base", 1.4);

#undef GET

	/* the accounting port is not used */
	config = radius_config_create(name, address, source, auth_port,
								  auth_port + 1, nas_identifier, secret,
								  sockets, preference, tries, timeout, base);
	if (!config)
	{
		DBG1(DBG_CFG, "psk-radius: invalid RADIUS server '%s'", name);
		return NULL;
	}
	INIT(server,
		.config = config,
		.secret = chunk_clone(chunk_from_str(secret)),
	);
	return server;
}

static void load_servers(private_psk_radius_lookup_t *this)
{
	enumerator_t *enumerator;
	server_t *server;
	char *section;

	if (lib->settings->get_str(lib->settings, PREFIX ".server", NULL, lib->ns))
	{
		server = load_server("psk-radius", NULL);
		if (server)
		{
			this->servers->insert_last(this->servers, server);
		}
	}
	enumerator = lib->settings->create_section_enumerator(lib->settings,
											PREFIX ".servers", lib->ns);
	while (enumerator->enumerate(enumerator, &section))
	{
		server = load_server(section, section);
		if (server)
		{
			this->servers->insert_last(this->servers, server);
		}
	}
	enumerator->destroy(enumerator);
	DBG1(DBG_CFG, "psk-radius: loaded %d RADIUS server configuration%s",
		 this->servers->get_count(this->servers),
		 this->servers->get_count(this->servers) == 1 ? "" : "s");
}

static void load_identities(private_psk_radius_lookup_t *this)
{
	enumerator_t *enumerator;
	char *patterns, *pattern;

	patterns = lib->settings->get_str(lib->settings, PREFIX ".identities",
									  NULL, lib->ns);
	if (!patterns)
	{
		return;
	}
	enumerator = enumerator_create_token(patterns, ",", " ");
	while (enumerator->enumerate(enumerator, &pattern))
	{
		this->identities->insert_last(this->identities,
								identification_create_from_string(pattern));
	}
	enumerator->destroy(enumerator);
}

METHOD(psk_radius_lookup_t, destroy, void,
	private_psk_radius_lookup_t *this)
{
	enumerator_t *enumerator;
	cache_entry_t *cached;

	enumerator = this->cache->create_enumerator(this->cache);
	while (enumerator->enumerate(enumerator, NULL, &cached))
	{
		cache_entry_destroy(cached);
	}
	enumerator->destroy(enumerator);
	this->cache->destroy(this->cache);
	this->servers->destroy_function(this->servers, (void*)server_destroy);
	this->identities->destroy_offset(this->identities,
									 offsetof(identification_t, destroy));
	this->mutex->destroy(this->mutex);
	this->lock->destroy(this->lock);
	free(this);
}

/*
 * Described in header
 */
psk_radius_lookup_t *psk_radius_lookup_create()
{
	private_psk_radius_lookup_t *this;

	INIT(this,
		.public = {
			.lookup = _lookup,
			.destroy = _destroy,
		},
		.servers = linked_list_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.identities = linked_list_create(),
		.key_id_as_string = lib->settings->get_bool(lib->settings,
							PREFIX ".key_id_as_string", TRUE, lib->ns),
		.station_id_with_port = lib->settings->get_bool(lib->settings,
							PREFIX ".station_id_with_port", TRUE, lib->ns),
		.cache_ttl = lib->settings->get_time(lib->settings,
							PREFIX ".cache_ttl", 60, lib->ns),
		.negative_cache_ttl = lib->settings->get_time(lib->settings,
							PREFIX ".negative_cache_ttl", 10, lib->ns),
		.cache = hashtable_create(hashtable_hash_str, hashtable_equals_str, 32),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	load_servers(this);
	if (this->servers->get_count(this->servers) == 0)
	{
		DBG1(DBG_CFG, "psk-radius: no RADIUS server configured");
		destroy(this);
		return NULL;
	}
	load_identities(this);
	return &this->public;
}
