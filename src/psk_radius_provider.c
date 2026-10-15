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

#include "psk_radius_provider.h"

#include <daemon.h>

typedef struct private_psk_radius_provider_t private_psk_radius_provider_t;

struct private_psk_radius_provider_t {

	/** public interface */
	psk_radius_provider_t public;

	/** RADIUS lookup */
	psk_radius_lookup_t *lookup;
};

static bool has_pool(linked_list_t *pools)
{
	return pools->find_first(pools, linked_list_match_str, NULL,
							 PSK_RADIUS_POOL);
}

METHOD(attribute_provider_t, acquire_address, host_t*,
	private_psk_radius_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, host_t *requested)
{
	psk_radius_entry_t *entry;
	host_t *vip = NULL;

	if (!has_pool(pools))
	{
		return NULL;
	}
	entry = this->lookup->lookup(this->lookup, ike_sa->get_other_eap_id(ike_sa),
								 ike_sa);
	if (!entry)
	{
		return NULL;
	}
	switch (requested->get_family(requested))
	{
		case AF_INET:
			vip = entry->vip4 ? entry->vip4->clone(entry->vip4) : NULL;
			break;
		case AF_INET6:
			vip = entry->vip6 ? entry->vip6->clone(entry->vip6) : NULL;
			break;
		default:
			break;
	}
	psk_radius_entry_destroy(entry);
	if (!vip)
	{
		DBG1(DBG_CFG, "psk-radius: no %s virtual IP for '%Y'",
			 requested->get_family(requested) == AF_INET6 ? "IPv6" : "IPv4",
			 ike_sa->get_other_eap_id(ike_sa));
	}
	return vip;
}

METHOD(attribute_provider_t, release_address, bool,
	private_psk_radius_provider_t *this, linked_list_t *pools,
	host_t *address, ike_sa_t *ike_sa)
{
	/* addresses are fixed per identity, there are no leases to release */
	return has_pool(pools);
}

/**
 * Enumerator over the configuration attributes of an entry.
 */
typedef struct {

	/** implements enumerator_t */
	enumerator_t public;

	/** enumerator over entry->attributes */
	enumerator_t *inner;

	/** the entry, owned */
	psk_radius_entry_t *entry;
} attribute_enumerator_t;

METHOD(enumerator_t, attribute_enumerate, bool,
	attribute_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	psk_radius_attribute_t *attribute;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);

	if (this->inner->enumerate(this->inner, &attribute))
	{
		*type = attribute->type;
		*data = attribute->data;
		return TRUE;
	}
	return FALSE;
}

METHOD(enumerator_t, attribute_destroy, void,
	attribute_enumerator_t *this)
{
	this->inner->destroy(this->inner);
	psk_radius_entry_destroy(this->entry);
	free(this);
}

METHOD(attribute_provider_t, create_attribute_enumerator, enumerator_t*,
	private_psk_radius_provider_t *this, linked_list_t *pools,
	ike_sa_t *ike_sa, linked_list_t *vips)
{
	attribute_enumerator_t *enumerator;
	psk_radius_entry_t *entry;

	if (!has_pool(pools))
	{
		return enumerator_create_empty();
	}
	entry = this->lookup->lookup(this->lookup, ike_sa->get_other_eap_id(ike_sa),
								 ike_sa);
	if (!entry)
	{
		return enumerator_create_empty();
	}
	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _attribute_enumerate,
			.destroy = _attribute_destroy,
		},
		.inner = entry->attributes->create_enumerator(entry->attributes),
		.entry = entry,
	);
	return &enumerator->public;
}

METHOD(psk_radius_provider_t, destroy, void,
	private_psk_radius_provider_t *this)
{
	free(this);
}

/*
 * Described in header
 */
psk_radius_provider_t *psk_radius_provider_create(psk_radius_lookup_t *lookup)
{
	private_psk_radius_provider_t *this;

	INIT(this,
		.public = {
			.provider = {
				.acquire_address = _acquire_address,
				.release_address = _release_address,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.lookup = lookup,
	);
	return &this->public;
}
