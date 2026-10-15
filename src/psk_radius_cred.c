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

#include "psk_radius_cred.h"

#include <daemon.h>
#include <credentials/keys/shared_key.h>

typedef struct private_psk_radius_cred_t private_psk_radius_cred_t;

struct private_psk_radius_cred_t {

	/** public interface */
	psk_radius_cred_t public;

	/** RADIUS lookup */
	psk_radius_lookup_t *lookup;
};

/**
 * Enumerator over the single key found for a peer.
 */
typedef struct {

	/** implements enumerator_t */
	enumerator_t public;

	/** the key */
	shared_key_t *key;

	/** whether the key was returned */
	bool done;
} shared_enumerator_t;

METHOD(enumerator_t, shared_enumerate, bool,
	shared_enumerator_t *this, va_list args)
{
	shared_key_t **key;
	id_match_t *me, *other;

	VA_ARGS_VGET(args, key, me, other);

	if (this->done)
	{
		return FALSE;
	}
	this->done = TRUE;
	*key = this->key;
	if (me)
	{	/* the key is not bound to our identity */
		*me = ID_MATCH_ANY;
	}
	if (other)
	{
		*other = ID_MATCH_PERFECT;
	}
	return TRUE;
}

METHOD(enumerator_t, shared_destroy, void,
	shared_enumerator_t *this)
{
	this->key->destroy(this->key);
	free(this);
}

METHOD(credential_set_t, create_shared_enumerator, enumerator_t*,
	private_psk_radius_cred_t *this, shared_key_type_t type,
	identification_t *me, identification_t *other)
{
	shared_enumerator_t *enumerator;
	psk_radius_entry_t *entry;

	if ((type != SHARED_IKE && type != SHARED_ANY) ||
		!other || other->get_type(other) == ID_ANY)
	{
		return NULL;
	}
	entry = this->lookup->lookup(this->lookup, other,
								 charon->bus->get_sa(charon->bus));
	if (!entry)
	{
		return NULL;
	}
	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _shared_enumerate,
			.destroy = _shared_destroy,
		},
		.key = shared_key_create(SHARED_IKE, chunk_clone(entry->psk)),
	);
	psk_radius_entry_destroy(entry);
	return &enumerator->public;
}

METHOD(psk_radius_cred_t, destroy, void,
	private_psk_radius_cred_t *this)
{
	free(this);
}

/*
 * Described in header
 */
psk_radius_cred_t *psk_radius_cred_create(psk_radius_lookup_t *lookup)
{
	private_psk_radius_cred_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = _create_shared_enumerator,
				.create_private_enumerator = (void*)return_null,
				.create_cert_enumerator = (void*)return_null,
				.create_cdp_enumerator = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
		.lookup = lookup,
	);
	return &this->public;
}
