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

/**
 * @defgroup psk_radius_lookup psk_radius_lookup
 * @{ @ingroup psk_radius
 */

#ifndef PSK_RADIUS_LOOKUP_H_
#define PSK_RADIUS_LOOKUP_H_

#include <library.h>
#include <networking/host.h>
#include <utils/identification.h>
#include <collections/linked_list.h>
#include <attributes/attributes.h>
#include <sa/ike_sa.h>

typedef struct psk_radius_entry_t psk_radius_entry_t;
typedef struct psk_radius_attribute_t psk_radius_attribute_t;
typedef struct psk_radius_lookup_t psk_radius_lookup_t;

/**
 * What the RADIUS server returned for a peer identity.
 */
struct psk_radius_entry_t {

	/** pre-shared key, from Tunnel-Password */
	chunk_t psk;

	/** IPv4 virtual IP, from Framed-IP-Address, or NULL */
	host_t *vip4;

	/** IPv6 virtual IP, from Framed-IPv6-Address, or NULL */
	host_t *vip6;

	/** configuration attributes (DNS servers), psk_radius_attribute_t */
	linked_list_t *attributes;
};

/**
 * A configuration attribute to send to the peer.
 */
struct psk_radius_attribute_t {

	/** attribute type */
	configuration_attribute_type_t type;

	/** attribute data */
	chunk_t data;
};

/**
 * Clone an entry.
 *
 * @param entry			entry to clone
 * @return				independent copy
 */
psk_radius_entry_t *psk_radius_entry_clone(psk_radius_entry_t *entry);

/**
 * Destroy an entry, wiping the pre-shared key.
 *
 * @param entry			entry to destroy
 */
void psk_radius_entry_destroy(psk_radius_entry_t *entry);

/**
 * Looks up the pre-shared key and virtual IPs of a peer identity in RADIUS.
 */
struct psk_radius_lookup_t {

	/**
	 * Look up a peer identity, in the cache or with an Access-Request.
	 *
	 * @param id		peer identity
	 * @param ike_sa	IKE_SA of the request, for Calling/Called-Station-Id,
	 *					or NULL
	 * @return			entry (to destroy), or NULL if the identity is out of
	 *					scope, unknown, or the server failed
	 */
	psk_radius_entry_t *(*lookup)(psk_radius_lookup_t *this,
								  identification_t *id, ike_sa_t *ike_sa);

	/**
	 * Destroy a psk_radius_lookup_t.
	 */
	void (*destroy)(psk_radius_lookup_t *this);
};

/**
 * Create a psk_radius_lookup_t from strongswan.conf.
 *
 * @return					lookup, or NULL if no RADIUS server is configured
 */
psk_radius_lookup_t *psk_radius_lookup_create();

#endif /** PSK_RADIUS_LOOKUP_H_ @}*/
