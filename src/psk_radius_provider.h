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
 * @defgroup psk_radius_provider psk_radius_provider
 * @{ @ingroup psk_radius
 */

#ifndef PSK_RADIUS_PROVIDER_H_
#define PSK_RADIUS_PROVIDER_H_

#include "psk_radius_lookup.h"

#include <attributes/attribute_provider.h>

/**
 * Name of the pool connections reference to get virtual IPs from RADIUS.
 */
#define PSK_RADIUS_POOL "psk-radius"

typedef struct psk_radius_provider_t psk_radius_provider_t;

/**
 * Provides the virtual IPs and DNS servers RADIUS returned for a peer.
 */
struct psk_radius_provider_t {

	/**
	 * Implements attribute_provider_t.
	 */
	attribute_provider_t provider;

	/**
	 * Destroy a psk_radius_provider_t.
	 */
	void (*destroy)(psk_radius_provider_t *this);
};

/**
 * Create a psk_radius_provider_t.
 *
 * @param lookup			RADIUS lookup to use
 * @return					attribute provider
 */
psk_radius_provider_t *psk_radius_provider_create(psk_radius_lookup_t *lookup);

#endif /** PSK_RADIUS_PROVIDER_H_ @}*/
