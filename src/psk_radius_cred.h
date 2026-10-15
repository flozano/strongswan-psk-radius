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
 * @defgroup psk_radius_cred psk_radius_cred
 * @{ @ingroup psk_radius
 */

#ifndef PSK_RADIUS_CRED_H_
#define PSK_RADIUS_CRED_H_

#include "psk_radius_lookup.h"

#include <credentials/credential_set.h>

typedef struct psk_radius_cred_t psk_radius_cred_t;

/**
 * Credential set providing IKE pre-shared keys looked up in RADIUS.
 */
struct psk_radius_cred_t {

	/**
	 * Implements credential_set_t.
	 */
	credential_set_t set;

	/**
	 * Destroy a psk_radius_cred_t.
	 */
	void (*destroy)(psk_radius_cred_t *this);
};

/**
 * Create a psk_radius_cred_t.
 *
 * @param lookup			RADIUS lookup to use
 * @return					credential set
 */
psk_radius_cred_t *psk_radius_cred_create(psk_radius_lookup_t *lookup);

#endif /** PSK_RADIUS_CRED_H_ @}*/
