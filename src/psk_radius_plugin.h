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
 * @defgroup psk_radius psk_radius
 * @ingroup cplugins
 *
 * @defgroup psk_radius_plugin psk_radius_plugin
 * @{ @ingroup psk_radius
 */

#ifndef PSK_RADIUS_PLUGIN_H_
#define PSK_RADIUS_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct psk_radius_plugin_t psk_radius_plugin_t;

/**
 * Plugin looking up IKE pre-shared keys and virtual IPs in RADIUS.
 */
struct psk_radius_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** PSK_RADIUS_PLUGIN_H_ @}*/
