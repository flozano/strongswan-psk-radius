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

#include "psk_radius_plugin.h"
#include "psk_radius_lookup.h"
#include "psk_radius_cred.h"
#include "psk_radius_provider.h"

#include <daemon.h>

typedef struct private_psk_radius_plugin_t private_psk_radius_plugin_t;

struct private_psk_radius_plugin_t {

	/** public interface */
	psk_radius_plugin_t public;

	/** RADIUS lookup */
	psk_radius_lookup_t *lookup;

	/** credential set */
	psk_radius_cred_t *cred;

	/** attribute provider */
	psk_radius_provider_t *provider;
};

static bool register_cb(private_psk_radius_plugin_t *this,
						plugin_feature_t *feature, bool reg, void *data)
{
	if (reg)
	{
		this->lookup = psk_radius_lookup_create();
		if (!this->lookup)
		{
			return FALSE;
		}
		this->cred = psk_radius_cred_create(this->lookup);
		this->provider = psk_radius_provider_create(this->lookup);
		lib->credmgr->add_set(lib->credmgr, &this->cred->set);
		charon->attributes->add_provider(charon->attributes,
										 &this->provider->provider);
	}
	else if (this->lookup)
	{
		charon->attributes->remove_provider(charon->attributes,
											&this->provider->provider);
		lib->credmgr->remove_set(lib->credmgr, &this->cred->set);
		this->provider->destroy(this->provider);
		this->cred->destroy(this->cred);
		this->lookup->destroy(this->lookup);
		this->lookup = NULL;
	}
	return TRUE;
}

METHOD(plugin_t, get_name, char*,
	private_psk_radius_plugin_t *this)
{
	return "psk-radius";
}

METHOD(plugin_t, get_features, int,
	private_psk_radius_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)register_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "psk-radius"),
				PLUGIN_DEPENDS(HASHER, HASH_MD5),
				PLUGIN_DEPENDS(SIGNER, AUTH_HMAC_MD5_128),
				PLUGIN_DEPENDS(RNG, RNG_WEAK),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_psk_radius_plugin_t *this)
{
	free(this);
}

/*
 * Also defines psk_radius_plugin_version: charon refuses to load the plugin
 * into a strongSwan version other than the one it was built against.
 */
PLUGIN_DEFINE(psk_radius)
{
	private_psk_radius_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);
	return &this->public.plugin;
}
