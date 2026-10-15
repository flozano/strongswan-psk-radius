# strongswan-psk-radius

A [strongSwan](https://www.strongswan.org/) plugin that looks up IKE
pre-shared keys, and optionally virtual IPs and DNS servers, in RADIUS when a
peer connects.

strongSwan reads pre-shared keys from its configuration (`swanctl.conf`,
`ipsec.secrets`, SQL), so every key has to be loaded on the gateway before a
peer can use it. With this plugin the gateway asks a RADIUS server for the key
of the identity that is connecting, the way commercial gateways fetch per-peer
keys from AAA. Keys stay in whatever backs the RADIUS server (a users file,
SQL, LDAP, a REST service via `rlm_rest`, a script via `rlm_exec`, ...).

This is useful when many peers each have their own key, and when peers can't
do EAP: most routers only offer pre-shared keys or certificates for IKEv2.

## How it works

1. A peer starts an IKEv2 exchange and authenticates with a pre-shared key,
   sending its identity (e.g. `site-1.example.com`) in IKE_AUTH.
2. charon needs the key for that identity and asks its credential sets, which
   include this plugin's.
3. The plugin sends the RADIUS server an Access-Request:
   - `User-Name` = the peer identity
   - `Service-Type` = `Authorize-Only` (RFC 5176), and no password
   - `NAS-Port-Type` = `Virtual`
   - `Calling-Station-Id` / `Called-Station-Id` = the peer / gateway address
   - `NAS-Identifier`, `Message-Authenticator`
4. An Access-Accept carries:
   - `Tunnel-Password` (RFC 2868): the pre-shared key, encrypted with the
     RADIUS shared secret (required)
   - `Framed-IP-Address` / `Framed-IPv6-Address`: the peer's virtual IPs
     (optional)
   - `MS-Primary-DNS-Server` / `MS-Secondary-DNS-Server` and
     `DNS-Server-IPv6-Address`: DNS servers sent to the peer (optional)
5. charon verifies the peer's AUTH with the key. Connections with
   `pools = psk-radius` assign the virtual IPs and DNS servers from the same
   answer.

An Access-Reject, or no answer, means there is no key for that identity and
the peer gets AUTHENTICATION_FAILED. Answers are cached for `cache_ttl`
seconds (60 by default) and rejections for `negative_cache_ttl` seconds (10),
so the several lookups charon makes during one IKE_AUTH send a single request.

## Requirements

- strongSwan 6.x with charon, built with `libradius` (the `eap-radius` plugin
  needs it too, so most distribution packages have it).
- The exact strongSwan version the plugin runs with. strongSwan has no stable
  plugin ABI, and charon refuses to load a plugin built for another version.
- A RADIUS server that answers `Authorize-Only` requests with
  `Tunnel-Password`. See [FreeRADIUS](#freeradius) below.

Tested with strongSwan 6.0.6 (EPEL 9) and FreeRADIUS 3.0.

## Building

### RPM for EL9 with EPEL's strongSwan

    contrib/build-el9-epel.sh            # EPEL's current strongswan
    contrib/build-el9-epel.sh 6.0.6-1.el9

This builds EPEL's strongSwan source package in an AlmaLinux 9 container
(podman or docker) and writes `out/strongswan-psk-radius-*.rpm`. The package
requires exactly the strongswan package it was built against. CI builds the
same RPM, runs the integration test and attaches the RPM to tagged releases.

### Any other strongSwan

Configure and build the strongSwan source of the version you run, with the
same options as your package, then:

    make STRONGSWAN_SRC=/path/to/strongswan-6.0.6 LIBDIR=/usr/lib/ipsec
    sudo make install LIBDIR=/usr/lib/ipsec

`LIBDIR` is where `libstrongswan.so.0`, `libcharon.so.0` and `libradius.so.0`
are installed: `/usr/lib/ipsec` upstream and on Debian/Ubuntu,
`/usr/lib64/strongswan` on Fedora/RHEL. The plugin goes to `$(LIBDIR)/plugins`.

## Configuration

### strongswan.conf

`/etc/strongswan/strongswan.d/charon/psk-radius.conf` on Fedora/RHEL,
`/etc/strongswan.d/charon/psk-radius.conf` on Debian/Ubuntu:

    psk-radius {
        load = yes
        server = 127.0.0.1
        secret = change-me-to-a-long-random-secret
    }

| Option | Default | |
|---|---|---|
| `server` | | address of the RADIUS server |
| `secret` | | shared secret with the RADIUS server |
| `port` | `1812` | authentication port |
| `source` | | source address for requests |
| `nas_identifier` | `strongSwan` | `NAS-Identifier` |
| `sockets` | `1` | sockets, i.e. parallel requests, per server |
| `retransmit_tries` | `3` | retransmissions per request |
| `retransmit_timeout` | `1.0` | retransmission timeout in seconds |
| `retransmit_base` | `1.4` | base of the exponential backoff |
| `identities` | all | comma-separated identity patterns to look up, e.g. `*@example.com, *.sites.example.com` |
| `key_id_as_string` | `yes` | send printable `ID_KEY_ID` identities as plain strings |
| `station_id_with_port` | `yes` | include the port in `Calling-Station-Id` and `Called-Station-Id` |
| `cache_ttl` | `60` | seconds to cache answers |
| `negative_cache_ttl` | `10` | seconds to cache rejections |

Several servers can be configured in a `servers` section, as with
`eap-radius`. Each takes the options above (`address` instead of `server`,
`auth_port` or `port`) plus a `preference`; missing options fall back to the
global ones. Requests go to the server with the best preference and health:

    psk-radius {
        load = yes
        secret = shared-by-both
        servers {
            primary {
                address = 192.0.2.10
                preference = 1
            }
            secondary {
                address = 192.0.2.11
            }
        }
    }

Lookups are synchronous in the charon thread that handles the IKE_SA, so keep
retransmissions short. With `identities` set, only matching identities are
looked up; this keeps RADIUS out of the way of keys configured elsewhere.

### swanctl.conf

    connections {
        sites {
            version = 2
            pools = psk-radius
            encap = yes
            local {
                auth = psk
                id = vpn.example.com
            }
            remote {
                auth = psk
            }
            children {
                sites {
                    local_ts = 192.0.2.1/32
                }
            }
        }
    }

With `auth = psk` both ways, the gateway authenticates with the peer's key
too. The gateway can authenticate with a certificate instead
(`local { auth = pubkey }`) when the peer supports it. `pools = psk-radius`
is only needed for virtual IPs and DNS servers. Peers have to request a
virtual IP (a CFG_REQUEST, e.g. `vips = 0.0.0.0`); the pool never hands out
addresses RADIUS did not return. See [`examples/`](examples/).

### FreeRADIUS

[`examples/freeradius/`](examples/freeradius/) has a virtual server that only
listens on localhost and only answers `Authorize-Only` requests, from the
users file:

    site-1.example.com	Service-Type == Authorize-Only, Auth-Type := Accept
    	Tunnel-Password = "use-a-long-random-key-per-peer-1",
    	Framed-IP-Address = 10.10.0.10,
    	MS-Primary-DNS-Server = 10.10.0.1

Any other FreeRADIUS module can produce the same reply. To answer from an
external service, use `rlm_rest` or `rlm_exec` in `authorize`, set
`Auth-Type := Accept` and add `Tunnel-Password` and `Framed-IP-Address` to the
reply. Other RADIUS servers work if they can answer without a password and
send `Tunnel-Password`.

## Security

- **Keep `Authorize-Only` answers to this plugin.** The RADIUS server hands
  out keys to anyone with the shared secret who asks. Run it on the gateway or
  a private network, with a long random secret, and answer key lookups only
  to `Authorize-Only` requests, never to ordinary logins.
- **Use long random keys**, one per peer. An attacker who completes
  IKE_SA_INIT and gets an initiator's AUTH can try to guess the key offline;
  that is only practical for weak, human-chosen keys.
- **Cached keys live in charon's memory** for `cache_ttl` seconds, as keys
  from swanctl.conf do.
- **Revocation**: once RADIUS stops returning a key, new IKE_SAs fail after
  the cache expires. Existing IKE_SAs are not affected; terminate them with
  `swanctl --terminate --ike-id`.
- Every new identity costs a RADIUS request. Unknown identities are cached as
  rejections, and `identities` limits what is looked up.

## Limitations

- **IKEv2 only, in practice.** IKEv1 main mode needs the key before the peer's
  identity is known, so a lookup by identity only works in aggressive mode.
- **One key for both directions.** IKEv2 allows different keys per direction;
  only `Tunnel-Password` is used for both.
- **No RADIUS accounting** for these IKE_SAs.

## License

GPL-2.0-or-later, like strongSwan. See [LICENSE](LICENSE).
