#!/bin/bash
#
# Integration test: a gateway container (EL9, EPEL strongSwan with the plugin
# RPM, FreeRADIUS) and a client container (Alpine strongSwan) on a private
# network.
#
#   1. the client connects with its pre-shared key, gets the virtual IP and DNS
#      server RADIUS returned, and pings the gateway through the tunnel;
#   2. a wrong key is rejected;
#   3. an unknown identity is rejected.
#
# Usage: test/run.sh            # expects out/strongswan-psk-radius-*.rpm
#        KEEP=1 test/run.sh     # leave the containers running, to debug
#
# Uses podman, or docker if podman is not installed.
#
set -euo pipefail

cd "$(dirname "$0")/.."
ENGINE=$(command -v podman || command -v docker)
RPM=$(ls out/strongswan-psk-radius-[0-9]*.rpm 2>/dev/null | head -1)
[ -n "$RPM" ] || { echo "no RPM in out/, run contrib/build-el9-epel.sh first"; exit 1; }

ID=$$
NET=psk-radius-test-$ID
GW=psk-radius-gw-$ID
CLIENT=psk-radius-client-$ID
SUBNET=10.89.42
GW_IP=$SUBNET.2
CLIENT_IP=$SUBNET.3
VIP=10.10.0.10
DNS=10.10.0.1

random() { head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c "$1"; }
PSK=$(random 40)
RADIUS_SECRET=$(random 32)

cleanup() {
	if [ -n "${KEEP:-}" ]; then
		echo "KEEP set: leaving $GW, $CLIENT and network $NET"
		return
	fi
	"$ENGINE" rm -f "$GW" "$CLIENT" >/dev/null 2>&1 || true
	"$ENGINE" network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*"
	echo "--- gateway charon log"; "$ENGINE" exec "$GW" grep -vE "proposals:|CFG\]  " /var/log/charon.log | tail -40 || true
	echo "--- gateway radiusd log"; "$ENGINE" exec "$GW" tail -20 /var/log/radius/radius.log || true
	exit 1
}

"$ENGINE" network create --subnet "$SUBNET.0/24" "$NET" >/dev/null

echo "== starting the gateway"
"$ENGINE" run -d --name "$GW" --network "$NET" --ip "$GW_IP" \
	--cap-add NET_ADMIN --cap-add NET_RAW \
	-v "$PWD/out:/out:ro" -v "$PWD/examples:/examples:ro" \
	docker.io/library/almalinux:9 sleep infinity >/dev/null

"$ENGINE" exec -e PSK="$PSK" -e RADIUS_SECRET="$RADIUS_SECRET" -e GW_IP="$GW_IP" \
	-e VIP="$VIP" -e DNS="$DNS" -e RPM="/out/$(basename "$RPM")" "$GW" bash -euc '
	dnf -y -q install epel-release >/dev/null
	dnf -y -q install "$RPM" freeradius iproute iputils >/dev/null
	rpm -q strongswan strongswan-psk-radius

	# FreeRADIUS: only the example virtual server, with a client for localhost.
	rm -f /etc/raddb/sites-enabled/* /etc/raddb/mods-enabled/eap
	cp /examples/freeradius/sites-available-psk /etc/raddb/sites-available/psk
	ln -s ../sites-available/psk /etc/raddb/sites-enabled/psk
	printf "client localhost {\n\tipaddr = 127.0.0.1\n\tsecret = %s\n\trequire_message_authenticator = yes\n}\n" "$RADIUS_SECRET" \
		> /etc/raddb/clients.conf
	printf "%s\tService-Type == Authorize-Only, Auth-Type := Accept\n\tTunnel-Password = \"%s\",\n\tFramed-IP-Address = %s,\n\tMS-Primary-DNS-Server = %s\n" \
		site-1.example.com "$PSK" "$VIP" "$DNS" > /etc/raddb/mods-config/files/authorize
	radiusd -C >/dev/null
	radiusd

	# strongSwan
	cat > /etc/strongswan/strongswan.d/charon/psk-radius.conf <<EOF
psk-radius {
	load = yes
	server = 127.0.0.1
	secret = $RADIUS_SECRET
	station_id_with_port = no
}
EOF
	cat > /etc/strongswan/strongswan.d/test-log.conf <<EOF
charon {
	filelog {
		charon-log {
			path = /var/log/charon.log
			flush_line = yes
			default = 1
			cfg = 2
		}
	}
}
EOF
	cat > /etc/strongswan/swanctl/conf.d/sites.conf <<EOF
connections {
	sites {
		version = 2
		pools = psk-radius
		encap = yes
		unique = replace
		local {
			auth = psk
			id = vpn.example.com
		}
		remote {
			auth = psk
		}
		children {
			sites {
				local_ts = $GW_IP/32
			}
		}
	}
}
EOF
	/usr/libexec/strongswan/charon >/dev/null 2>&1 &
	for i in $(seq 20); do [ -S /var/run/charon.vici ] && break; sleep 0.5; done
	swanctl --load-all --noprompt >/dev/null
	grep -q "psk-radius: loaded 1 RADIUS server" /var/log/charon.log
' || fail "setting up the gateway failed"

echo "== starting the client"
"$ENGINE" run -d --name "$CLIENT" --network "$NET" --ip "$CLIENT_IP" \
	--cap-add NET_ADMIN --cap-add NET_RAW \
	docker.io/library/alpine:3.20 sleep infinity >/dev/null
"$ENGINE" exec "$CLIENT" sh -c 'apk add --no-cache strongswan >/dev/null'

client_conf() { # name identity key-hex
	cat <<EOF
connections {
	$1 {
		version = 2
		remote_addrs = $GW_IP
		vips = 0.0.0.0
		encap = yes
		local {
			auth = psk
			id = $2
		}
		remote {
			auth = psk
			id = vpn.example.com
		}
		children {
			$1 {
				remote_ts = 0.0.0.0/0
			}
		}
	}
}
secrets {
	ike-$1 {
		id-1 = $2
		id-2 = vpn.example.com
		secret = 0x$3
	}
}
EOF
}
hex() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# One file per case, loaded alone: "good" and "wrongkey" share both
# identities, so with both loaded the client could pick either key.
"$ENGINE" exec "$CLIENT" mkdir -p /etc/swanctl/cases
client_conf good site-1.example.com "$(hex "$PSK")" |
	"$ENGINE" exec -i "$CLIENT" sh -c 'cat > /etc/swanctl/cases/good.conf'
client_conf wrongkey site-1.example.com "$(hex "not-the-right-key")" |
	"$ENGINE" exec -i "$CLIENT" sh -c 'cat > /etc/swanctl/cases/wrongkey.conf'
client_conf unknown site-9.example.com "$(hex "$PSK")" |
	"$ENGINE" exec -i "$CLIENT" sh -c 'cat > /etc/swanctl/cases/unknown.conf'

"$ENGINE" exec "$CLIENT" sh -c '
	/usr/lib/strongswan/charon >/tmp/charon.log 2>&1 &
	for i in $(seq 20); do [ -S /var/run/charon.vici ] && break; sleep 0.5; done'

load_case() {
	"$ENGINE" exec "$CLIENT" swanctl --load-all --clear --noprompt \
		--file "/etc/swanctl/cases/$1.conf" >/dev/null
}

echo "== 1. correct key"
load_case good
out=$("$ENGINE" exec "$CLIENT" swanctl --initiate --child good --timeout 20 2>&1) ||
	{ echo "$out"; fail "the client with the correct key did not connect"; }
"$ENGINE" exec "$CLIENT" swanctl --list-sas | grep -q "\[$VIP\]" ||
	fail "the client did not get virtual IP $VIP"
echo "$out" | grep -q "DNS server $DNS" ||
	fail "the client did not get DNS server $DNS"
"$ENGINE" exec "$CLIENT" ping -c 2 -W 3 "$GW_IP" >/dev/null ||
	fail "no ping through the tunnel"
"$ENGINE" exec "$CLIENT" swanctl --list-sas | grep -E "ESP|bytes" | head -3
"$ENGINE" exec "$CLIENT" swanctl --terminate --ike good >/dev/null
echo "ok"

echo "== 2. wrong key"
load_case wrongkey
if "$ENGINE" exec "$CLIENT" swanctl --initiate --child wrongkey --timeout 20 >/dev/null 2>&1; then
	fail "the client with a wrong key connected"
fi
"$ENGINE" exec "$GW" grep -q "MAC mismatched" /var/log/charon.log ||
	fail "the gateway did not reject the wrong key"
echo "ok"

echo "== 3. unknown identity"
load_case unknown
if "$ENGINE" exec "$CLIENT" swanctl --initiate --child unknown --timeout 20 >/dev/null 2>&1; then
	fail "the unknown identity connected"
fi
"$ENGINE" exec "$GW" grep -q "psk-radius: no pre-shared key for 'site-9.example.com'" /var/log/charon.log ||
	fail "the gateway did not look up and reject the unknown identity"
echo "ok"

echo "PASS"
