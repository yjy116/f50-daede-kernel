#!/bin/sh
# Only UCI-managed IDs, including a previous owned-ID ledger, are removed.
zt_remove_network() {
	zt_id_valid "$1" || { zt_error 'Invalid owned network ledger'; return 1; }
	rm -f "$ZT_RUNTIME/networks.d/$1.conf" "$ZT_RUNTIME/networks.d/$1.local.conf"
}

zt_write_network() {
	local id enabled managed global default dns
	config_get id "$1" id
	enabled=$(zt_bool "$1" enabled 1) || return 1
	[ "$enabled" = 1 ] || { zt_remove_network "$id"; return; }
	managed=$(zt_bool "$1" allow_managed 1) || return 1
	global=$(zt_bool "$1" allow_global 0) || return 1
	default=$(zt_bool "$1" allow_default 0) || return 1
	dns=$(zt_bool "$1" allow_dns 0) || return 1
	touch "$ZT_RUNTIME/networks.d/$id.conf" || return 1
	printf 'allowManaged=%s\nallowGlobal=%s\nallowDefault=%s\nallowDNS=%s\n' \
		"$managed" "$global" "$default" "$dns" > "$ZT_RUNTIME/networks.d/$id.local.conf"
}

zt_write_network_checked() {
	zt_write_network "$1" || ZT_INVALID=1
}

zt_sync_networks() {
	local id
	mkdir -p "$ZT_STATE" "$ZT_RUNTIME/networks.d" || return 1
	if [ -f "$ZT_STATE/network-ids" ]; then
		while IFS= read -r id; do
			zt_id_valid "$id" || { zt_error 'Invalid owned network ledger'; return 1; }
		done < "$ZT_STATE/network-ids"
		while IFS= read -r id; do
			case " $ZT_IDS " in *" $id "*) continue ;; esac
			zt_remove_network "$id" || return 1
		done < "$ZT_STATE/network-ids"
	fi
	ZT_INVALID=0
	config_foreach zt_write_network_checked network
	[ "$ZT_INVALID" = 0 ] || return 1
	: > "$ZT_STATE/network-ids.new" || return 1
	for id in $ZT_IDS; do printf '%s\n' "$id" >> "$ZT_STATE/network-ids.new" || return 1; done
	mv "$ZT_STATE/network-ids.new" "$ZT_STATE/network-ids"
}

zt_prepare_runtime() {
	zt_validate_paths || { zt_error 'Invalid or inaccessible configuration path'; return 1; }
	rm -rf "$ZT_RUNTIME" || return 1
	if [ -n "$ZT_CONFIG" ]; then
		if [ "$ZT_COPY" = 1 ]; then cp -r "$ZT_CONFIG" "$ZT_RUNTIME" || return 1
		else ln -s "$ZT_CONFIG" "$ZT_RUNTIME" || return 1; fi
	fi
	mkdir -p "$ZT_RUNTIME/networks.d" || return 1
	if [ -n "$ZT_LOCAL" ]; then
		ln -sf "$ZT_LOCAL" "$ZT_RUNTIME/local.conf" || return 1
	fi
	zt_sync_networks
}

zt_private_identity_present() {
	local prefix private
	prefix=${ZT_SECRET%:*}
	private=${ZT_SECRET##*:}
	case "$prefix" in *:*:*) ;; *) return 1 ;; esac
	case "$private" in ''|*[!0-9a-fA-F]*) return 1 ;; esac
}

zt_get_identity() {
	ZT_GENERATED=0
	if [ -z "$ZT_SECRET" ]; then
		ZT_SECRET=$(zerotier-idtool generate) || { zt_error 'Identity generation failed'; return 1; }
		[ -n "$ZT_SECRET" ] || { zt_error 'Identity generation returned no identity'; return 1; }
		ZT_GENERATED=1
	fi
	zt_private_identity_present || zt_error 'A private identity is required'
}

zt_validated_identity_file() {
	local candidate
	candidate=$(mktemp "$ZT_RUNTIME/.identity.XXXXXX") || return 1
	printf '%s\n' "$ZT_SECRET" > "$candidate" || { rm -f "$candidate"; return 1; }
	if ! zerotier-idtool validate "$candidate" >/dev/null 2>&1; then
		rm -f "$candidate"
		zt_error 'Configured identity is invalid'; return 1
	fi
	printf '%s\n' "$candidate"
}

zt_prepare_identity() {
	local candidate
	zt_get_identity || return 1
	candidate=$(zt_validated_identity_file) || return 1
	if [ "$ZT_GENERATED" = 1 ]; then
		uci set "zerotier.global.secret=$ZT_SECRET" && uci commit zerotier || {
			rm -f "$candidate"; return 1
		}
	fi
	mv "$candidate" "$ZT_RUNTIME/identity.secret" || {
		rm -f "$candidate"; return 1
	}
	rm -f "$ZT_RUNTIME/identity.public"
}
