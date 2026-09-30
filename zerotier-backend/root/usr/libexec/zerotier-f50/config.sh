#!/bin/sh
# Configuration validation has no device or filesystem mutations.
zt_error() {
	printf 'zerotier-f50: %s\n' "$*" >&2
	return 1
}

zt_bool() {
	local value
	config_get value "$1" "$2" "$3"
	case "$value" in
		1|on|true|yes) echo 1 ;;
		0|off|false|no) echo 0 ;;
		*) zt_error "Invalid boolean in $1.$2" ;;
	esac
}

zt_id_valid() {
	[ "${#1}" -eq 16 ] || return 1
	case "$1" in *[!0-9a-fA-F]*) return 1 ;; esac
}

zt_validate_network() {
	local id canonical key default value
	config_get id "$1" id
	zt_id_valid "$id" || { ZT_INVALID=1; zt_error "Invalid network ID in $1"; return; }
	canonical=$(printf '%s' "$id" | tr A-F a-f)
	case " $ZT_CANONICAL_IDS " in *" $canonical "*) ZT_INVALID=1; zt_error 'Duplicate network ID'; return ;; esac
	ZT_CANONICAL_IDS="${ZT_CANONICAL_IDS:+$ZT_CANONICAL_IDS }$canonical"
	ZT_IDS="${ZT_IDS:+$ZT_IDS }$id"
	for key in enabled allow_managed allow_global allow_default allow_dns fw_allow_input fw_allow_forward fw_allow_masq; do
		default=0
		case "$key" in enabled|allow_managed) default=1 ;; esac
		zt_bool "$1" "$key" "$default" >/dev/null || ZT_INVALID=1
	done
	for key in fw_forward_ifaces fw_masq_ifaces; do
		config_get value "$1" "$key"
		[ -z "$value" ] || { ZT_INVALID=1; zt_error "$key restrictions are not supported by this backend"; }
	done
}

zt_validate_networks() {
	ZT_IDS= ZT_CANONICAL_IDS= ZT_INVALID=0
	config_foreach zt_validate_network network
	[ "$ZT_INVALID" = 0 ]
}

zt_validate_port() {
	case "$1" in ''|*[!0-9]*) zt_error 'Invalid listening port'; return 1 ;; esac
	[ "$1" -le 65535 ] 2>/dev/null || zt_error 'Listening port is out of range'
}

zt_validate_global() {
	ZT_ENABLED=$(zt_bool global enabled 0) || return 1
	ZT_COPY=$(zt_bool global copy_config_path 0) || return 1
	zt_bool global fw_allow_input 0 >/dev/null || return 1
	config_get ZT_PORT global port
	config_get ZT_CONFIG global config_path
	config_get ZT_LOCAL global local_conf_path
	config_get ZT_SECRET global secret
	[ -z "$ZT_PORT" ] || zt_validate_port "$ZT_PORT" || return 1
	zt_validate_networks
}

zt_external_path() {
	local resolved runtime
	case "$1" in /*) ;; *) zt_error 'Configuration paths must be absolute'; return 1 ;; esac
	resolved=$(readlink -f "$1") || return 1
	runtime=$(readlink -f "$(dirname "$ZT_RUNTIME")") || return 1
	runtime="$runtime/$(basename "$ZT_RUNTIME")"
	case "$resolved/" in "$runtime/"*) zt_error 'Configuration source is inside the runtime directory'; return 1 ;; esac
	case "$runtime/" in "$resolved/"*) zt_error 'Configuration source contains the runtime directory'; return 1 ;; esac
}

zt_validate_paths() {
	[ -z "$ZT_CONFIG" ] || {
		[ -d "$ZT_CONFIG" ] && zt_external_path "$ZT_CONFIG" || return 1
	}
	[ -z "$ZT_LOCAL" ] || {
		[ -f "$ZT_LOCAL" ] && [ -r "$ZT_LOCAL" ] && zt_external_path "$ZT_LOCAL" || return 1
	}
}
