#!/bin/sh
# Publish service-owned fw4 rules without touching persistent firewall sections.
ZT_FW_SERVICE_NAME=zerotier
ZT_FW_READY_INTERVAL=1
ZT_FW_READY_ATTEMPTS=20

zt_fw_json_load() {
	local parsed
	parsed=$(jshn -r "$1") || { zt_error 'Invalid JSON from runtime command'; return 1; }
	eval "$parsed"
}

zt_fw_read_service() {
	local kind
	ZT_FW_SERVICE=$(ubus call service list '{"name":"zerotier","verbose":true}') || {
		zt_error 'Cannot read ZeroTier service state'; return 1;
	}
	json_set_namespace zt_service_
	zt_fw_json_load "$ZT_FW_SERVICE" || return 1
	json_get_type kind "$ZT_FW_SERVICE_NAME"
	[ -n "$kind" ] || return 2
	[ "$kind" = object ] || { zt_error 'Invalid ZeroTier service state'; return 1; }
	json_select "$ZT_FW_SERVICE_NAME"
	json_get_type kind data
	[ -z "$kind" ] || [ "$kind" = object ] || {
		zt_error 'Invalid ZeroTier service data'; return 1;
	}
}

zt_fw_running() {
	local keys key running found=0
	json_is_a instances object || return 2
	json_select instances
	json_get_keys keys
	for key in $keys; do
		json_is_a "$key" object || { zt_error 'Invalid service instance'; return 1; }
		json_select "$key"
		json_is_a running boolean || { zt_error 'Invalid service running state'; return 1; }
		json_get_var running running
		[ "$running" != 1 ] || found=1
		json_select ..
	done
	[ "$found" = 1 ] || return 2
}

zt_fw_wait_info() {
	local status enabled attempt=0
	while [ "$attempt" -lt "$ZT_FW_READY_ATTEMPTS" ]; do
		config_load zerotier || return 1
		enabled=$(zt_bool global enabled 0) || return 1
		[ "$enabled" = 1 ] || return 2
		zt_fw_read_service; status=$?
		[ "$status" = 0 ] || return "$status"
		zt_fw_running; status=$?
		[ "$status" = 0 ] || return "$status"
		ZT_FW_INFO=$(zerotier-cli -j info) && return 0
		[ "$attempt" != 0 ] || printf '%s\n' 'zerotier-f50: Waiting for ZeroTier CLI readiness' >&2
		attempt=$((attempt + 1))
		[ "$attempt" -ge "$ZT_FW_READY_ATTEMPTS" ] || sleep "$ZT_FW_READY_INTERVAL"
	done
	zt_error "ZeroTier CLI readiness failed after $ZT_FW_READY_ATTEMPTS attempts"
}

zt_fw_device_valid() {
	[ -n "$1" ] && [ "${#1}" -le 15 ] || return 1
	case "$1" in zt*) ;; *) return 1 ;; esac
	case "$1" in *[!a-z0-9]*) return 1 ;; esac
}

zt_fw_map_entry() {
	local id iface kind
	json_get_type kind id
	[ "$kind" = string ] || { zt_error 'Network runtime ID is missing'; return 1; }
	json_get_var id id
	zt_id_valid "$id" || { zt_error 'Invalid network runtime ID'; return 1; }
	id=$(printf '%s' "$id" | tr A-F a-f)
	case " $ZT_FW_SEEN " in *" $id "*) zt_error 'Duplicate runtime network ID'; return 1 ;; esac
	ZT_FW_SEEN="${ZT_FW_SEEN:+$ZT_FW_SEEN }$id"
	json_get_type kind portDeviceName
	[ "$kind" = string ] || { zt_error 'Network runtime device is missing'; return 1; }
	json_get_var iface portDeviceName
	[ -n "$iface" ] || return 0
	zt_fw_device_valid "$iface" || { zt_error 'Invalid network runtime device'; return 1; }
	case " $ZT_FW_DEVICES " in *" $iface "*) zt_error 'Duplicate runtime device'; return 1 ;; esac
	ZT_FW_DEVICES="${ZT_FW_DEVICES:+$ZT_FW_DEVICES }$iface"
	[ "$iface" != "$ZT_FW_EXCLUDED" ] || return 0
	ZT_FW_MAP="${ZT_FW_MAP:+$ZT_FW_MAP }$id:$iface"
}

zt_fw_read_networks() {
	local raw keys key
	ZT_FW_MAP= ZT_FW_SEEN= ZT_FW_DEVICES=
	raw=$(zerotier-cli -j listnetworks) || { zt_error 'Cannot read ZeroTier networks'; return 1; }
	json_set_namespace zt_networks_
	zt_fw_json_load "{\"networks\":$raw}" || return 1
	json_is_a networks array || { zt_error 'Network runtime result is not an array'; return 1; }
	json_select networks
	json_get_keys keys
	for key in $keys; do
		json_is_a "$key" object || { zt_error 'Invalid network runtime entry'; return 1; }
		json_select "$key"
		zt_fw_map_entry || return 1
		json_select ..
	done
}

zt_fw_read_ports() {
	local key port kind
	ZT_FW_PORTS=
	json_set_namespace zt_info_
	zt_fw_json_load "$ZT_FW_INFO" || return 1
	json_is_a config object && json_select config && json_is_a settings object && json_select settings || {
		zt_error 'Runtime ZeroTier settings are missing'; return 1;
	}
	[ "$(zt_bool global fw_allow_input 0)" = 1 ] || return 0
	for key in primaryPort secondaryPort; do
		json_get_type kind "$key"
		[ "$kind" = int ] || { zt_error 'Runtime UDP port is missing or invalid'; return 1; }
		json_get_var port "$key"
		[ "$port" != 0 ] || { [ "$key" = secondaryPort ] && continue; zt_error 'Primary UDP port is not ready'; return 1; }
		zt_validate_port "$port" || return 1
		case " $ZT_FW_PORTS " in *" $port "*) continue ;; esac
		ZT_FW_PORTS="${ZT_FW_PORTS:+$ZT_FW_PORTS }$port"
	done
}

zt_fw_rule() {
	json_add_object ''
	json_add_string type rule
	json_add_string src '*'
	[ "$1" = input ] || json_add_string dest '*'
	json_add_string device "$2"
	json_add_string direction "$3"
	json_add_string proto all
	json_add_string target ACCEPT
	json_close_object
}

zt_fw_network_rules() {
	local id pair iface= key flag
	[ "$(zt_bool "$1" enabled 1)" = 1 ] || return 0
	config_get id "$1" id
	id=$(printf '%s' "$id" | tr A-F a-f)
	for pair in $ZT_FW_MAP; do [ "${pair%%:*}" != "$id" ] || iface=${pair#*:}; done
	[ -n "$iface" ] || return 0
	for key in input forward masq; do
		flag=$(zt_bool "$1" "fw_allow_$key" 0) || { ZT_FW_INVALID=1; return 1; }
		[ "$flag" = 1 ] || continue
		case "$key" in
			input) zt_fw_rule input "$iface" in ;;
			forward) zt_fw_rule forward "$iface" in; zt_fw_rule forward "$iface" out ;;
			masq) zt_fw_masq "$iface" ;;
		esac
	done
}

zt_fw_masq() {
	json_add_object ''
	json_add_string type nat
	json_add_string device "$1"
	json_add_string family any
	json_add_string proto all
	json_add_string target MASQUERADE
	json_close_object
}

zt_fw_global_rules() {
	local port
	for port in $ZT_FW_PORTS; do
		json_add_object ''
		json_add_string type rule
		json_add_string src '*'
		json_add_string proto udp
		json_add_string dest_port "$port"
		json_add_string target ACCEPT
		json_close_object
	done
}

zt_fw_rules() (
	json_set_namespace zt_new_
	json_init
	json_add_array firewall
	if [ "$1" = refresh ] && [ "$ZT_ENABLED" = 1 ]; then
		ZT_FW_INVALID=0
		zt_fw_global_rules
		config_foreach zt_fw_network_rules network
		[ "$ZT_FW_INVALID" = 0 ] || exit 1
	fi
	json_close_array
	json_dump
)

zt_fw_payload() {
	local rules
	rules=$(zt_fw_rules "$1") || return 1
	# Native JSON merge preserves arbitrary metadata keys and numeric precision.
	printf '{"service":%s,"rules":%s}' "$ZT_FW_SERVICE" "$rules" | ucode -e '
		import { readfile } from "fs";
		let input = json(readfile("/dev/stdin"));
		let service = input.service.zerotier;
		if (type(service) != "object") die("Invalid service metadata");
		let data = service.data ?? {};
		if (type(data) != "object") die("Invalid service data");
		data.firewall = input.rules.firewall;
		print({ name: "zerotier", data: data });
	' || { zt_error 'Could not merge ZeroTier service data'; return 1; }
}

zt_fw_publish() {
	local payload
	payload=$(zt_fw_payload "$1") || return 1
	ubus call service set_data "$payload" >/dev/null || {
		zt_error 'Could not update ZeroTier service firewall data'; return 1;
	}
	fw4 reload || { zt_error 'Firewall reload failed after service data update'; return 1; }
}

zt_fw_absent() {
	printf '%s\n' 'zerotier-f50: Service is disabled, absent or not running; no firewall data published' >&2
}

zt_fw_refresh() {
	local status
	ZT_FW_EXCLUDED=${1:-}
	[ -z "$ZT_FW_EXCLUDED" ] || zt_fw_device_valid "$ZT_FW_EXCLUDED" || {
		zt_error 'Invalid removed interface'; return 1;
	}
	zt_validate_global || return 1
	[ "$ZT_ENABLED" = 1 ] || { zt_fw_clear; return $?; }
	zt_fw_wait_info; status=$?
	[ "$status" != 2 ] || { zt_fw_absent; return 0; }
	[ "$status" = 0 ] || return "$status"
	zt_validate_global || return 1
	zt_fw_read_ports && zt_fw_read_networks || return 1
	# Refresh metadata immediately before replacing only this service's data.
	zt_fw_read_service; status=$?
	[ "$status" != 2 ] || { zt_fw_absent; return 0; }
	[ "$status" = 0 ] && zt_fw_publish refresh
}

zt_fw_clear() {
	local status
	zt_fw_read_service; status=$?
	[ "$status" != 2 ] || { zt_fw_absent; return 0; }
	[ "$status" = 0 ] && zt_fw_publish clear
}
