# F50 wrappers: do not touch UCI for a service which has never been enabled.
F50_STARTED_MARKER=/var/run/easytier-f50.started

f50_easytier_enabled() {
    [ "$(uci -q get easytier.@easytier[0].enabled)" = 1 ] ||
        [ "$(uci -q get easytier.@easytier[0].web_enabled)" = 1 ]
}

start_service() {
    f50_easytier_enabled || return 0
    if ! (umask 077; : >"$F50_STARTED_MARKER"); then
        logger -t easytier "Unable to record EasyTier service start"
        return 1
    fi
    start_service_upstream
}

stop_service() {
    if ! f50_easytier_enabled && [ ! -f "$F50_STARTED_MARKER" ]; then
        return 0
    fi
    stop_service_upstream || return $?
    if ! rm -f "$F50_STARTED_MARKER"; then
        logger -t easytier "Unable to clear EasyTier service start record"
        return 1
    fi
}
