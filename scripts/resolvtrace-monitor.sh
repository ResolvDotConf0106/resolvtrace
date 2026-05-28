#!/bin/bash
# resolvtrace-monitor
# Dynamic DNS health monitor - no hardcoded IPs or domains
# Detects: resolv.conf changes, DNS server down/up, missing config

LOG_FILE="/var/log/resolvtrace/resolvtrace.log"
RESOLV_CONF="/etc/resolv.conf"
PROBE_INTERVAL=10
LAST_STATE=""

log_event() {
    local level="$1"
    local reason="$2"
    local TS
    TS=$(date '+%Y-%m-%dT%H:%M:%S')
    local MSG="[RESOLVTRACE] $TS | $level | $reason"
    echo "$MSG"                  # stdout → journald
    echo "$MSG" >> "$LOG_FILE"   # file
}

get_nameservers() {
    grep "^nameserver" "$RESOLV_CONF" 2>/dev/null | awk '{print $2}'
}

get_probe_target() {
    hostname -f 2>/dev/null || hostname 2>/dev/null || echo "localhost"
}

probe_nameserver() {
    local ns="$1"
    local target
    target=$(get_probe_target)
    dig +short +tries=1 +timeout=3 "@${ns}" "$target" A > /dev/null 2>&1 || \
    dig +short +tries=1 +timeout=3 "@${ns}" . NS > /dev/null 2>&1
}

log_event "INFO    " "resolvtrace-monitor started | pid=$$ | config=$RESOLV_CONF | interval=${PROBE_INTERVAL}s"

# ── Background: inotify watches resolv.conf ────────────────────────────────
(
inotifywait -m -e modify,move,create,delete,attrib "$RESOLV_CONF" 2>/dev/null | \
while read -r dir event file; do
    NS_LIST=$(get_nameservers | tr '\n' ',' | sed 's/,$//')
    SEARCH=$(grep "^search\|^domain" "$RESOLV_CONF" 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
    if [ -z "$NS_LIST" ]; then
        log_event "FAILED  " "resolv.conf changed | event=$event | NO nameservers | DNS will fail"
    else
        log_event "CONFIG  " "resolv.conf changed | event=$event | nameservers=$NS_LIST | search=${SEARCH:-none}"
    fi
done
) &

# ── Foreground: active health probe loop ──────────────────────────────────
declare -A NS_STATES

while true; do
    mapfile -t NS_LIST < <(get_nameservers)

    if [ ${#NS_LIST[@]} -eq 0 ]; then
        if [ "$LAST_STATE" != "no_config" ]; then
            log_event "FAILED  " "health_check | no nameservers in $RESOLV_CONF | DNS resolution impossible"
            LAST_STATE="no_config"
        fi
    else
        LAST_STATE="checking"
        for NS in "${NS_LIST[@]}"; do
            PREV="${NS_STATES[$NS]:-unknown}"
            if probe_nameserver "$NS"; then
                if [ "$PREV" != "up" ]; then
                    if [ "$PREV" = "down" ]; then
                        log_event "RECOVER " "health_check | nameserver=$NS | DNS is back UP"
                    else
                        log_event "INFO    " "health_check | nameserver=$NS | status=UP"
                    fi
                    NS_STATES[$NS]="up"
                fi
            else
                if [ "$PREV" != "down" ]; then
                    log_event "FAILED  " "health_check | nameserver=$NS | DNS server DOWN or unreachable"
                    NS_STATES[$NS]="down"
                fi
            fi
        done
    fi

    sleep "$PROBE_INTERVAL"
done
