#!/system/bin/sh
MODDIR=${0%/*}

# Wait for full boot
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
sleep 3

# Verify module integrity before running
_verify() {
    local file="$1"
    local expected="$2"
    local actual
    actual=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    [ "$actual" = "$expected" ]
}

# Kill and restart FF if running — forces fresh Zygisk injection
if pidof com.dts.freefireth > /dev/null 2>&1; then
    am force-stop com.dts.freefireth
fi

if pidof com.dts.freefiremax > /dev/null 2>&1; then
    am force-stop com.dts.freefiremax
fi
