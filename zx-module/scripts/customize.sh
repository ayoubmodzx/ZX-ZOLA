#!/system/bin/sh
SKIPUNZIP=1

SONAME="zx_zola"
SUPPORTED_ABIS="arm64 arm x86 x64"

if [ "$BOOTMODE" ] && [ "$KSU" ]; then
    ui_print "- KernelSU detected: v$KSU_KERNEL_VER_CODE"
elif [ "$BOOTMODE" ] && [ "$MAGISK_VER_CODE" ]; then
    ui_print "- Magisk detected: v$MAGISK_VER_CODE"
else
    abort "! Install from KernelSU or Magisk only"
fi

VERSION=$(grep_prop version "$TMPDIR/module.prop")
ui_print "- Installing ZX-ZOLA $VERSION"
ui_print "- Device ABI: $ARCH"

# Check ABI support
support=false
for abi in $SUPPORTED_ABIS; do
    [ "$ARCH" = "$abi" ] && support=true && break
done
[ "$support" = "false" ] && abort "! Unsupported ABI: $ARCH"

ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop'   "$MODPATH"
extract "$ZIPFILE" 'service.sh'    "$MODPATH"

mkdir -p "$MODPATH/zygisk"

ABI64=""
ABI32=""

case "$ARCH" in
    arm64) ABI64="arm64-v8a"; ABI32="armeabi-v7a" ;;
    arm)   ABI32="armeabi-v7a" ;;
    x64)   ABI64="x86_64";    ABI32="x86" ;;
    x86)   ABI32="x86" ;;
esac

[ -n "$ABI64" ] && {
    ui_print "- Extracting $ABI64 library"
    unzip -o -j "$ZIPFILE" "zygisk/$ABI64.so" -d "$MODPATH/zygisk" >&2
    [ -f "$MODPATH/zygisk/$ABI64.so" ] || abort "! Failed to extract $ABI64 library"
}

# ABI32 is optional — only extract if present in the zip
[ -n "$ABI32" ] && unzip -l "$ZIPFILE" "zygisk/$ABI32.so" >/dev/null 2>&1 && {
    ui_print "- Extracting $ABI32 library"
    unzip -o -j "$ZIPFILE" "zygisk/$ABI32.so" -d "$MODPATH/zygisk" >&2
}

chmod 755 "$MODPATH/service.sh"
ui_print "- ZX-ZOLA installed. Hide root+Zygisk or you will get banned."
