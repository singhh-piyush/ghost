#!/bin/bash
# Ghost Capability Dropper - Enhanced
# Drops dangerous capabilities, sanitizes environment, and switches user
set -e

REAL_USER="$1"
shift

if [[ -z "$REAL_USER" ]]; then
    echo "Usage: caps.sh <user> <command...>" >&2
    exit 1
fi

# Comprehensive list of dangerous capabilities
DROP_CAPS="cap_net_admin,cap_net_raw,cap_sys_admin,cap_dac_override,cap_sys_ptrace,cap_sys_module,cap_mknod,cap_sys_boot,cap_sys_chroot,cap_sys_time,cap_audit_control,cap_audit_write,cap_mac_admin,cap_mac_override,cap_sys_rawio,cap_sys_nice,cap_sys_resource"

# Environment variables to clear (comprehensive list)
DANGEROUS_ENV="LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_DEBUG_OUTPUT LD_BIND_NOW LD_BIND_NOT LD_DYNAMIC_WEAK LD_ORIGIN_PATH LD_PROFILE LD_PROFILE_OUTPUT LD_USE_LOAD_BIAS LD_VERBOSE LD_WARN LD_PREFER_MAP_32BIT_EXEC LD_TRACE_LOADED_OBJECTS GCONV_PATH GETCONF_DIR HOSTALIASES LOCALDOMAIN LOCPATH MALLOC_CHECK_ MALLOC_TRACE NIS_PATH NLSPATH RESOLV_HOST_CONF RES_OPTIONS TMPDIR TZDIR"

# Build env -u arguments
ENV_UNSET=""
for var in $DANGEROUS_ENV; do
    ENV_UNSET="$ENV_UNSET -u $var"
done

# Fail-closed logic with better error messages
if command -v capsh &>/dev/null; then
    # Preferred: capsh with explicit drops
    exec env $ENV_UNSET capsh \
        --drop="$DROP_CAPS" \
        --keep=0 \
        --inh=0 \
        --user="$REAL_USER" \
        --no-new-privs \
        -- -c "$*"
        
elif command -v setpriv &>/dev/null; then
    # Fallback: setpriv with comprehensive bounding set
    exec env $ENV_UNSET setpriv \
        --bounding-set=-all \
        --bounding-set=+cap_setuid,+cap_setgid \
        --reuid="$REAL_USER" \
        --regid="$REAL_USER" \
        --clear-groups \
        --reset-env \
        --no-new-privs \
        bash -c "$*"
        
elif command -v su &>/dev/null; then
    # Last resort: su (less secure, but better than nothing)
    echo "[WARN] Using 'su' as capability dropper (capsh/setpriv not available)" >&2
    echo "[WARN] Security is reduced - install libcap-bin or util-linux" >&2
    exec env $ENV_UNSET su -s /bin/bash -c "$*" "$REAL_USER"
    
else
    # FATAL: No capability dropper available
    echo "[FATAL] No capability dropper found!" >&2
    echo "[FATAL] Install one of: libcap-bin (capsh), util-linux (setpriv), or shadow-utils (su)" >&2
    echo "[FATAL] Cannot guarantee security. Aborting." >&2
    exit 1
fi
