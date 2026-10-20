#!/bin/bash
# Source this file:  . ./wg_unconfine.sh
# Ubuntu 25.x ships an AppArmor profile "wg" that is attached to the path /usr/bin/wg.  Inside it, `wg` cannot read key files
# outside its allow-list and cannot connect to wireguard-go's UAPI socket, so `wg set` fails with "Permission denied"
# (userspace WireGuard) even for root.  Kernel WireGuard + key over stdin still works, which hides the problem.
# AppArmor attaches by PATH, so an identical copy of the binary in another directory runs unconfined.  This puts such a copy
# first on PATH.  No profile is unloaded or edited.  Disable with WP_NO_UNCONFINE=1.  Needs root; silently does nothing otherwise.
wp_wg_setup() {
  [ "${WP_NO_UNCONFINE:-0}" = 1 ] && return 0
  [ "$(id -u)" -eq 0 ] || return 0
  [ -d /sys/module/apparmor ] || [ "${WP_FORCE_UNCONFINE:-0}" = 1 ] || return 0
  local dir=${WP_BIN_DIR:-/usr/local/lib/wp/bin} real
  real=$(PATH=${PATH//"$dir:"/} command -v wg) || { echo "wg_unconfine: wg not installed (apt install wireguard-tools)" >&2; return 0; }
  mkdir -p "$dir" || return 0
  if [ ! -x "$dir/wg" ] || ! cmp -s "$real" "$dir/wg" 2>/dev/null; then cp -f "$real" "$dir/wg" && chmod 755 "$dir/wg"; fi
  case ":$PATH:" in ":$dir:"*) ;; *) export PATH="$dir:$PATH" ;; esac
  echo "wg_unconfine: using $(command -v wg) (copy of $real, outside the AppArmor 'wg' profile path)" >&2
}
wp_wg_setup
