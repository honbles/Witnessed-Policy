#!/bin/bash
# WireGuard sanity check between two network namespaces (run as root).  Prints what works on THIS host.
#   sudo ./diag_wg.sh            no added delay
#   sudo DELAY=25 ./diag_wg.sh   25 ms netem delay on each side (50 ms one way, like the experiments)
. "$(dirname "$0")/wg_unconfine.sh"
D=${DELAY:-0}; ok() { echo "  [ok]  $1"; }; bad() { echo "  [FAIL] $1"; }
cleanup() { ip netns del dga 2>/dev/null; ip netns del dgb 2>/dev/null; pkill -f "wireguard-go -f dg" 2>/dev/null; rm -f /var/run/wireguard/dg*.sock; }
cleanup; trap cleanup EXIT
echo "host: $(uname -r)   delay per side: ${D} ms   wg: $(command -v wg)"
grep -qE "^(wg|/usr/bin/wg) \(enforce\)" /sys/kernel/security/apparmor/profiles 2>/dev/null && echo "  [info] AppArmor profile 'wg' is enforcing: the stock /usr/bin/wg is blocked on this host; the unconfined copy above is used instead"
ip netns add dga && ip netns add dgb && ip link add va type veth peer name vb && ip link set va netns dga && ip link set vb netns dgb || { bad "cannot build namespaces/veth"; exit 1; }
ip netns exec dga sh -c "ip addr add 10.50.0.1/24 dev va; ip link set va up; ip link set lo up"; ip netns exec dgb sh -c "ip addr add 10.50.0.2/24 dev vb; ip link set vb up; ip link set lo up"
if [ "$D" != "0" ]; then ip netns exec dga tc qdisc add dev va root netem delay ${D}ms && ip netns exec dgb tc qdisc add dev vb root netem delay ${D}ms && ok "netem ${D}ms on both ends" || bad "netem unavailable"; fi
echo "1) plain UDP/TCP across the veth"
ip netns exec dga ping -c2 -W3 10.50.0.2 > /tmp/dg_ping.txt 2>&1 && ok "ping: $(tail -1 /tmp/dg_ping.txt)" || bad "ping failed"
ip netns exec dgb sh -c 'python3 -c "
import socket;u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((\"10.50.0.2\",7777));u.settimeout(5)
try:
    d,a=u.recvfrom(16);u.sendto(b\"pong\",a)
except Exception: pass" &' ; sleep 0.5
ip netns exec dga python3 -c "
import socket,time;u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.settimeout(3);t=time.time();u.sendto(b'ping',('10.50.0.2',7777))
try: u.recvfrom(16);print('  [ok]  UDP echo rtt %.0f ms'%(1000*(time.time()-t)))
except Exception as e: print('  [FAIL] UDP echo',e)"
KA=$(wg genkey); KB=$(wg genkey); PA=$(echo $KA | wg pubkey); PB=$(echo $KB | wg pubkey); echo $KA > /tmp/dg_ka; echo $KB > /tmp/dg_kb
try_wg() { # mode
  echo "2) WireGuard ($1)"; echo "   key file: $(ls -l /tmp/dg_ka 2>&1)"; echo "   id: $(id -u) umask: $(umask) protected_regular: $(sysctl -n fs.protected_regular 2>&1)"
  for ns in a b; do
    if [ "$1" = kernel ]; then ip netns exec dg$ns ip link add dev dg$ns type wireguard 2>/tmp/dg_err.txt || { bad "kernel WireGuard not available: $(cat /tmp/dg_err.txt)"; return; }
    else ip netns exec dg$ns sh -c "nohup wireguard-go -f dg$ns > /tmp/dg_wgo_$ns.log 2>&1 &"; for i in $(seq 1 40); do ip netns exec dg$ns ip link show dg$ns >/dev/null 2>&1 && break; sleep 0.25; done; ip netns exec dg$ns ip link show dg$ns >/dev/null 2>&1 || { bad "wireguard-go did not create dg$ns: $(tail -3 /tmp/dg_wgo_$ns.log)"; return; }; fi
  done
  setkey() { # ns keyfile key
    ip netns exec dg$1 wg set dg$1 private-key $2 listen-port 51820 2>/tmp/dg_e1.txt && { echo "   private key loaded from a FILE"; return 0; }
    echo "   [note] key from file failed: $(cat /tmp/dg_e1.txt)"
    echo "$3" | ip netns exec dg$1 wg set dg$1 private-key /dev/stdin listen-port 51820 2>/tmp/dg_e2.txt && { echo "   private key loaded over STDIN"; return 0; }
    echo "   [FAIL] key from stdin failed too: $(cat /tmp/dg_e2.txt)"; return 1; }
  setkey a /tmp/dg_ka "$KA" && setkey b /tmp/dg_kb "$KB" || { aa-status 2>&1 | head -4; (journalctl -k -b 2>/dev/null || dmesg 2>/dev/null) | grep -iE "apparmor=.DENIED" | tail -5; echo "   hint: if the profile 'wg' denies this, run with WP_FORCE_UNCONFINE=1, or: sudo apparmor_parser -R /etc/apparmor.d/wg"; return; }
  ip netns exec dga sh -c "wg set dga peer $PB allowed-ips 10.99.0.2/32 endpoint 10.50.0.2:51820 persistent-keepalive 1; ip addr add 10.99.0.1/24 dev dga; ip link set dga up mtu 1380"
  ip netns exec dgb sh -c "wg set dgb peer $PA allowed-ips 10.99.0.1/32 endpoint 10.50.0.1:51820 persistent-keepalive 1; ip addr add 10.99.0.2/24 dev dgb; ip link set dgb up mtu 1380"
  for i in $(seq 1 30); do hs=$(ip netns exec dga wg show dga latest-handshakes | awk '{print $2}'); [ "${hs:-0}" != "0" ] && break; sleep 0.5; done
  [ "${hs:-0}" != "0" ] && ok "handshake after ~$((i/2)) s" || { bad "no handshake in 15 s"; ip netns exec dga wg show dga; ip netns exec dga ip -s link show dga | tail -4; }
  ip netns exec dga ping -c3 -W3 10.99.0.2 > /tmp/dg_ping2.txt 2>&1 && ok "ping through the tunnel: $(tail -1 /tmp/dg_ping2.txt)" || bad "ping through the tunnel failed"
  ip netns exec dga wg show dga | grep -E "transfer|handshake"
  ip netns exec dga ip link del dga; ip netns exec dgb ip link del dgb; pkill -f "wireguard-go -f dg" 2>/dev/null; rm -f /var/run/wireguard/dg*.sock; sleep 1
}
try_wg kernel; try_wg userspace
echo "3) host firewall hints"; iptables -S FORWARD 2>/dev/null | head -3; sysctl net.bridge.bridge-nf-call-iptables 2>/dev/null; nft list ruleset 2>/dev/null | head -5
echo "done (if any line says FAIL, see the Troubleshooting section of README.md)"
