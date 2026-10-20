import socket, threading, sys
def serve(port, v6):
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if v6: s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(('::' if v6 else '0.0.0.0', port)); s.listen(128)
    while True:
        c, _ = s.accept(); threading.Thread(target=echo, args=(c,), daemon=True).start()
def echo(c):
    try:
        while True:
            d = c.recv(64)
            if not d: break
            c.sendall(d)
    except Exception: pass
    c.close()
for p in (443, 22, 5432, 8080):
    threading.Thread(target=serve, args=(p, False), daemon=True).start()
threading.Thread(target=serve, args=(443, True), daemon=True).start()
threading.Event().wait()
