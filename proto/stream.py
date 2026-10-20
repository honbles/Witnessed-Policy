import socket, sys, time, os
TO = float(os.environ.get('WP_PROBE_TO', '0.3'))
log, stop = sys.argv[1], sys.argv[2]; f = open(log, 'a', buffering=1); s = None
while not os.path.exists(stop):
    t = time.time()
    try:
        if s is None: s = socket.create_connection(('10.2.0.2', 443), timeout=TO); s.settimeout(TO)
        s.sendall(b'x'); ok = 1 if s.recv(8) == b'x' else 0
    except Exception: ok = 0
    f.write(f'{t:.4f} {ok}\n'); time.sleep(max(0.0, 0.05 - (time.time() - t)))
