import socket, sys, time, os
TO = float(os.environ.get('WP_PROBE_TO', '0.15'))
log, stop = sys.argv[1], sys.argv[2]; tgt = sys.argv[3] if len(sys.argv) > 3 else '10.2.0.2'; port = int(sys.argv[4]) if len(sys.argv) > 4 else 443; src = sys.argv[5] if len(sys.argv) > 5 else None
fam = socket.AF_INET6 if ':' in tgt else socket.AF_INET; f = open(log, 'a', buffering=1)
while not os.path.exists(stop):
    t = time.time(); s = socket.socket(fam); s.settimeout(TO)
    try:
        if src: s.bind((src, 0))
        s.connect((tgt, port)); ok = 1
    except Exception: ok = 0
    s.close(); f.write(f'{t:.4f} {ok}\n'); time.sleep(max(0.0, 0.1 - (time.time() - t)))
