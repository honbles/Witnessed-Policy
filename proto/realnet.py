"""Real-socket transport with the same interface as wpcore.Net (now, at, send, log, nodes, rng...).
One RealNet per OS process; messages are length-prefixed JSON over TCP."""
import socket, struct, threading, queue, time, json, heapq, random, sys, traceback
class RealNet:
    def __init__(s, me, peers, listen, trace_path=None, app_delay=0.0, seed=1):
        s.me, s.peers, s.nodes, s.rng = me, peers, {}, random.Random(seed); s.t0 = time.monotonic()
        s.down, s.cut, s.msgs, s.bytes, s.trace = set(), [], 0, 0, []
        s.q = queue.Queue(); s.timers = []; s.seq = 0; s.lock = threading.Lock(); s.app_delay = app_delay
        s.tf = open(trace_path, 'a', buffering=1) if trace_path else None; s.stop = threading.Event(); s.tx_fail = 0; s.tx_ok = 0; s.last_err = ''; s.rx_err = 0
        s.srv = socket.socket(); s.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.srv.bind(tuple(listen)); s.srv.listen(256)
        threading.Thread(target=s._accept, daemon=True).start()
    @property
    def now(s): return time.time()          # absolute wall clock: certified time, leases and activation delays share one timebase
    def at(s, t, fn):
        with s.lock: s.seq += 1; heapq.heappush(s.timers, (t, s.seq, fn))
    def log(s, **k):
        k['t'] = round(time.time(), 4)
        if s.tf: s.tf.write(json.dumps(k) + '\n')
    def send(s, a, b, m):
        data = json.dumps(m, separators=(',', ':')).encode(); s.msgs += 1; s.bytes += len(data)
        if b == s.me: s.q.put(m); return
        if s.app_delay > 0: threading.Timer(s.app_delay, s._tx, (b, data)).start()
        else: threading.Thread(target=s._tx, args=(b, data), daemon=True).start()
    def _tx(s, b, data):
        err = None
        for attempt in range(4):                       # the transport is best-effort TCP: retry refused/timed-out connects (startup storms)
            try:
                with socket.create_connection(tuple(s.peers[b]), timeout=4) as c: c.sendall(struct.pack('>I', len(data)) + data)
                s.tx_ok += 1; return
            except Exception as ex: err = ex; time.sleep(0.15 * (attempt + 1))
        s.tx_fail += 1; s.last_err = f'{b}: {err!r}'
    def _accept(s):
        while True:
            try: c, _ = s.srv.accept()
            except Exception: return
            threading.Thread(target=s._rx, args=(c,), daemon=True).start()
    def _rx(s, c):
        try:
            with c:
                hdr = b''
                while len(hdr) < 4:
                    x = c.recv(4 - len(hdr));
                    if not x: return
                    hdr += x
                n = struct.unpack('>I', hdr)[0]; buf = bytearray()
                while len(buf) < n:
                    x = c.recv(min(65536, n - len(buf)))
                    if not x: return
                    buf += x
                s.q.put(json.loads(bytes(buf)))
        except Exception: s.rx_err += 1
    def close(s):
        s.stop.set()
        try: s.srv.shutdown(socket.SHUT_RDWR)
        except Exception: pass
        try: s.srv.close()
        except Exception: pass
    def run(s):
        node = None
        while not s.stop.is_set():
            with s.lock: nxt = s.timers[0][0] if s.timers else None
            to = 0.2 if nxt is None else max(0.0, min(0.2, nxt - s.now))
            try:
                m = s.q.get(timeout=to)
                node = node or next(iter(s.nodes.values()))
                try: node.on_msg(m)
                except Exception: traceback.print_exc(file=sys.stderr)
            except queue.Empty: pass
            while True:
                with s.lock:
                    if not s.timers or s.timers[0][0] > s.now: break
                    _, _, fn = heapq.heappop(s.timers)
                try: fn()
                except Exception: traceback.print_exc(file=sys.stderr)
