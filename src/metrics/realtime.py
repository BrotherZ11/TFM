import time
import statistics
from collections import deque

class RealtimeStats:
    def __init__(self, window=50):
        self.window = window
        self.rtt = deque(maxlen=window)
        self.sign = deque(maxlen=window)
        self.verify = deque(maxlen=window)
        self.stanza = deque(maxlen=window)
        self.last_print = time.time()

    def add(self, rtt_ms=None, sign_ms=None, verify_ms=None, stanza_bytes=None):
        if rtt_ms is not None: self.rtt.append(float(rtt_ms))
        if sign_ms is not None: self.sign.append(float(sign_ms))
        if verify_ms is not None: self.verify.append(float(verify_ms))
        if stanza_bytes is not None: self.stanza.append(int(stanza_bytes))

    def _p(self, arr, q):
        if not arr: return None
        s = sorted(arr)
        i = int((q/100.0) * (len(s)-1))
        return s[i]

    def maybe_print(self, every_sec=2.0, prefix=""):
        now = time.time()
        if now - self.last_print < every_sec:
            return
        self.last_print = now

        def fmt(name, arr):
            if not arr: return f"{name}: n/a"
            return (f"{name}: n={len(arr)} "
                    f"mean={statistics.fmean(arr):.2f} "
                    f"med={statistics.median(arr):.2f} "
                    f"p95={self._p(arr,95):.2f}")

        parts = [
            fmt("RTT(ms)", list(self.rtt)),
            fmt("SIGN(ms)", list(self.sign)),
            fmt("VERIFY(ms)", list(self.verify)),
        ]
        if self.stanza:
            parts.append(f"STANZA(bytes): mean={statistics.fmean(self.stanza):.0f} med={statistics.median(self.stanza):.0f}")

        print(prefix + " | " + " | ".join(parts))
