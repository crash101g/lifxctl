"""A tiny simulated LIFX light (LAN protocol) for tests. Runs in a background thread."""
import socket
import struct
import threading
import time


class FakeLight:
    def __init__(self, ip="127.0.0.1", port=56700, mac="d073d5aabbcc", label="Test Strip",
                 zones=90, firmware=(3, 70), rssi=-62):
        self.mac = bytes.fromhex(mac)
        self.label = label.encode()
        self.power = 0
        self.hsbk = [0, 0, 65535, 3500]
        self.zones = [[(i * 700) % 65536, 65535, 30000, 3500] for i in range(zones)]
        self.firmware = firmware
        self.rssi = rssi
        self.boot = time.time() - 3 * 3600
        self.rebooted = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.2)
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.thread.join(2)
        self.sock.close()

    def _reply(self, src, seq, mtype, payload, addr):
        head = struct.pack("<HHI8s6sBB8sHH", 36 + len(payload), 1024 | 0x1000, src, self.mac + b"\0\0",
                           b"\0" * 6, 0, seq, b"\0" * 8, mtype, 0)
        self.sock.sendto(head + payload, addr)

    def _run(self):
        while not self._stop.is_set():
            try:
                d, a = self.sock.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            if len(d) < 36:
                continue
            src = struct.unpack_from("<I", d, 4)[0]
            seq, t, p, tgt = d[23], struct.unpack_from("<H", d, 32)[0], d[36:], d[8:14]
            if any(tgt) and tgt != self.mac:
                continue
            r = lambda mt, pl: self._reply(src, seq, mt, pl, a)
            if t == 2:
                r(3, struct.pack("<BI", 1, 56700))
            elif t == 14:
                r(15, struct.pack("<QQHH", 0, 0, self.firmware[1], self.firmware[0]))
            elif t == 16:
                r(17, struct.pack("<fIIh", 10 ** (self.rssi / 10), 0, 0, 0))
            elif t == 20:
                r(22, struct.pack("<H", self.power))
            elif t == 23:
                r(25, self.label.ljust(32, b"\0"))
            elif t == 32:
                r(33, struct.pack("<II", 1, 118 if self.zones else 27))
            elif t == 34:
                r(35, struct.pack("<QQQ", int(time.time() * 1e9), int((time.time() - self.boot) * 1e9), 0))
            elif t == 38:
                self.rebooted += 1
            elif t == 101:
                r(107, struct.pack("<HHHHhH32sQ", *self.hsbk, 0, self.power, self.label, 0))
            elif t == 102:
                self.hsbk = list(struct.unpack_from("<HHHH", p, 1))
            elif t == 117:
                self.power = struct.unpack_from("<H", p)[0]
            elif t == 511 and self.zones:
                n = len(self.zones)
                for start in range(0, n, 82):
                    chunk = self.zones[start:start + 82]
                    colors = b"".join(struct.pack("<HHHH", *z) for z in chunk).ljust(82 * 8, b"\0")
                    r(512, struct.pack("<HHB", n, start, len(chunk)) + colors)
            elif t == 510:
                _dur, _apply, idx, n = struct.unpack_from("<IBHB", p)
                for i in range(n):
                    self.zones[idx + i] = list(struct.unpack_from("<HHHH", p, 8 + 8 * i))
