#!/usr/bin/env python3
"""
lifxctl.py - find, control and reboot LIFX lights (bulbs, LED strips, Beams) on the LAN.

Uses the LIFX LAN protocol (UDP 56700) directly. No extra packages, Python 3.8+.
Runs on Linux, macOS and Windows (on Windows: `py lifxctl.py ...`).

  lifxctl.py                            # interactive menu
  lifxctl.py scan                       # broadcast + sweep local /24 on UDP 56700, plus ARP check
  lifxctl.py known                      # last-known devices (IP, MAC, label) and whether they answer now
  lifxctl.py forget <target>            # remove a device from the known list
  lifxctl.py firmware                   # firmware vs LIFX's latest release, Wi-Fi signal, uptime
  lifxctl.py diagnose                   # find out WHY a light drops off / hangs / turns off, with fixes
  lifxctl.py guide                      # troubleshooting guide (router settings, power, reset)
  lifxctl.py token                      # save your LIFX cloud token (needed for app scenes)
  lifxctl.py scenes [--refresh]         # list scenes: from your LIFX app + local snapshots
  lifxctl.py scene "Movie Night"        # activate by name or number (cloud, falls back to LAN)
  lifxctl.py scene-save "TV gradient"   # snapshot current colors (incl. every strip zone) locally
  lifxctl.py on  [target ...]           # default target: all
  lifxctl.py off [target ...]
  lifxctl.py status [target ...]
  lifxctl.py reboot <target ...|all>    # waits for the device to come back
  lifxctl.py reboot "TV Strip" --then-on
  lifxctl.py watch --interval 60        # log when devices drop off / come back

A target is an IP, a MAC (d0:73:d5:xx:xx:xx), a label (case-insensitive substring), or "all".

Common options (put before the command):
  --subnet 192.168.1.0/24   sweep this range instead of the auto-detected /24
  --no-sweep                broadcast only, no per-IP sweep
  --log FILE                log file (default: lifxctl.log in the data folder, rotated 1 MB x 5)
  --no-log                  don't write a log file
  -v / --verbose            debug logging: every packet sent and received
  -q / --quiet              console shows warnings only (log file still gets everything)
  --cache FILE              known-devices file (default: devices.json in the data folder)

Data folder: ~/.local/state/lifxctl (Linux), ~/Library/Application Support/lifxctl (macOS),
%LOCALAPPDATA%\\lifxctl (Windows).

Every device seen is remembered (IP, MAC, label, product, last power, first/last seen).
Discovery also probes each remembered IP directly, so devices are found even when the
router blocks broadcasts, and a device that changed IP is still matched by MAC.

Note: reboot / on / off need the device to still be on Wi-Fi. A device that has
dropped off the network can only be recovered by cutting its power.
"""
import argparse
import atexit
import getpass
import ipaddress
import json
import logging
import logging.handlers
import math
import os
import re
import random
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


def _app_dirs():
    """(state dir, config dir) in the usual place for each OS."""
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Local")
        roaming = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(local, "lifxctl"), os.path.join(roaming, "lifxctl")
    if IS_MACOS:
        d = os.path.join(os.path.expanduser("~"), "Library", "Application Support", "lifxctl")
        return d, d
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    config = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(state, "lifxctl"), os.path.join(config, "lifxctl")


STATE_DIR, CONFIG_DIR = _app_dirs()

PORT = 56700
SRC = random.randint(2, 0xFFFFFFFF)
LIFX_OUI = "d0:73:d5"

GET_SERVICE, STATE_SERVICE = 2, 3
GET_POWER, STATE_POWER = 20, 22
GET_LABEL, STATE_LABEL = 23, 25
GET_VERSION, STATE_VERSION = 32, 33
SET_REBOOT = 38
LIGHT_SET_POWER = 117
GET_HOST_FIRMWARE, STATE_HOST_FIRMWARE = 14, 15
GET_WIFI_INFO, STATE_WIFI_INFO = 16, 17
GET_INFO, STATE_INFO = 34, 35
LIGHT_GET, LIGHT_SET_COLOR, LIGHT_STATE = 101, 102, 107
SET_EXT_ZONES, GET_EXT_ZONES, STATE_EXT_ZONES = 510, 511, 512

_seq = 0
_sweeping = False  # suppress per-packet debug lines during the /24 sweep
log = logging.getLogger("lifxctl")


class Cache:
    """Last-known LIFX devices, keyed by MAC, saved as JSON."""

    def __init__(self, path=None):
        self.path, self.devices, self.dirty = path, {}, False
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                self.devices = json.load(f).get("devices", {})
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as e:
            log.warning(f"can't read device cache {path}: {e}")

    def seen(self, mac, ip, **fields):
        key = fmt_mac(mac)
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        d = self.devices.get(key)
        if d is None:
            d = self.devices[key] = {"first_seen": now}
            log.info(f"New LIFX device remembered: {ip} {key}", extra={"fileonly": True})
        elif d.get("ip") and d["ip"] != ip:
            log.warning(f"{key} {d.get('label', '')} changed IP {d['ip']} -> {ip}")
            d["ip_changes"] = d.get("ip_changes", 0) + 1
        d["ip"], d["last_seen"] = ip, now
        for k, v in fields.items():
            if v not in (None, "?"):
                d[k] = v
        self.dirty = True

    def ips(self):
        return [d["ip"] for d in self.devices.values() if d.get("ip")]

    def sorted(self):
        return sorted(self.devices.items(), key=lambda kv: (kv[1].get("label", "~").lower(), kv[0]))

    def forget(self, key):
        if self.devices.pop(key, None) is not None:
            self.dirty = True
            return True
        return False

    def save(self):
        if not (self.dirty and self.path):
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "devices": self.devices}, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError as e:
            log.warning(f"can't save device cache {self.path}: {e}")


CACHE = Cache()  # replaced in main()
TYPE_NAMES = {2: "GetService", 3: "StateService", 20: "GetPower", 22: "StatePower",
              23: "GetLabel", 25: "StateLabel", 32: "GetVersion", 33: "StateVersion",
              38: "SetReboot", 45: "Acknowledgement", 117: "SetPower",
              14: "GetHostFirmware", 15: "StateHostFirmware", 16: "GetWifiInfo", 17: "StateWifiInfo",
              34: "GetInfo", 35: "StateInfo", 101: "LightGet", 102: "SetColor", 107: "LightState",
              510: "SetExtendedColorZones", 511: "GetExtendedColorZones", 512: "StateExtendedColorZones"}


# ---------------------------------------------------------------- protocol ---
def frame(msg_type, target=None, payload=b"", res=False, ack=False):
    """Build a LIFX LAN packet. target=None -> tagged (all devices)."""
    global _seq
    _seq = (_seq + 1) % 256
    proto = 1024 | 0x1000 | (0x2000 if target is None else 0)
    flags = (1 if res else 0) | (2 if ack else 0)
    tgt = (target or b"").ljust(8, b"\0")
    return struct.pack("<HHI8s6sBB8sHH", 36 + len(payload), proto, SRC, tgt,
                       b"\0" * 6, flags, _seq, b"\0" * 8, msg_type, 0) + payload


def parse(data):
    if len(data) < 36:
        return None
    src = struct.unpack_from("<I", data, 4)[0]
    mac = bytes(data[8:14])
    mtype = struct.unpack_from("<H", data, 32)[0]
    return src, mac, mtype, data[36:]


def collect(sock, seconds, want):
    """Gather replies of type `want` for `seconds`. Returns {ip: (mac, payload)}."""
    out = {}
    end = time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            data, (ip, _) = sock.recvfrom(2048)
        except socket.timeout:
            break
        except OSError:
            continue
        p = parse(data)
        if p and log.isEnabledFor(logging.DEBUG):
            log.debug(f"recv {ip:15} {fmt_mac(p[1])} {TYPE_NAMES.get(p[2], p[2])} "
                      f"({len(data)} bytes){'' if p[0] == SRC else ' [not ours]'}")
        if p and p[0] == SRC and p[2] == want:
            out[ip] = (p[1], p[3])
    return out


def wait_one(sock, ip, want, timeout, seq=None):
    """Return the payload of the first reply of type `want` from `ip` (matching `seq` if given),
    as soon as it arrives. None on timeout."""
    end = time.time() + timeout
    while True:
        left = end - time.time()
        if left <= 0:
            return None
        sock.settimeout(left)
        try:
            data, (rip, _) = sock.recvfrom(2048)
        except socket.timeout:
            return None
        except OSError:
            continue
        p = parse(data)
        if p and log.isEnabledFor(logging.DEBUG):
            log.debug(f"recv {rip:15} {fmt_mac(p[1])} {TYPE_NAMES.get(p[2], p[2])} "
                      f"({len(data)} bytes){'' if p[0] == SRC else ' [not ours]'}")
        if p and p[0] == SRC and p[2] == want and rip == ip and (seq is None or data[23] == seq):
            if want == STATE_SERVICE:  # discovery-type reply: remember it, return (mac, payload)
                CACHE.seen(p[1], ip)
                return p[1], p[3]
            return p[3]


def send(sock, msg, ip):
    if log.isEnabledFor(logging.DEBUG) and not _sweeping:
        mtype = struct.unpack_from("<H", msg, 32)[0]
        tgt = fmt_mac(msg[8:14]) if any(msg[8:14]) else "all"
        log.debug(f"send {ip:15} {tgt:17} {TYPE_NAMES.get(mtype, mtype)}")
    try:
        sock.sendto(msg, (ip, PORT))
    except OSError as e:
        log.debug(f"send {ip} failed: {e}")


def query(sock, ip, mac, mtype, want, payload=b"", tries=3, wait=0.6):
    for _ in range(tries):
        msg = frame(mtype, mac, payload, res=True)
        send(sock, msg, ip)
        p = wait_one(sock, ip, want, wait, seq=msg[23])
        if p is not None:
            return p
    return None


def probe(sock, ip, tries=2, wait=0.6):
    """Unicast GetService to one IP. Returns MAC bytes or None."""
    for _ in range(tries):
        msg = frame(GET_SERVICE)
        send(sock, msg, ip)
        r = wait_one(sock, ip, STATE_SERVICE, wait, seq=msg[23])
        if r:
            return r[0]
    return None


def link_quality(sock, ip, mac, n=20, gap=0.1, timeout=0.5):
    """Ping a device n times over the LIFX protocol. Returns (loss %, median ms, max ms)."""
    rtts = []
    for _ in range(n):
        msg = frame(GET_SERVICE, mac, res=True)
        t0 = time.time()
        send(sock, msg, ip)
        if wait_one(sock, ip, STATE_SERVICE, timeout, seq=msg[23]) is not None:
            rtts.append((time.time() - t0) * 1000)
        time.sleep(gap)
    loss = 100.0 * (n - len(rtts)) / n
    if not rtts:
        return loss, None, None
    rtts.sort()
    return loss, rtts[len(rtts) // 2], rtts[-1]


def discover(sock, subnet=None, timeout=3.0, use_cache=True):
    """Broadcast GetService (+ unicast sweep of subnet, + remembered IPs). Returns {ip: mac}."""
    bcasts = broadcast_addresses(subnet)
    targets = []
    if subnet:
        targets += [str(h) for h in ipaddress.ip_network(subnet, strict=False).hosts()]
    if use_cache:
        already = set(targets)
        targets += [ip for ip in CACHE.ips() if ip not in already]  # remembered IPs, unicast
    global _sweeping
    msg = frame(GET_SERVICE)
    found = {}
    log.debug(f"discover: GetService -> {', '.join(bcasts)}" + (f" + {len(targets)} hosts" if targets else ""))
    for _ in range(2):
        for b in bcasts:
            send(sock, msg, b)
        _sweeping = True
        try:
            for t in targets:
                send(sock, msg, t)
        finally:
            _sweeping = False
        found.update({ip: v[0] for ip, v in collect(sock, timeout / 2, STATE_SERVICE).items()})
    log.debug(f"discover: {len(found)} device(s) answered")
    for ip, mac in found.items():
        CACHE.seen(mac, ip)
    return found


def get_label(sock, ip, mac):
    p = query(sock, ip, mac, GET_LABEL, STATE_LABEL)
    label = p[:32].split(b"\0")[0].decode(errors="replace") if p else "?"
    if p:
        CACHE.seen(mac, ip, label=label)
    return label


def get_power(sock, ip, mac):
    p = query(sock, ip, mac, GET_POWER, STATE_POWER)
    if p is None or len(p) < 2:
        return "?"
    power = "on" if struct.unpack_from("<H", p)[0] else "off"
    CACHE.seen(mac, ip, power=power)
    return power


def get_product(sock, ip, mac):
    p = query(sock, ip, mac, GET_VERSION, STATE_VERSION)
    if not (p and len(p) >= 8):
        return "?"
    product = str(struct.unpack_from("<II", p)[1])
    CACHE.seen(mac, ip, product=product)
    return product


# ------------------------------------------------------------------ helpers ---
def fmt_mac(mac):
    return ":".join(f"{b:02x}" for b in mac[:6])


def local_subnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()
    return str(ipaddress.ip_network(ip + "/24", strict=False))


def broadcast_addresses(subnet=None):
    """255.255.255.255 plus the directed broadcast of the local (or given) subnet.
    The directed one matters on macOS/Windows machines with several network adapters."""
    out = ["255.255.255.255"]
    net = subnet or local_subnet()
    if net:
        try:
            b = str(ipaddress.ip_network(net, strict=False).broadcast_address)
            if b not in out and not b.startswith("127."):
                out.append(b)
        except ValueError:
            pass
    return out


def pick_subnet(args):
    if args.no_sweep:
        return None
    return args.subnet or local_subnet()


def norm_mac(text):
    """'D0-73-D5-A-BB-C' / 'd0:73:d5:0a:bb:0c' -> 'd0:73:d5:0a:bb:0c' (macOS drops leading zeros)."""
    parts = re.split(r"[:-]", text.strip().lower())
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(x, 16):02x}" for x in parts)
    except ValueError:
        return None


_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\D+?((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})(?![0-9a-fA-F])")


def parse_arp_output(text):
    """Parse `arp -a` (Windows) / `arp -an` (macOS, BSD, Linux net-tools) output into {ip: mac}.
    Incomplete entries have no MAC and are skipped."""
    out = {}
    for line in text.splitlines():
        m = _ARP_LINE.search(line)
        if m:
            mac = norm_mac(m.group(2))
            if mac and mac != "ff:ff:ff:ff:ff:ff" and mac != "00:00:00:00:00:00":
                out[m.group(1)] = mac
    return out


def parse_proc_arp(text):
    """Parse Linux /proc/net/arp into {ip: mac}, skipping incomplete (flags 0x0) entries."""
    out = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[2] != "0x0":
            mac = norm_mac(parts[3])
            if mac and mac != "00:00:00:00:00:00":
                out[parts[0]] = mac
    return out


def arp_table():
    """{ip: mac} from the OS neighbour/ARP cache."""
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8", errors="replace") as f:
                return parse_proc_arp(f.read())
        except OSError:
            pass
    cmd = ["arp", "-a"] if IS_WINDOWS else ["arp", "-an"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as e:
        log.debug(f"arp table unavailable: {e}")
        return {}
    return parse_arp_output(res.stdout)


def arp_lifx():
    """LIFX MACs (OUI d0:73:d5) currently in the ARP table: {ip: mac}."""
    return {ip: mac for ip, mac in arp_table().items() if mac.startswith(LIFX_OUI)}


def ip_sort(items):
    return sorted(items, key=lambda kv: ipaddress.ip_address(kv[0]))


def resolve(sock, args, targets):
    """Turn target tokens into {ip: mac}."""
    subnet = pick_subnet(args)
    only_ips = all(_is_ip(t) for t in targets)
    found = {} if only_ips else discover(sock, subnet)
    chosen, labels = {}, {}
    for t in targets:
        if t.lower() == "all":
            chosen.update(found)
            continue
        if _is_ip(t):
            mac = found.get(t) or probe(sock, t)
            if mac:
                chosen[t] = mac
            else:
                log.warning(f"{t}: no answer on UDP {PORT}")
            continue
        norm = t.lower().replace("-", ":")
        hits = {ip: m for ip, m in found.items() if fmt_mac(m) == norm}
        if not hits:
            for ip, m in found.items():
                if ip not in labels:
                    labels[ip] = get_label(sock, ip, m)
                if t.lower() in labels[ip].lower():
                    hits[ip] = m
        if not hits:  # fall back to remembered devices (matches by MAC or saved label)
            known = [(k, d) for k, d in CACHE.devices.items()
                     if k == norm or t.lower() in d.get("label", "").lower()]
            for key, d in known:
                mac = probe(sock, d["ip"]) if d.get("ip") else None
                if mac and fmt_mac(mac) == key:
                    hits[d["ip"]] = mac
                else:
                    log.warning(f"{t}: known device '{d.get('label', '?')}' {key} "
                                f"(last seen {d.get('last_seen', '?')} at {d.get('ip', '?')}) is not answering"
                                f" - run 'scan' if its IP changed")
            if not known:
                log.warning(f"{t}: no matching LIFX device found")
        chosen.update(hits)
    return chosen


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------- commands ---
def print_table(sock, devs):
    log.info(f"{'IP':15}  {'MAC':17}  {'POWER':5}  {'PRODUCT':7}  LABEL")
    for ip, mac in ip_sort(devs.items()):
        log.info(f"{ip:15}  {fmt_mac(mac):17}  {get_power(sock, ip, mac):5}  "
                 f"{get_product(sock, ip, mac):7}  {get_label(sock, ip, mac)}")


def cmd_scan(sock, args):
    subnet = pick_subnet(args)
    log.info(f"Scanning UDP {PORT}: broadcast" + (f" + sweep {subnet}" if subnet else "") + " ...")
    found = discover(sock, subnet)
    if found:
        print_table(sock, found)
    else:
        log.warning("No LIFX devices answered.")
    arp = arp_lifx()
    live = {fmt_mac(m) for m in found.values()}
    missing = [(k, d) for k, d in CACHE.sorted() if k not in live]
    if missing:
        log.warning("Known devices NOT answering:")
        for k, d in missing:
            where = "in ARP: on Wi-Fi, LIFX service not answering" if arp.get(d.get("ip")) == k \
                else "not in ARP: off Wi-Fi?"
            log.warning(f"  {d.get('ip', '?'):15}  {k}  {d.get('label', '?'):20}  "
                        f"last seen {d.get('last_seen', '?')}  ({where})")
    silent = {ip: m for ip, m in arp.items() if ip not in found and m not in CACHE.devices}
    if silent:
        log.warning("LIFX MACs in the ARP table that did NOT answer on UDP 56700")
        log.warning("(on Wi-Fi but LIFX service hung, or ARP entry is stale):")
        for ip, m in ip_sort(silent.items()):
            log.warning(f"  {ip:15}  {m}")


def cmd_status(sock, args):
    devs = resolve(sock, args, args.targets or ["all"])
    if devs:
        print_table(sock, devs)
    else:
        log.warning("No LIFX devices answered.")
        return 1


def cmd_power(sock, args, on):
    devs = resolve(sock, args, args.targets or ["all"])
    if not devs:
        log.warning("No LIFX devices answered.")
        return 1
    payload = struct.pack("<HI", 65535 if on else 0, args.fade)
    for ip, mac in devs.items():
        msg = frame(LIGHT_SET_POWER, mac, payload, ack=True)
        for _ in range(3):
            send(sock, msg, ip)
            time.sleep(0.05)
    time.sleep(args.fade / 1000 + 0.3)
    rc = 0
    for ip, mac in ip_sort(devs.items()):
        state = get_power(sock, ip, mac)
        ok = state == ("on" if on else "off")
        rc |= 0 if ok else 1
        line = f"{ip:15}  {get_label(sock, ip, mac):24}  -> {state}"
        if ok:
            log.info(line)
        else:
            log.warning(line + f"  (wanted {'on' if on else 'off'})")
    return rc


def cmd_reboot(sock, args):
    devs = resolve(sock, args, args.targets)
    if not devs:
        log.warning("No LIFX devices answered.")
        return 1
    labels = {ip: get_label(sock, ip, mac) for ip, mac in devs.items()}
    for ip, mac in devs.items():
        if fmt_mac(mac) in CACHE.devices:  # so the uptime reset isn't reported as a surprise
            CACHE.devices[fmt_mac(mac)]["expect_reboot_until"] = time.time() + 600
            CACHE.dirty = True
        msg = frame(SET_REBOOT, mac, ack=True)
        for _ in range(3):
            send(sock, msg, ip)
            time.sleep(0.05)
        log.info(f"Reboot sent: {ip:15} {fmt_mac(mac)}  {labels[ip]}")
    if args.no_wait:
        return 0

    pending = {mac: ip for ip, mac in devs.items()}
    t0 = time.time()
    log.info(f"Waiting up to {args.wait}s for devices to come back ...")
    time.sleep(6)  # let them actually go down first
    end = time.time() + args.wait
    while pending and time.time() < end:
        seen = {m: ip for ip, m in discover(sock, None, timeout=1.5).items()}
        for mac, old_ip in list(pending.items()):
            new_ip = seen.get(mac) or (old_ip if probe(sock, old_ip, tries=1) == mac else None)
            if new_ip:
                del pending[mac]
                moved = f" (was {old_ip})" if new_ip != old_ip else ""
                log.info(f"Back online after {time.time() - t0:.0f}s: {new_ip}{moved}  {fmt_mac(mac)}")
                if args.then_on:
                    payload = struct.pack("<HI", 65535, 500)
                    for _ in range(3):
                        send(sock, frame(LIGHT_SET_POWER, mac, payload, ack=True), new_ip)
                        time.sleep(0.05)
                    log.info(f"  turned on -> {get_power(sock, new_ip, mac)}")
        if pending:
            time.sleep(2)
    for mac, ip in pending.items():
        log.warning(f"Not back after {args.wait}s: {ip} {fmt_mac(mac)} - try 'scan', or power-cycle it")
    return 1 if pending else 0


def _key_to_mac(key):
    return bytes.fromhex(key.replace(":", ""))


def _parse_ts(s):
    try:
        return time.mktime(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except (TypeError, ValueError):
        return None


def _label_of(sock, ip, mac):
    return CACHE.devices.get(fmt_mac(mac), {}).get("label") or get_label(sock, ip, mac)


def cmd_watch(sock, args):
    subnet = pick_subnet(args)
    _ConsoleFormatter.timestamps = True
    online, misses, last_seen, down = {}, {}, {}, {}  # mac->ip, mac->n, mac->t, mac->t last seen
    power = {}  # mac -> last power state seen
    log.info(f"Watching every {args.interval}s, DOWN after {args.misses} missed scans (Ctrl-C to stop)")
    first = True
    try:
        while True:
            now = {m: ip for ip, m in discover(sock, subnet).items()}
            t = time.time()
            for m, ip in now.items():
                if m in down:
                    gone = _dur(t - down.pop(m))
                    log.warning(f"BACK    {ip:15} {fmt_mac(m)}  {_label_of(sock, ip, m)}  (unreachable ~{gone})")
                elif m not in online:
                    log.info(f"UP      {ip:15} {fmt_mac(m)}  {_label_of(sock, ip, m)}")
                online[m], misses[m], last_seen[m] = ip, 0, t
                # power changes and silent reboots (uptime reset) while it stayed reachable
                pw = get_power(sock, ip, m)
                prev = power.get(m)
                if prev and pw != "?" and pw != prev:
                    if pw == "off":
                        log.warning(f"POWER   {ip:15} {fmt_mac(m)}  {_label_of(sock, ip, m)}  on -> off "
                                    "(if you didn't do it: app schedules/routines, Alexa/Google/HomeKit)")
                    else:
                        log.info(f"POWER   {ip:15} {fmt_mac(m)}  {_label_of(sock, ip, m)}  off -> on")
                if pw != "?":
                    power[m] = pw
                get_uptime(sock, ip, m)  # logs REBOOTED if the uptime reset and we didn't ask for it
            for m in list(online):
                if m not in now:
                    misses[m] += 1
                    if misses[m] >= args.misses:
                        ip = online.pop(m)
                        in_arp = arp_lifx().get(ip) == fmt_mac(m)
                        log.warning(f"DOWN    {ip:15} {fmt_mac(m)}  {_label_of(sock, ip, m)}  "
                                    + ("(still in ARP: on Wi-Fi, LIFX service not answering)"
                                       if in_arp else "(gone from ARP: off Wi-Fi)"))
                        down[m] = last_seen[m]
            if first:  # remembered devices that aren't here at all
                for key, d in CACHE.sorted():
                    m = _key_to_mac(key)
                    if m not in now:
                        log.warning(f"MISSING {d.get('ip', '?'):15} {key}  {d.get('label', '?')}  "
                                    f"(known device, last seen {d.get('last_seen', '?')})")
                        down[m] = _parse_ts(d.get("last_seen")) or t
                first = False
            if down:
                log.debug("still down: " + ", ".join(f"{fmt_mac(m)} {_dur(t - s)}" for m, s in down.items()))
            CACHE.save()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print()
        log.info("Stopped watching.")
    finally:
        _ConsoleFormatter.timestamps = bool(getattr(args, "verbose", False))
    return 0


def cmd_known(sock, args, check=True):
    """Remembered devices, with a live check of each one."""
    if not CACHE.devices:
        log.warning("No known devices yet. Run a scan first.")
        return 1
    live = {fmt_mac(m): ip for ip, m in discover(sock, None, timeout=2.0).items()} if check else {}
    print(f"{'#':>2}  {'LABEL':22} {'IP':15}  {'MAC':17}  {'NOW':7}  {'POWER':5}  LAST SEEN")
    for i, (key, d) in enumerate(CACHE.sorted(), 1):
        state = ("online" if key in live else "OFFLINE") if check else "-"
        ip = live.get(key, d.get("ip", "?"))
        print(f"{i:>2}  {d.get('label', '?')[:22]:22} {ip:15}  {key:17}  {state:7}  "
              f"{d.get('power', '?'):5}  {d.get('last_seen', '?')}")
    if check:
        off = [d.get("label", k) for k, d in CACHE.devices.items() if k not in live]
        if off:
            log.warning(f"{len(off)} known device(s) not answering: {', '.join(off)}")
        else:
            log.info(f"All {len(CACHE.devices)} known device(s) answering.")
    return 0


def cmd_forget(sock, args):
    rc = 0
    for t in args.targets:
        norm = t.lower().replace("-", ":")
        keys = [k for k, d in CACHE.devices.items()
                if k == norm or d.get("ip") == t or t.lower() in d.get("label", "").lower()]
        if not keys:
            log.warning(f"{t}: not in the known-devices list")
            rc = 1
        for k in keys:
            label = CACHE.devices[k].get("label", "?")
            CACHE.forget(k)
            log.info(f"Forgot {k} ({label})")
    return rc


# ------------------------------------------------------- firmware & health ---
FIRMWARE_URL = "https://lifx.com/pages/current-firmware"


def get_firmware(sock, ip, mac):
    p = query(sock, ip, mac, GET_HOST_FIRMWARE, STATE_HOST_FIRMWARE)
    if not p or len(p) < 20:
        return None
    _build, _res, minor, major = struct.unpack_from("<QQHH", p)
    CACHE.seen(mac, ip, firmware=f"{major}.{minor}")
    return major, minor


def get_rssi(sock, ip, mac):
    p = query(sock, ip, mac, GET_WIFI_INFO, STATE_WIFI_INFO)
    if not p or len(p) < 4:
        return None
    signal = struct.unpack_from("<f", p)[0]
    if signal <= 0:
        return None
    rssi = int(math.floor(10 * math.log10(signal) + 0.5))
    CACHE.seen(mac, ip, rssi=rssi)
    return rssi


def get_uptime(sock, ip, mac):
    p = query(sock, ip, mac, GET_INFO, STATE_INFO)
    if not p or len(p) < 16:
        return None
    up = struct.unpack_from("<QQ", p)[1] / 1e9  # ns -> s
    note_uptime(mac, ip, up)
    return up


def latest_firmware():
    """Versions LIFX lists on its current-firmware page, e.g. {(2, 90), (3, 90)}.
    Cached for a day; falls back to the last good copy if the site can't be reached."""
    cache_file = os.path.join(STATE_DIR, "firmware.json")
    cached = {}
    try:
        with open(cache_file, encoding="utf-8") as f:
            cached = json.load(f)
        if time.time() - cached.get("fetched", 0) < 86400:
            return {tuple(v) for v in cached["versions"]}, cached.get("title", ""), False
    except (OSError, ValueError, KeyError):
        pass
    try:
        req = urllib.request.Request(FIRMWARE_URL, headers={"User-Agent": "Mozilla/5.0 lifxctl"})
        with urllib.request.urlopen(req, timeout=10) as r:
            html = r.read().decode("utf-8", "replace")
        m = re.search(r"<title>(.*?)</title>", html, re.S | re.I)
        title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
        versions = {(int(a), int(b)) for a, b in re.findall(r"\bv?(\d)\.(\d{2})\b", title)}
        if not versions:  # title format changed: fall back to the first heading
            h = re.search(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I)
            versions = {(int(a), int(b)) for a, b in re.findall(r"\bv?(\d)\.(\d{2})\b", h.group(1) if h else "")}
        if versions:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({"fetched": time.time(), "title": title, "versions": sorted(versions)}, f)
            log.debug(f"firmware page: {title}")
            return versions, title, False
        log.warning(f"couldn't find version numbers on {FIRMWARE_URL}")
    except (OSError, ValueError) as e:
        log.warning(f"can't reach {FIRMWARE_URL}: {e}")
    if cached.get("versions"):
        return {tuple(v) for v in cached["versions"]}, cached.get("title", ""), True
    return set(), "", True


def cmd_firmware(sock, args):
    devs = resolve(sock, args, args.targets or ["all"])
    if not devs:
        log.warning("No LIFX devices answered.")
        return 1
    latest, title, stale = latest_firmware()
    if title:
        log.info(f"LIFX says: {title}" + ("  (cached copy)" if stale else ""))
    log.info(f"{'IP':15}  {'LABEL':22} {'FIRMWARE':8}  {'STATUS':26}  {'WIFI':9}  UPTIME")
    rc = 0
    for ip, mac in ip_sort(devs.items()):
        label = _label_of(sock, ip, mac)
        fw, rssi, up = get_firmware(sock, ip, mac), get_rssi(sock, ip, mac), get_uptime(sock, ip, mac)
        fw_s = f"{fw[0]}.{fw[1]}" if fw else "?"
        same = sorted(v for v in latest if fw and v[0] == fw[0])
        if not fw:
            status = "no answer"
        elif not same:
            status = f"no published {fw[0]}.x version"
        elif fw >= same[-1]:
            status = "up to date"
        else:
            status = f"UPDATE {same[-1][0]}.{same[-1][1]} available"
            rc = 1
        if rssi is None:
            wifi = "?"
        else:
            wifi = f"{rssi} dBm" + (" !" if rssi < -70 else "")
        line = f"{ip:15}  {label[:22]:22} {fw_s:8}  {status:26}  {wifi:9}  {_dur(up) if up is not None else '?'}"
        (log.warning if status.startswith("UPDATE") or (rssi is not None and rssi < -70) else log.info)(line)
    log.info("Signal guide: -50 excellent, -60 good, -70 marginal, below -70 expect drop-offs.")
    log.info("Uptime resets on every power loss or crash: a short uptime you didn't cause points to a reboot.")
    if rc:
        log.info("Firmware can only be installed from the LIFX app (Settings > Update firmware).")
    return rc


# ------------------------------------------------------------------ scenes ---
API_BASE = os.environ.get("LIFX_API_BASE", "https://api.lifx.com/v1")
TOKEN_FILE = os.path.join(CONFIG_DIR, "token")


def _scenes_file():
    return os.path.join(STATE_DIR, "scenes.json")


def load_scenes():
    try:
        with open(_scenes_file(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    data.setdefault("cloud", [])
    data.setdefault("local", {})
    return data


def save_scenes(data):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = _scenes_file() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, _scenes_file())


def get_token():
    tok = os.environ.get("LIFX_TOKEN", "").strip()
    if tok:
        return tok
    try:
        with open(TOKEN_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def set_token(tok):
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(tok.strip() + "\n")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass
    log.info(f"LIFX token saved to {TOKEN_FILE}" + ("" if IS_WINDOWS else " (mode 600)"))


def api(method, path, body=None, timeout=15):
    tok = get_token()
    if not tok:
        raise RuntimeError("no LIFX API token: run 'lifxctl.py token' (get one at https://cloud.lifx.com/settings)")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API_BASE + path, data=data, method=method, headers={
        "Authorization": "Bearer " + tok, "Content-Type": "application/json", "User-Agent": "lifxctl"})
    log.debug(f"api {method} {path}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        if e.code == 401:
            raise RuntimeError("LIFX rejected the token (401): create a new one at https://cloud.lifx.com/settings")
        raise RuntimeError(f"LIFX API {e.code}: {detail}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"can't reach LIFX cloud: {e}")


def refresh_cloud_scenes():
    data = load_scenes()
    scenes = api("GET", "/scenes")
    data["cloud"] = [{"uuid": s.get("uuid"), "name": s.get("name", "?"), "states": s.get("states", [])}
                     for s in scenes]
    data["cloud_fetched"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save_scenes(data)
    log.info(f"Fetched {len(data['cloud'])} scene(s) from your LIFX account")
    return data


def scene_list(data):
    """[(kind, name, obj)] cloud first, then local; numbering used by CLI and menu."""
    out = [("cloud", s["name"], s) for s in sorted(data["cloud"], key=lambda s: s["name"].lower())]
    out += [("local", n, s) for n, s in sorted(data["local"].items(), key=lambda kv: kv[0].lower())]
    return out


def find_scene(data, token):
    items = scene_list(data)
    kind = None
    if token.lower().startswith(("local:", "cloud:")):
        kind, token = token.split(":", 1)
        kind = kind.lower()
    pool = [i for i in items if not kind or i[0] == kind]
    if token.isdigit() and not kind and 1 <= int(token) <= len(items):
        return items[int(token) - 1]
    exact = [i for i in pool if i[1].lower() == token.lower()]
    if exact:
        return exact[0]
    part = [i for i in pool if token.lower() in i[1].lower()]
    if len(part) == 1:
        return part[0]
    if len(part) > 1:
        log.warning(f"'{token}' matches several scenes: {', '.join(f'{k}:{n}' for k, n, _ in part)}")
    return None


def cmd_scenes(sock, args):
    data = load_scenes()
    if getattr(args, "refresh", False) or (not data["cloud"] and get_token()):
        try:
            data = refresh_cloud_scenes()
        except RuntimeError as e:
            log.warning(str(e) + ("  (showing cached list)" if data["cloud"] else ""))
    items = scene_list(data)
    if not items:
        log.warning("No scenes yet. Add a LIFX token ('token') to pull your app scenes, "
                    "or save the current look with 'scene-save NAME'.")
        return 1
    print(f"{'#':>2}  {'SOURCE':6}  {'NAME':28}  DEVICES")
    for i, (kind, name, s) in enumerate(items, 1):
        devs = _scene_device_names(kind, s)
        print(f"{i:>2}  {kind:6}  {name[:28]:28}  {devs}")
    if data["cloud"]:
        print(f"(cloud list fetched {data.get('cloud_fetched', '?')}; refresh with 'scenes --refresh')")
    return 0


def _scene_device_names(kind, s):
    keys = []
    if kind == "cloud":
        for st in s.get("states", []):
            sel = str(st.get("selector", ""))
            if sel.startswith("id:"):
                h = sel[3:].lower()
                keys.append(":".join(h[i:i + 2] for i in range(0, 12, 2)))
    else:
        keys = list(s.get("devices", {}).keys())
    names = [CACHE.devices.get(k, {}).get("label", k) for k in keys]
    return ", ".join(names) if names else "-"


def cmd_scene(sock, args):
    data = load_scenes()
    hit = find_scene(data, args.name)
    if not hit:
        log.warning(f"No scene matches '{args.name}'. List them with 'scenes'.")
        return 1
    kind, name, s = hit
    if kind == "local":
        return apply_local_scene(sock, args, name, s)
    if not args.local_only:
        try:
            res = api("PUT", f"/scenes/scene_id:{s['uuid']}/activate", {"duration": args.duration})
            results = res.get("results", []) if isinstance(res, dict) else []
            bad = [r for r in results if r.get("status") != "ok"]
            for r in results:
                (log.info if r.get("status") == "ok" else log.warning)(
                    f"  {r.get('label', r.get('id', '?')):24} {r.get('status')}")
            if not bad:
                log.info(f"Scene '{name}' activated via LIFX cloud")
                return 0
            log.warning(f"{len(bad)} light(s) didn't take the scene via cloud; applying those over the LAN")
            only = {str(r.get("id", "")).lower() for r in bad}
            return apply_cloud_states_locally(sock, args, name, s, only=only)
        except RuntimeError as e:
            log.warning(f"{e}; applying '{name}' over the LAN from the saved copy")
    return apply_cloud_states_locally(sock, args, name, s)


def _hsbk_from_cloud(st):
    c = st.get("color") or {}
    hue = int(round((float(c.get("hue", 0)) % 360) / 360 * 65535))
    sat = int(round(max(0.0, min(1.0, float(c.get("saturation", 0)))) * 65535))
    bri = int(round(max(0.0, min(1.0, float(st.get("brightness", c.get("brightness", 1))))) * 65535))
    kel = int(c.get("kelvin", 3500) or 3500)
    return hue, sat, bri, kel


def _locate(sock, key):
    """IP for a remembered MAC key, verified live."""
    d = CACHE.devices.get(key)
    mac = _key_to_mac(key)
    if d and d.get("ip") and probe(sock, d["ip"], tries=1) == mac:
        return d["ip"]
    for ip, m in discover(sock, None, timeout=1.5).items():
        if m == mac:
            return ip
    return None


def _set_power(sock, ip, mac, on, ms):
    msg = frame(LIGHT_SET_POWER, mac, struct.pack("<HI", 65535 if on else 0, ms), ack=True)
    for _ in range(3):
        send(sock, msg, ip)
        time.sleep(0.03)


def _set_color(sock, ip, mac, hsbk, ms):
    msg = frame(LIGHT_SET_COLOR, mac, struct.pack("<BHHHHI", 0, *hsbk, ms), ack=True)
    for _ in range(3):
        send(sock, msg, ip)
        time.sleep(0.03)


def apply_cloud_states_locally(sock, args, name, s, only=None):
    ms = int(args.duration * 1000)
    rc = 0
    for st in s.get("states", []):
        sel = str(st.get("selector", "")).lower()
        if not sel.startswith("id:"):
            continue
        serial = sel[3:]
        if only and serial not in only:
            continue
        key = ":".join(serial[i:i + 2] for i in range(0, 12, 2))
        ip = _locate(sock, key)
        label = CACHE.devices.get(key, {}).get("label", key)
        if not ip:
            log.warning(f"  {label}: not answering on the LAN")
            rc = 1
            continue
        mac = _key_to_mac(key)
        if st.get("power", "on") == "on":
            _set_color(sock, ip, mac, _hsbk_from_cloud(st), ms)
            _set_power(sock, ip, mac, True, ms)
        else:
            _set_power(sock, ip, mac, False, ms)
        log.info(f"  {label:24} {st.get('power', 'on')} (LAN)")
    log.info(f"Scene '{name}' applied over the LAN (one color per light; for strip gradients "
             f"use a local scene)" + (" (some lights missing)" if rc else ""))
    return rc


# local scenes: exact snapshot, including every zone on a strip
def _collect_many(sock, ip, want, seconds=1.0):
    out, end = [], time.time() + seconds
    while True:
        left = end - time.time()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            data, (rip, _) = sock.recvfrom(2048)
        except socket.timeout:
            break
        except OSError:
            continue
        p = parse(data)
        if p and p[0] == SRC and p[2] == want and rip == ip:
            out.append(p[3])
    return out


def snapshot_device(sock, ip, mac):
    p = query(sock, ip, mac, LIGHT_GET, LIGHT_STATE)
    if not p or len(p) < 12:
        return None
    hsbk = list(struct.unpack_from("<HHHH", p))
    power = struct.unpack_from("<H", p, 10)[0]
    snap = {"label": _label_of(sock, ip, mac), "power": "on" if power else "off", "hsbk": hsbk}
    # strips: try extended multizone (one message covers up to 82 zones; long strips send several)
    send(sock, frame(GET_EXT_ZONES, mac, res=True), ip)
    replies = _collect_many(sock, ip, STATE_EXT_ZONES, 1.0)
    if replies:
        count = struct.unpack_from("<H", replies[0])[0]
        zones = [None] * count
        for r in replies:
            _, index, n = struct.unpack_from("<HHB", r)
            for i in range(n):
                if index + i < count:
                    zones[index + i] = list(struct.unpack_from("<HHHH", r, 5 + 8 * i))
        if all(z is not None for z in zones):
            snap["zones"] = zones
    return snap


def cmd_scene_save(sock, args):
    devs = resolve(sock, args, args.targets or ["all"])
    if not devs:
        log.warning("No LIFX devices answered.")
        return 1
    scene = {"saved": time.strftime("%Y-%m-%d %H:%M:%S"), "devices": {}}
    for ip, mac in ip_sort(devs.items()):
        snap = snapshot_device(sock, ip, mac)
        if not snap:
            log.warning(f"  {ip}: no state reply, skipped")
            continue
        scene["devices"][fmt_mac(mac)] = snap
        extra = f", {len(snap['zones'])} zones" if "zones" in snap else ""
        log.info(f"  {snap['label']:24} {snap['power']}{extra}")
    if not scene["devices"]:
        return 1
    data = load_scenes()
    replaced = args.name in data["local"]
    data["local"][args.name] = scene
    save_scenes(data)
    log.info(f"Local scene '{args.name}' {'updated' if replaced else 'saved'} ({len(scene['devices'])} device(s))")
    return 0


def apply_local_scene(sock, args, name, s):
    ms = int(args.duration * 1000)
    rc = 0
    for key, snap in s.get("devices", {}).items():
        ip = _locate(sock, key)
        if not ip:
            log.warning(f"  {snap.get('label', key)}: not answering on the LAN")
            rc = 1
            continue
        mac = _key_to_mac(key)
        if snap.get("power") == "off":
            _set_power(sock, ip, mac, False, ms)
            log.info(f"  {snap.get('label', key):24} off")
            continue
        zones = snap.get("zones")
        if zones:
            for start in range(0, len(zones), 82):
                chunk = zones[start:start + 82]
                colors = b"".join(struct.pack("<HHHH", *z) for z in chunk).ljust(82 * 8, b"\0")
                payload = struct.pack("<IBHB", ms, 1, start, len(chunk)) + colors
                msg = frame(SET_EXT_ZONES, mac, payload, ack=True)
                for _ in range(2):
                    send(sock, msg, ip)
                    time.sleep(0.03)
        else:
            _set_color(sock, ip, mac, tuple(snap["hsbk"]), ms)
        _set_power(sock, ip, mac, True, ms)
        log.info(f"  {snap.get('label', key):24} on" + (f", {len(zones)} zones" if zones else ""))
    log.info(f"Local scene '{name}' applied" + (" (some lights missing)" if rc else ""))
    return rc


def cmd_scene_delete(sock, args):
    data = load_scenes()
    if args.name in data["local"]:
        del data["local"][args.name]
        save_scenes(data)
        log.info(f"Deleted local scene '{args.name}'")
        return 0
    log.warning(f"No local scene named '{args.name}' (app scenes are deleted in the LIFX app)")
    return 1


def cmd_token(sock, args):
    tok = args.value
    if not tok:
        print("Create a personal access token at https://cloud.lifx.com/settings (log in with your LIFX app account).")
        try:
            tok = getpass.getpass("Paste token (input hidden; Enter to cancel): ").strip()
        except (EOFError, KeyboardInterrupt):
            tok = ""
    if not tok:
        log.info("Token unchanged." + ("" if get_token() else " (none set)"))
        return 0
    set_token(tok)
    try:
        refresh_cloud_scenes()
    except RuntimeError as e:
        log.warning(str(e))
        return 1
    return 0


def scenes_menu(sock, args, quick):
    while True:
        data = load_scenes()
        ns = argparse.Namespace(**vars(quick), refresh=False)
        print()
        cmd_scenes(sock, ns)
        print("\n  #) activate that scene   r) refresh from LIFX app   s) save current look as local scene")
        print("  d) delete a local scene   t) set LIFX API token      Enter) back")
        c = _ask("Scenes: ").strip()
        if not c:
            return
        lc = c.lower()
        if lc == "r":
            try:
                refresh_cloud_scenes()
            except RuntimeError as e:
                log.warning(str(e))
        elif lc == "s":
            name = _ask("Name for this scene: ")
            if name:
                picked = _pick("Which lights to include", allow_all=True)
                if picked:
                    cmd_scene_save(sock, argparse.Namespace(**vars(quick), name=name,
                                                            targets=_targets_for(picked)))
        elif lc == "d":
            name = _ask("Local scene name to delete: ")
            if name:
                cmd_scene_delete(sock, argparse.Namespace(name=name))
        elif lc == "t":
            cmd_token(sock, argparse.Namespace(value=None))
        else:
            cmd_scene(sock, argparse.Namespace(**vars(quick), name=c, duration=1.0, local_only=False))


# --------------------------------------------------------- help & diagnose ---
ABOUT = """\
lifxctl: keep an eye on your LIFX lights and get them back without the phone app.

It talks to your lights directly on your home network (the same LAN protocol the LIFX
app uses), so it works even when the app says a light is offline. It can:
  * find every LIFX light, remember its IP / MAC / name, and spot ones that went missing
  * turn lights on/off, reboot them, and switch scenes (from your LIFX app or saved here)
  * check firmware, Wi-Fi signal strength and uptime
  * watch your lights over time and log exactly when they drop off, reboot or turn off
  * DIAGNOSE why a light keeps disappearing or turning off, and tell you what to fix

Everything is logged to {log}.
Saved devices: {cache}.
"""

GUIDE = """\
LIFX TROUBLESHOOTING GUIDE
==========================

First, find out WHICH problem you have. Run "d) Diagnose" in the menu (or
`lifxctl.py diagnose`), or leave "watch" running for a day and read the log.

-----------------------------------------------------------------------------
SYMPTOM A: The app can't see the light, but this script can
-----------------------------------------------------------------------------
The light is fine and still on Wi-Fi. Your phone just isn't hearing it.
The LIFX app finds lights with a broadcast on UDP 56700, and some routers drop
those broadcasts.
  Fix (router settings):
  * Put the phone and lights on the SAME network: not a guest network, not a
    separate IoT VLAN (if you use VLANs, enable mDNS/Bonjour forwarding)
  * Turn off AP / client / wireless isolation on the network the lights use
  * Turn off IGMP snooping or multicast filtering (or toggle it off and on),
    then restart the router
  * If the phone is on 5 GHz and the lights are on 2.4 GHz, make sure the router
    bridges them (most do; some "IoT" or "smart" modes don't)

-----------------------------------------------------------------------------
SYMPTOM B: The light drops off Wi-Fi completely, and unplugging it fixes it
-----------------------------------------------------------------------------
Diagnose shows "not in ARP / off Wi-Fi", or watch logs DOWN ... (gone from ARP).
The light lost its Wi-Fi connection and didn't rejoin on its own.
  Fix, roughly in order of how often it helps:
  1. Signal. LIFX lights are 2.4 GHz only. Aim for -65 dBm or better. A strip
     behind a TV is shielded by the TV's metal back panel and backlight; moving
     the controller a few inches out from behind the TV can gain 10 dB or more.
  2. Band steering / "Smart Connect": give 2.4 GHz its own network name (or add
     a 2.4-only IoT network) and rejoin the lights to it.
  3. Security: WPA2-PSK (AES). LIFX can't use WPA3-only or Enterprise. In
     WPA2/WPA3 "transition" mode, set PMF (protected management frames) to
     optional, not required.
  4. Wi-Fi 6 settings on 2.4 GHz: allow 802.11b/g/n. No AX-only mode. Try turning
     802.11ax off on 2.4 GHz if drops continue.
  5. 2.4 GHz channel: fixed channel 1, 6 or 11 at 20 MHz width, not "auto" and
     not 40 MHz. Auto-channel routers often hop at night, which strands IoT devices.
  6. Mesh / extenders: lights get stuck on a far node during hand-offs. Turn off
     "smart steering" / fast roaming (802.11r) for the IoT network, or pin the
     lights to the nearest node if your system allows it.
  7. Turn off Airtime Fairness, and "QoS" or "traffic optimisation" features, and
     see if the drops stop.
  8. DHCP: reserve a fixed IP for each light (by MAC) in the router. That stops
     lease-renewal failures and keeps IPs from moving.
  9. Firmware: update from the LIFX app (Settings > Update firmware).
 10. Still dropping? Factory reset and set it up again (see RESET below).
  Workaround while you fix it: put the strip on a smart plug and let a script
  power-cycle it when watch reports DOWN.

-----------------------------------------------------------------------------
SYMPTOM C: The light is still on Wi-Fi but ignores commands ("hung")
-----------------------------------------------------------------------------
Diagnose shows "in ARP but LIFX service not answering". The radio is
connected but the light's software is stuck.
  Fix: try `lifxctl.py reboot <light>` first. If it doesn't answer at all, power
  cycle it. If this keeps happening, update firmware or factory reset.

-----------------------------------------------------------------------------
SYMPTOM D: The light turns itself OFF
-----------------------------------------------------------------------------
Two very different causes. Diagnose and watch tell them apart:
  * Uptime reset ("REBOOTED") means the light lost power or crashed. For a strip,
    check the power supply and connectors: a loose barrel plug, a failing or
    undersized adapter, a power strip with a timer or switch, or the TV's USB
    port turning off with the TV. After power returns, LIFX lights come back ON
    by default.
  * Power went on -> off with NO reboot means something sent it an "off"
    command. Check:
      - LIFX app: Schedules, Routines, Day & Dusk, sleep/wake timers
      - Alexa / Google Home / Apple Home automations, groups and routines
      - IFTTT, SmartThings, Home Assistant or other integrations on your account
      - A light switch or smart plug the strip is wired through
      - Someone else's phone with access to your LIFX account

-----------------------------------------------------------------------------
RESET (last resort: erases its Wi-Fi settings; set it up again in the app)
-----------------------------------------------------------------------------
  * Bulbs: with the light on, turn power off and on 5 times, slowly and evenly.
    On the last power-on it flashes its reset pattern and enters setup mode.
  * Lightstrip with a controller: press and hold the controller button for
    10-15 seconds (or use the 5x power-cycle method).
  * Newer Everyday Lightstrip (4-button controller): hold all buttons ~10 s.

-----------------------------------------------------------------------------
USEFUL COMMANDS
-----------------------------------------------------------------------------
  lifxctl.py diagnose              run all checks and get a fix list
  lifxctl.py watch --interval 60   log DOWN / BACK / REBOOTED / POWER changes
  lifxctl.py firmware              firmware, Wi-Fi dBm, uptime
  grep -E "DOWN|BACK|REBOOT|POWER" {log}                     (Linux/macOS)
  findstr "DOWN BACK REBOOT POWER" "{log}"                    (Windows)
"""


def note_uptime(mac, ip, uptime):
    """Track boot time; log a reboot we didn't cause. Returns True if one was detected."""
    key = fmt_mac(mac)
    d = CACHE.devices.get(key)
    if d is None or uptime is None:
        return False
    now = time.time()
    boot = now - uptime
    prev = d.get("boot_time")
    rebooted = prev is not None and boot - prev > 120  # >2 min later than the last boot we knew
    expected = False
    if rebooted:
        expected = d.get("expect_reboot_until", 0) > now
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(boot))
        if expected:
            log.info(f"{key} {d.get('label', '')} rebooted at {when} (requested by lifxctl)")
        else:
            log.warning(f"REBOOTED {ip:15} {key}  {d.get('label', '')}  at ~{when}  "
                        f"(power loss or crash: nobody asked it to)")
            d.setdefault("reboots", []).append(when)
            d["reboots"] = d["reboots"][-20:]
    d["boot_time"] = boot
    if rebooted:
        d.pop("expect_reboot_until", None)
    CACHE.dirty = True
    return rebooted and not expected


def _log_history(days=7):
    """Parse DOWN/BACK/REBOOTED/POWER events from the log files. Returns {mac: [(ts, kind, text)]}."""
    base = os.path.expanduser(LOGPATH or DEFAULT_LOG)
    files = [f"{base}.{i}" for i in range(5, 0, -1)] + [base]
    cutoff = time.time() - days * 86400
    pat = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \S+\s+\[\d+\] "
                     r"(DOWN|BACK|REBOOTED|POWER|MISSING)\s+(\S+)\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})(.*)$")
    out = {}
    for fn in files:
        try:
            with open(fn, encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = pat.match(line.rstrip("\n"))
                    if not m:
                        continue
                    ts = _parse_ts(m.group(1))
                    if ts and ts >= cutoff:
                        out.setdefault(m.group(4), []).append((m.group(1), m.group(2), m.group(5).strip()))
        except OSError:
            continue
    return out


FIX_TEXT = {
    "broadcast": "Router is dropping LIFX discovery broadcasts (that's why the app loses lights). "
                 "Turn off AP/client isolation and IGMP snooping/multicast filtering; keep phone and "
                 "lights on the same network (no guest/IoT VLAN split).",
    "signal": "Weak Wi-Fi signal. Move the strip's controller out from behind the TV, move the "
              "router/mesh node closer, or set 2.4 GHz to a fixed channel 1/6/11 at 20 MHz.",
    "loss": "Packet loss to the light. Usually signal or 2.4 GHz interference: fixed channel 1/6/11 "
            "at 20 MHz, turn off Airtime Fairness/QoS, and move it away from the TV's metal back.",
    "offwifi": "Light dropped off Wi-Fi. Check band steering (give 2.4 GHz its own name), WPA2-AES "
               "(PMF optional, not required), no AX-only on 2.4 GHz, and mesh smart-steering. "
               "Power cycle it to bring it back now.",
    "hung": "Light is on Wi-Fi but its LIFX software isn't answering. Try 'reboot'; if that fails, "
            "power cycle. Repeated hangs: update firmware or factory reset.",
    "reboots": "Unexpected reboots mean it's losing power or crashing. Check the strip's power adapter "
               "and connectors, and don't power it from the TV's USB port or a switched/timer outlet.",
    "turnedoff": "Something sent it an OFF command. Check LIFX app Schedules/Routines/Day & Dusk, "
                 "Alexa/Google/Apple Home automations, and other integrations on your LIFX account.",
    "ipchange": "IP address keeps changing. Add a DHCP reservation for each light's MAC in your router.",
    "firmware": "Firmware update available. Install it from the LIFX app (Settings > Update firmware).",
    "outages": "Repeated outages are logged. If they happen at the same time each day, look for router "
               "auto-channel changes, scheduled reboots or DHCP lease renewals at that time.",
    "nodata": "No outage history yet. Leave 'lifxctl.py watch' running for a day so the next "
              "diagnose can show when and how the light drops.",
}


def cmd_diagnose(sock, args):
    findings, fixes = [], []

    def finding(sev, text, fix=None):
        findings.append((sev, text))
        quiet = sev in ("ok", "info")
        (log.info if quiet else log.warning)(("  " if quiet else "") + text)
        if fix and fix not in fixes:
            fixes.append(fix)

    log.info("LIFX diagnose: checking discovery, signal, packet loss, reboots, power and history.")
    log.info("This takes 5-10 seconds per light. Lines starting with ! are problems.\n")
    subnet = pick_subnet(args)

    # 1. how can we reach them?
    log.info("[1] Discovery: broadcast (what the app uses) vs direct")
    bcast = discover(sock, None, timeout=2.0, use_cache=False)
    full = discover(sock, subnet, timeout=3.0)
    b_macs = {fmt_mac(m) for m in bcast.values()}
    only_direct = [(ip, m) for ip, m in full.items() if fmt_mac(m) not in b_macs]
    if full and not only_direct:
        finding("ok", f"All {len(full)} light(s) answer the broadcast, so the app should find them.")
    elif only_direct and bcast:
        finding("warn", f"{len(only_direct)} light(s) answer only when contacted directly, not by broadcast: "
                + ", ".join(_label_of(sock, ip, m) for ip, m in only_direct), "broadcast")
    elif only_direct:
        finding("warn", "No light answers the broadcast, but they do answer directly: broadcasts are "
                "being blocked on your network.", "broadcast")

    # 2. remembered lights that are gone
    arp = arp_lifx()
    live = {fmt_mac(m): ip for ip, m in full.items()}
    log.info("\n[2] Known lights not answering")
    gone = [(k, d) for k, d in CACHE.sorted() if k not in live]
    if not gone:
        finding("ok", "Every remembered light is answering.")
    for k, d in gone:
        if arp.get(d.get("ip")) == k:
            finding("bad", f"{d.get('label', k)} ({d.get('ip')}): on Wi-Fi (in ARP) but LIFX not answering: HUNG",
                    "hung")
        else:
            finding("bad", f"{d.get('label', k)} (last at {d.get('ip')}, seen {d.get('last_seen', '?')}): "
                    "not on the network: OFF WI-FI or unpowered", "offwifi")

    # 3. per-light health
    latest, _title, _stale = latest_firmware()
    for ip, mac in ip_sort(full.items()):
        key = fmt_mac(mac)
        label = _label_of(sock, ip, mac)
        d = CACHE.devices.get(key, {})
        log.info(f"\n[3] {label}  {ip}  {key}")
        loss, med, worst = link_quality(sock, ip, mac)
        if med is None:
            finding("bad", f"{label}: no replies to 20 pings (100% loss)", "loss")
        elif loss >= 10 or med > 150:
            finding("warn", f"{label}: {loss:.0f}% packet loss, median {med:.0f} ms, worst {worst:.0f} ms", "loss")
        else:
            finding("ok", f"{label}: {loss:.0f}% packet loss, median {med:.0f} ms (good)")
        rssi = get_rssi(sock, ip, mac)
        if rssi is None:
            finding("warn", f"{label}: Wi-Fi signal unknown")
        elif rssi < -75:
            finding("bad", f"{label}: Wi-Fi signal {rssi} dBm: VERY WEAK (drop-offs expected)", "signal")
        elif rssi < -67:
            finding("warn", f"{label}: Wi-Fi signal {rssi} dBm: marginal", "signal")
        else:
            finding("ok", f"{label}: Wi-Fi signal {rssi} dBm: fine")
        up = get_uptime(sock, ip, mac)
        if up is not None:
            reboots = d.get("reboots", [])
            if reboots:
                finding("bad", f"{label}: {len(reboots)} unexpected reboot(s) seen, last {reboots[-1]}", "reboots")
            if up < 3600:
                finding("warn", f"{label}: up only {_dur(up)}: it lost power or rebooted recently "
                        "(ignore if you just unplugged it)", "reboots")
            else:
                finding("ok", f"{label}: up {_dur(up)}")
        fw = get_firmware(sock, ip, mac)
        same = sorted(v for v in latest if fw and v[0] == fw[0])
        if fw and same and fw < same[-1]:
            finding("warn", f"{label}: firmware {fw[0]}.{fw[1]}, {same[-1][0]}.{same[-1][1]} available", "firmware")
        elif fw:
            finding("ok", f"{label}: firmware {fw[0]}.{fw[1]}")
        power = get_power(sock, ip, mac)
        if power == "off":
            finding("warn", f"{label}: reachable but switched OFF. If you didn't turn it off, "
                    "something else did", "turnedoff")
        if d.get("ip_changes", 0):
            finding("warn", f"{label}: IP address changed {d['ip_changes']} time(s)", "ipchange")

    # 4. history from the log
    log.info("\n[4] Outage history (last 7 days, from watch)")
    hist = _log_history()
    if not hist:
        finding("info", "No DOWN/REBOOTED/POWER events logged yet.", "nodata")
    for key, events in hist.items():
        label = CACHE.devices.get(key, {}).get("label", key)
        counts = {}
        for _ts, kind, _t in events:
            counts[kind] = counts.get(kind, 0) + 1
        summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
        sev = "warn" if counts.get("DOWN") or counts.get("REBOOTED") or counts.get("POWER") else "ok"
        finding(sev, f"{label}: {summary}", "outages" if counts.get("DOWN", 0) >= 2 else None)
        for ts, kind, text in events[-6:]:
            log.info(f"      {ts}  {kind:8} {text[:70]}")
        downs = [ts[11:13] for ts, kind, _ in events if kind == "DOWN"]
        if len(downs) >= 3:
            hours = {h: downs.count(h) for h in set(downs)}
            h, n = max(hours.items(), key=lambda kv: kv[1])
            if n >= max(2, len(downs) // 2):
                finding("warn", f"{label}: {n} of {len(downs)} drop-offs happened around {h}:00. "
                        "Look for something scheduled then (router auto-channel, reboot, DHCP renewal)", "outages")

    # 5. what to do
    log.info("\n" + "=" * 70)
    if not fixes:
        log.info("No problems found right now. If a light still misbehaves, run 'watch' and diagnose again later.")
    else:
        log.info("WHAT TO DO (most likely first):")
        order = ["offwifi", "hung", "signal", "loss", "reboots", "turnedoff", "broadcast",
                 "ipchange", "outages", "firmware", "nodata"]
        for i, f in enumerate(sorted(fixes, key=order.index), 1):
            log.info(f"  {i}. {FIX_TEXT[f]}")
        log.info("\nFull guide: lifxctl.py guide   (menu: h)")
    CACHE.save()
    return 1 if any(s == "bad" for s, _ in findings) else 0


def cmd_guide(sock, args):
    text = GUIDE.format(log=LOGPATH or DEFAULT_LOG)
    if sys.stdout.isatty() and not getattr(args, "no_pager", False):
        import pydoc
        pydoc.pager(text)  # less on Linux/macOS, more on Windows
        return 0
    print(text)
    return 0


def print_about():
    print(ABOUT.format(log=LOGPATH or "(logging off)", cache=CACHE.path or "(not saved)"))


# --------------------------------------------------------------------- menu ---
MENU = """
  1) Scan network (full sweep + ARP check)
  2) Known devices: refresh status
  3) Turn ON
  4) Turn OFF
  5) Reboot (and turn on when it's back)
  6) Watch for drop-offs (Ctrl-C to return here)
  7) Forget a device
  8) Show recent log
  s) Scenes (from your LIFX app, plus local snapshots)
  f) Firmware, Wi-Fi signal and uptime
  d) Diagnose: why do my lights drop off / stop responding / turn off?
  h) Help: troubleshooting guide and fixes
  q) Quit
"""


def _ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt


def _pick(prompt, allow_all=True):
    """Choose remembered devices by number. Returns MAC strings, ['all'], or []."""
    items = CACHE.sorted()
    if not items:
        print("No known devices yet. Run a scan first (option 1).")
        return []
    print()
    for i, (key, d) in enumerate(items, 1):
        print(f"  {i:>2}) {d.get('label', '?')[:24]:24} {d.get('ip', '?'):15}  {key}")
    if allow_all:
        print("   a) all")
    raw = _ask(f"{prompt} (e.g. 1  or 1,3{'  or a' if allow_all else ''}; Enter to cancel): ").lower()
    if not raw:
        return []
    if allow_all and raw in ("a", "all"):
        return ["all"]
    picked = []
    for part in raw.replace(" ", ",").split(","):
        if part.isdigit() and 1 <= int(part) <= len(items):
            picked.append(items[int(part) - 1][0])
        elif part:
            print(f"  ignoring '{part}'")
    return picked


def _targets_for(picked):
    """'all' in the menu means every remembered device plus anything new that answers."""
    return ["all"] + [k for k, _ in CACHE.sorted()] if picked == ["all"] else picked


def cmd_menu(sock, args):
    base = dict(subnet=args.subnet, no_sweep=args.no_sweep, verbose=args.verbose)
    quick = argparse.Namespace(**{**base, "no_sweep": True})  # broadcast + remembered IPs only
    full = argparse.Namespace(**base)

    print_about()
    print("Tip: 'd' diagnoses drop-offs and power-offs; 'h' is the troubleshooting guide.\n")
    if not CACHE.devices:
        print("No devices remembered yet, so running a first scan ...\n")
        cmd_scan(sock, full)
        CACHE.save()
    else:
        cmd_known(sock, quick)

    while True:
        print(MENU)
        try:
            choice = _ask("Choice: ").lower()
        except KeyboardInterrupt:  # Ctrl-C / Ctrl-D at the main prompt quits
            print()
            break
        print()
        if choice in ("q", "quit", "exit"):
            break
        try:
            if choice == "1":
                cmd_scan(sock, full)
            elif choice == "2":
                cmd_known(sock, quick)
            elif choice in ("3", "4"):
                picked = _pick("Turn " + ("ON" if choice == "3" else "OFF"))
                if picked:
                    ns = argparse.Namespace(**vars(quick), targets=_targets_for(picked), fade=500)
                    cmd_power(sock, ns, choice == "3")
            elif choice == "5":
                picked = _pick("Reboot")
                n = "ALL" if picked == ["all"] else len(picked)
                if picked and _ask(f"Reboot {n} device(s)? [y/N]: ").lower() == "y":
                    ns = argparse.Namespace(**vars(quick), targets=_targets_for(picked),
                                            wait=60, no_wait=False, then_on=True)
                    cmd_reboot(sock, ns)
            elif choice == "6":
                iv = _ask("Check every how many seconds? [30]: ") or "30"
                ns = argparse.Namespace(**vars(full), interval=int(iv) if iv.isdigit() else 30, misses=2)
                cmd_watch(sock, ns)
            elif choice == "7":
                picked = _pick("Forget", allow_all=False)
                if picked:
                    cmd_forget(sock, argparse.Namespace(targets=picked))
            elif choice == "8":
                _show_log(args, 30)
            elif choice == "s":
                scenes_menu(sock, args, quick)
            elif choice == "d":
                cmd_diagnose(sock, full)
            elif choice in ("h", "?", "help"):
                print_about()
                cmd_guide(sock, args)
            elif choice == "f":
                picked = _pick("Check which", allow_all=True)
                if picked:
                    cmd_firmware(sock, argparse.Namespace(**vars(quick), targets=_targets_for(picked)))
            elif choice:
                print("Pick 1-8, s, f, d, h or q.")
        except KeyboardInterrupt:  # inside an action: cancel it, back to the menu
            print("\n(cancelled)")
        finally:
            CACHE.save()
    return 0


def _show_log(args, n):
    path = getattr(args, "logpath", None)
    if not path or not os.path.exists(path):
        print("No log file (logging disabled or nothing written yet).")
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-n:]
    print(f"--- last {len(lines)} lines of {path} ---")
    print("".join(lines).rstrip())


def _dur(sec):
    sec = int(sec)
    d, rem = divmod(sec, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d{h:02d}h"
    return f"{h}h{m:02d}m" if h else (f"{m}m{s:02d}s" if m else f"{s}s")


# ------------------------------------------------------------------ logging ---
DEFAULT_LOG = os.path.join(STATE_DIR, "lifxctl.log")
DEFAULT_CACHE = os.path.join(STATE_DIR, "devices.json")
LOGPATH = None  # set in main()


class _ConsoleFilter(logging.Filter):
    """Keep 'file only' records (run headers) off the console."""
    def filter(self, record):
        return not getattr(record, "fileonly", False)


class _ConsoleFormatter(logging.Formatter):
    """'! ' prefix for warnings; timestamps only when watching or verbose."""
    timestamps = False

    def format(self, record):
        msg = super().format(record)
        prefix = "! " if record.levelno >= logging.WARNING else ("  " if record.levelno == logging.DEBUG else "")
        ts = self.formatTime(record, "%Y-%m-%d %H:%M:%S") + " " if self.timestamps else ""
        return ts + prefix + msg


def setup_logging(args):
    log.setLevel(logging.DEBUG)
    level = logging.DEBUG if args.verbose else logging.INFO

    con = logging.StreamHandler(sys.stdout)
    con.setLevel(logging.WARNING if args.quiet else level)
    _ConsoleFormatter.timestamps = args.verbose
    con.setFormatter(_ConsoleFormatter("%(message)s"))
    con.addFilter(_ConsoleFilter())
    log.addHandler(con)

    if args.no_log:
        return None
    path = os.path.expanduser(args.log or DEFAULT_LOG)
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    except OSError as e:
        log.warning(f"can't open log file {path}: {e} (console only)")
        return None
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(process)d] %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(fh)
    return path


def make_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    if IS_WINDOWS and hasattr(socket, "SIO_UDP_CONNRESET"):
        # otherwise every unanswered sweep packet makes recvfrom() raise WSAECONNRESET
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except (OSError, ValueError):
            pass
    sock.bind(("", 0))
    return sock


def _console_setup():
    """Never crash on a character the console can't show (old Windows code pages)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


# --------------------------------------------------------------------- main ---
def main():
    global CACHE, LOGPATH
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=ABOUT.split("\nEverything is logged")[0]
        + "\nRun with no command for the interactive menu.",
        epilog="Lights keep dropping off or turning off?  Run:  lifxctl.py diagnose   and   lifxctl.py guide")
    ap.add_argument("--subnet", help="range to sweep (default: auto-detected local /24)")
    ap.add_argument("--no-sweep", action="store_true", help="broadcast only, skip per-IP sweep")
    ap.add_argument("--log", metavar="FILE", help=f"log file (default {DEFAULT_LOG})")
    ap.add_argument("--no-log", action="store_true", help="don't write a log file")
    ap.add_argument("--cache", metavar="FILE", help=f"known-devices file (default {DEFAULT_CACHE})")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging (every packet)")
    ap.add_argument("-q", "--quiet", action="store_true", help="console: warnings only")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("menu", help="interactive menu (the default)")
    sub.add_parser("scan", help="find all LIFX devices (UDP 56700 + ARP check)")
    sub.add_parser("known", help="list remembered devices and check which answer now")

    p = sub.add_parser("forget", help="remove remembered device(s) by MAC, IP or label")
    p.add_argument("targets", nargs="+")

    p = sub.add_parser("status", help="show power/label for targets (default all)")
    p.add_argument("targets", nargs="*")

    for name in ("on", "off"):
        p = sub.add_parser(name, help=f"turn targets {name} (default all)")
        p.add_argument("targets", nargs="*")
        p.add_argument("--fade", type=int, default=500, help="fade time in ms (default 500)")

    p = sub.add_parser("reboot", help="reboot targets and wait for them to return")
    p.add_argument("targets", nargs="+", help='IP, MAC, label, or "all"')
    p.add_argument("--wait", type=int, default=60, help="seconds to wait for return (default 60)")
    p.add_argument("--no-wait", action="store_true")
    p.add_argument("--then-on", action="store_true", help="turn each device on once it's back")

    p = sub.add_parser("firmware", help="firmware vs LIFX's latest, Wi-Fi signal, uptime")
    p.add_argument("targets", nargs="*")

    p = sub.add_parser("scenes", help="list scenes (LIFX app + local)")
    p.add_argument("--refresh", action="store_true", help="re-download scenes from your LIFX account")

    p = sub.add_parser("scene", help="activate a scene by number or name (prefix local:/cloud: if needed)")
    p.add_argument("name")
    p.add_argument("--duration", type=float, default=1.0, help="transition seconds (default 1)")
    p.add_argument("--local-only", action="store_true", help="don't use the LIFX cloud, apply over the LAN")

    p = sub.add_parser("scene-save", help="save the current look as a local scene (keeps strip zones)")
    p.add_argument("name")
    p.add_argument("targets", nargs="*", help="lights to include (default all)")

    p = sub.add_parser("scene-delete", help="delete a local scene")
    p.add_argument("name")

    p = sub.add_parser("token", help="set the LIFX cloud API token (for app scenes)")
    p.add_argument("value", nargs="?", help="token (omit to be prompted, input hidden)")

    p = sub.add_parser("diagnose", help="check for why lights drop off / hang / turn off, with fixes")

    p = sub.add_parser("guide", help="troubleshooting guide: symptoms, causes, router fixes, reset")
    p.add_argument("--no-pager", action="store_true")

    p = sub.add_parser("watch", help="log devices dropping off / coming back")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--misses", type=int, default=2, help="missed scans before DOWN (default 2)")

    _console_setup()
    args = ap.parse_args()
    args.cmd = args.cmd or "menu"
    args.logpath = LOGPATH = setup_logging(args)
    shown = sys.argv[1:]
    if args.cmd == "token" and getattr(args, "value", None):
        shown = [("<redacted>" if a == args.value else a) for a in shown]  # never log the token
    log.info("=== lifxctl " + " ".join(shown) + " ===", extra={"fileonly": True})
    if args.logpath and args.verbose:
        log.debug(f"logging to {args.logpath}")

    CACHE = Cache(os.path.expanduser(args.cache or DEFAULT_CACHE))
    atexit.register(CACHE.save)

    sock = make_socket()

    try:
        rc = {
            "menu": lambda: cmd_menu(sock, args),
            "scan": lambda: cmd_scan(sock, args),
            "known": lambda: cmd_known(sock, args),
            "forget": lambda: cmd_forget(sock, args),
            "status": lambda: cmd_status(sock, args),
            "on": lambda: cmd_power(sock, args, True),
            "off": lambda: cmd_power(sock, args, False),
            "reboot": lambda: cmd_reboot(sock, args),
            "watch": lambda: cmd_watch(sock, args),
            "firmware": lambda: cmd_firmware(sock, args),
            "diagnose": lambda: cmd_diagnose(sock, args),
            "guide": lambda: cmd_guide(sock, args),
            "scenes": lambda: cmd_scenes(sock, args),
            "scene": lambda: cmd_scene(sock, args),
            "scene-save": lambda: cmd_scene_save(sock, args),
            "scene-delete": lambda: cmd_scene_delete(sock, args),
            "token": lambda: cmd_token(sock, args),
        }[args.cmd]()
    except KeyboardInterrupt:
        print()
        rc = 130
    except Exception:
        log.exception("unexpected error")
        rc = 2
    CACHE.save()
    log.info(f"=== exit {rc or 0} ===", extra={"fileonly": True})
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
