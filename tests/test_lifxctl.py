"""Tests for lifxctl. Run from the repo root:  python -m unittest discover -s tests -v"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "lifxctl.py")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import lifxctl  # noqa: E402
from fakelight import FakeLight  # noqa: E402


class Protocol(unittest.TestCase):
    def test_frame_roundtrip(self):
        msg = lifxctl.frame(lifxctl.GET_SERVICE)
        self.assertEqual(len(msg), 36)
        src, mac, mtype, payload = lifxctl.parse(msg)
        self.assertEqual(src, lifxctl.SRC)
        self.assertEqual(mtype, lifxctl.GET_SERVICE)
        self.assertEqual(payload, b"")
        size, proto = struct.unpack_from("<HH", msg)
        self.assertEqual(size, 36)
        self.assertTrue(proto & 0x2000)  # tagged = all devices

    def test_targeted_frame_not_tagged(self):
        mac = bytes.fromhex("d073d5aabbcc")
        msg = lifxctl.frame(lifxctl.LIGHT_SET_POWER, mac, struct.pack("<HI", 65535, 0))
        self.assertEqual(msg[8:14], mac)
        self.assertFalse(struct.unpack_from("<H", msg, 2)[0] & 0x2000)
        self.assertEqual(len(msg), 42)


class ArpParsing(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(lifxctl.norm_mac("D0-73-D5-AA-BB-CC"), "d0:73:d5:aa:bb:cc")
        self.assertEqual(lifxctl.norm_mac("d0:73:d5:a:b:c"), "d0:73:d5:0a:0b:0c")  # macOS style
        self.assertIsNone(lifxctl.norm_mac("garbage"))

    def test_macos(self):
        text = ("? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n"
                "? (192.168.1.57) at d0:73:d5:a:bb:c on en0 ifscope [ethernet]\n"
                "? (192.168.1.60) at (incomplete) on en0 ifscope [ethernet]\n"
                "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n")
        t = lifxctl.parse_arp_output(text)
        self.assertEqual(t["192.168.1.57"], "d0:73:d5:0a:bb:0c")
        self.assertEqual(t["192.168.1.1"], "00:11:22:33:44:55")
        self.assertNotIn("192.168.1.60", t)
        self.assertNotIn("192.168.1.255", t)

    def test_windows(self):
        text = ("\nInterface: 192.168.1.20 --- 0x7\n"
                "  Internet Address      Physical Address      Type\n"
                "  192.168.1.1           00-11-22-33-44-55     dynamic\n"
                "  192.168.1.57          d0-73-d5-aa-bb-cc     dynamic\n"
                "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
                "  224.0.0.22            01-00-5e-00-00-16     static\n")
        t = lifxctl.parse_arp_output(text)
        self.assertEqual(t["192.168.1.57"], "d0:73:d5:aa:bb:cc")
        self.assertNotIn("192.168.1.20", t)  # the interface line has no MAC
        self.assertNotIn("192.168.1.255", t)

    def test_linux_proc(self):
        text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                "192.168.1.57     0x1         0x2         d0:73:d5:aa:bb:cc     *        wlp3s0\n"
                "192.168.1.60     0x1         0x0         00:00:00:00:00:00     *        wlp3s0\n")
        t = lifxctl.parse_proc_arp(text)
        self.assertEqual(t, {"192.168.1.57": "d0:73:d5:aa:bb:cc"})

    def test_arp_table_runs_on_this_os(self):
        self.assertIsInstance(lifxctl.arp_table(), dict)


class Paths(unittest.TestCase):
    def test_app_dirs(self):
        state, config = lifxctl._app_dirs()
        self.assertTrue(state.endswith("lifxctl"))
        self.assertTrue(config.endswith("lifxctl"))
        self.assertTrue(os.path.isabs(state))


class EndToEnd(unittest.TestCase):
    """Runs the real script against a simulated light on 127.0.0.1."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lifxctl-test-")
        self.env = dict(os.environ, HOME=self.tmp, USERPROFILE=self.tmp, LOCALAPPDATA=self.tmp,
                        APPDATA=self.tmp, XDG_STATE_HOME=self.tmp, XDG_CONFIG_HOME=self.tmp,
                        PYTHONIOENCODING="utf-8")
        self.cache = os.path.join(self.tmp, "devices.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        cmd = [sys.executable, SCRIPT, "--no-log", "--cache", self.cache] + list(args)
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env=self.env, timeout=120, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout + p.stderr

    def test_full_flow(self):
        with FakeLight() as light:
            rc, out = self.run_cli("--no-sweep", "status", "127.0.0.1")
            self.assertEqual(rc, 0, out)
            self.assertIn("Test Strip", out)
            self.assertIn("off", out)

            rc, out = self.run_cli("--no-sweep", "on", "127.0.0.1")
            self.assertEqual(rc, 0, out)
            self.assertEqual(light.power, 65535)

            # the light is remembered, so it can be addressed by name now
            rc, out = self.run_cli("--no-sweep", "off", "test strip")
            self.assertEqual(rc, 0, out)
            self.assertEqual(light.power, 0)

            rc, out = self.run_cli("--no-sweep", "known")
            self.assertIn("online", out)

            # local scene keeps all 90 strip zones (2 SetExtendedColorZones messages)
            self.run_cli("--no-sweep", "on", "test strip")
            rc, out = self.run_cli("--no-sweep", "scene-save", "grad", "test strip")
            self.assertEqual(rc, 0, out)
            self.assertIn("90 zones", out)
            saved = [z[:] for z in light.zones]
            light.zones = [[0, 0, 0, 3500] for _ in saved]
            rc, out = self.run_cli("--no-sweep", "scene", "local:grad", "--duration", "0")
            self.assertEqual(rc, 0, out)
            self.assertEqual(light.zones, saved)

            rc, out = self.run_cli("--no-sweep", "reboot", "test strip", "--no-wait")
            self.assertEqual(rc, 0, out)
            self.assertGreaterEqual(light.rebooted, 1)

    def test_sweep_survives_unanswered_hosts(self):
        # Sweeping addresses with nothing listening triggers ICMP "port unreachable";
        # on Windows that used to make recvfrom() raise WSAECONNRESET.
        with FakeLight():
            rc, out = self.run_cli("--subnet", "127.0.0.0/29", "scan")
            self.assertIn("Test Strip", out, out)

    def test_help_and_guide(self):
        rc, out = self.run_cli("--help")
        self.assertEqual(rc, 0, out)
        self.assertIn("diagnose", out)
        rc, out = self.run_cli("guide", "--no-pager")
        self.assertEqual(rc, 0, out)
        self.assertIn("TROUBLESHOOTING", out)


if __name__ == "__main__":
    unittest.main()
