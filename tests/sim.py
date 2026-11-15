"""Start the simulator and talk to it like a USB HID host would.

    cargo build -p vomit-sim
    python3 -m unittest discover -s tests -v
"""

import os
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = 64


class Sim:
    """One simulated device. Every instance starts empty: no PIN, no vault."""

    def __init__(self, *args):
        binary = os.environ.get("VOMIT_SIM") or os.path.join(ROOT, "target", "debug", "vomit-sim")
        if not os.path.exists(binary):
            raise RuntimeError(f"{binary} not found: run `cargo build -p vomit-sim` first")
        self.dir = tempfile.mkdtemp(prefix="vomit-sim-")
        self.path = os.path.join(self.dir, "usb.sock")
        self.proc = subprocess.Popen([binary, "--socket", self.path, *args])
        deadline = time.time() + 10
        while not os.path.exists(self.path):
            if self.proc.poll() is not None or time.time() > deadline:
                raise RuntimeError("the simulator did not start")
            time.sleep(0.01)

    def connect(self) -> socket.socket:
        """Open the device. Like a hidraw file: write and read 64-byte reports."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.path)
        return s

    def close(self):
        self.proc.kill()
        self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def read_packet(sock: socket.socket, timeout: float | None = None) -> bytes:
    """One 64-byte report from the device. Raises TimeoutError if none comes."""
    sock.settimeout(timeout)
    data = b""
    while len(data) < PACKET:
        chunk = sock.recv(PACKET - len(data))
        if not chunk:
            raise ConnectionError("the simulator went away")
        data += chunk
    return data
