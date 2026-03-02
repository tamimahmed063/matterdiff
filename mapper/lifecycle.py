import subprocess
import time
import os
import signal
import socket
import logging

logger = logging.getLogger(__name__)

DEVICE_READY_TIMEOUT = 5
CHIPTOOL_READY_DELAY = 1
DEVICE_PORT          = 5540


class LifecycleManager:
    def __init__(self, device_bin: str, chip_tool_bin: str, device_ip: str = "::1"):
        self.device_bin    = device_bin
        self.chip_tool     = chip_tool_bin
        self.device_ip     = device_ip
        self.device_proc   = None
        self.chiptool_proc = None

    def start(self):
        self._start_device()
        self._start_chiptool()

    def reset(self):
        self._stop_chiptool()
        self._stop_device()
        self._clear_storage()
        self._start_device()
        self._start_chiptool()

    def get_chiptool_proc(self):
        return self.chiptool_proc

    def stop(self):
        self._stop_chiptool()
        self._stop_device()

    def _start_device(self):
        self._clear_storage()
        self.device_proc = subprocess.Popen(
            [self.device_bin],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        if not self._wait_for_device():
            raise RuntimeError("Device did not become ready in time.")
        logger.info("Device ready.")

    def _start_chiptool(self):
        self.chiptool_proc = subprocess.Popen(
            [self.chip_tool, "interactive", "start", "--trace_decode", "1"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            preexec_fn=os.setsid
        )
        time.sleep(CHIPTOOL_READY_DELAY)
        logger.info("chip-tool ready.")

    def _stop_device(self):
        if self.device_proc and self.device_proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.device_proc.pid), signal.SIGTERM)
                self.device_proc.wait(timeout=5)
            except Exception:
                pass
        self.device_proc = None

    def _stop_chiptool(self):
        if self.chiptool_proc and self.chiptool_proc.poll() is None:
            try:
                self.chiptool_proc.stdin.write("exit\n")
                self.chiptool_proc.stdin.flush()
                self.chiptool_proc.wait(timeout=5)
            except Exception:
                pass
            try:
                os.killpg(os.getpgid(self.chiptool_proc.pid), signal.SIGTERM)
            except Exception:
                pass
        self.chiptool_proc = None

    def _clear_storage(self):
        subprocess.run("rm -rf /tmp/chip_* /tmp/chip_tool_*", shell=True)
        subprocess.run("rm -f /tmp/chip_kvs /tmp/chip_tool_kvs", shell=True)
        subprocess.run("rm -f /tmp/final_*.bin /tmp/final_*.hex /tmp/final_certs.log", shell=True)
        subprocess.run("rm -f /tmp/device_csr.bin", shell=True)

    def _wait_for_device(self) -> bool:
        start = time.time()
        while time.time() - start < DEVICE_READY_TIMEOUT:
            if self._device_port_open():
                return True
            time.sleep(0.5)
        return False

    def _device_port_open(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.device_ip, DEVICE_PORT, 0, 0))
            sock.close()
            return result == 0
        except Exception:
            return False