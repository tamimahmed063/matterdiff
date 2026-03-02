import os
import time
import re
import threading
from learner.alphabet import InputSymbol, OutputSymbol
from mapper.parameter_store import ParameterStore, ATTESTATION_NONCE, CSR_NONCE, IPK_HEX, CSR_BIN
from mapper.context_manager import ContextManager

import logging
logger = logging.getLogger(__name__)

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[mJKHF]|\x1b\[[\d;]*[A-Za-z]|\x1b\[\?[\d;]*[hl]')

DEFAULT_WAIT  = 5
FAILSAFE_WAIT = 100


class Mapper:
    def __init__(self, store: ParameterStore, interactive_proc, context_manager: ContextManager):
        self.store   = store
        self.proc    = interactive_proc
        self.context = context_manager
        self._buf_lock = threading.Lock()
        self._buffer   = []
        self._reader   = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        for raw in self.proc.stdout:
            clean = ANSI_ESCAPE.sub('', raw).rstrip()
            if clean:
                with self._buf_lock:
                    self._buffer.append(clean)

    def _send(self, cmd: str, wait: float = DEFAULT_WAIT,
              wait_for: str = None, wait_for_timeout: float = 30) -> str:
        with self._buf_lock:
            self._buffer.clear()
        self.proc.stdin.write(cmd + "\n")
        self.proc.stdin.flush()
        if wait_for:
            deadline = time.time() + wait_for_timeout
            while time.time() < deadline:
                time.sleep(0.2)
                with self._buf_lock:
                    joined = "\n".join(self._buffer)
                if wait_for.lower() in joined.lower():
                    break
            with self._buf_lock:
                return "\n".join(self._buffer)
        time.sleep(wait)
        with self._buf_lock:
            return "\n".join(self._buffer)

    def _ok(self, output: str) -> bool:
        low = output.lower()
        has_error = any(k in low for k in [
            "chip error", "general error", "im error",
            "run command failure",
            "failed to send",
            "invalid argument",
        ])
        has_success = any(k in low for k in [
            "no session to clear",
            "session created and stored",
            "sent pbkdf param request",
            "received pbkdf param response",
            "not auto-sending msg1",
            "not auto-sending msg3",
            "pase session established",
            "session established successfully",
            "arm fail safe response",
            "armfailsaferesponse",
            "attestationresponse",
            "opcsr",
            "certificatechain",
            "csrresponse received",
            "addtrustedrootcertificate sent!",
            "addtrustedrootcertificate succeeded!",
            "addnoc sent!",
            "addnoc successful!",
            "sigma messages will not auto-send",
            "case session created and stored!",
            "sigma1 sent!",
            "sigma3 sent!",
            "case session established!",
            "secure operational session is now active",
        ])
        return has_success and not has_error

    def execute(self, symbol: InputSymbol) -> OutputSymbol:
        if not self.context.is_allowed(symbol):
            return OutputSymbol.INVALID_STATE
        handlers = {
            InputSymbol.PASE_START:                  self._pase_start,
            InputSymbol.PASE_PBKDF_REQUEST:          self._pase_pbkdf,
            InputSymbol.PASE_PAKE1:                  self._pase_pake1,
            InputSymbol.PASE_PAKE3:                  self._pase_pake3,
            InputSymbol.COMM_ARM_FAILSAFE:           self._comm_arm_failsafe,
            InputSymbol.COMM_ATTESTATION_REQUEST:    self._comm_attestation,
            InputSymbol.COMM_CERT_CHAIN_REQUEST_DAC: self._comm_cert_dac,
            InputSymbol.COMM_CERT_CHAIN_REQUEST_PAI: self._comm_cert_pai,
            InputSymbol.COMM_CSR_REQUEST:            self._comm_csr,
            InputSymbol.COMM_ADD_TRUSTED_ROOT_CERT:  self._comm_add_root,
            InputSymbol.COMM_ADD_NOC:                self._comm_add_noc,
            InputSymbol.CASE_START_SESSION:          self._case_start_session,
            InputSymbol.CASE_SEND_SIGMA1:            self._case_send_sigma1,
            InputSymbol.CASE_SEND_SIGMA3:            self._case_send_sigma3,
            InputSymbol.PROBE_PASE_AFTER_COMMISSION: self._probe_pase_after_commission,
            InputSymbol.PROBE_COMM_BEFORE_PASE:      self._probe_comm_before_pase,
            InputSymbol.PROBE_NOC_WITHOUT_CSR:       self._probe_noc_without_csr,
            InputSymbol.PROBE_CSR_TWICE:             self._probe_csr_twice,
        }
        try:
            output = handlers[symbol]()
        except Exception:
            logger.exception("exception in handler for %s", symbol)
            output = OutputSymbol.SESSION_ERROR
        self.context.update(symbol, output)
        return output

    def _pase_start(self) -> OutputSymbol:
        s = self.store
        self._send(f"pase clear-session {s.node_id} {s.pin} {s.ip} {s.port}", wait=3)
        out = self._send(f"pase start-session {s.node_id} {s.pin} {s.ip} {s.port}", wait=5)
        if self._ok(out):
            return OutputSymbol.PASE_SESSION_STARTED
        return OutputSymbol.AUTH_FAILED

    def _pase_pbkdf(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase use-pbkdf-request {s.node_id} {s.pin} {s.ip} {s.port}",
            wait_for="not auto-sending msg1",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.PASE_PBKDF_SENT
        return OutputSymbol.SESSION_ERROR

    def _pase_pake1(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase use-pake1 {s.node_id} {s.pin} {s.ip} {s.port}",
            wait_for="not auto-sending msg3",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.PASE_PAKE1_SENT
        return OutputSymbol.SESSION_ERROR

    def _pase_pake3(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase use-pake3 {s.node_id} {s.pin} {s.ip} {s.port}",
            wait_for="pase session established",
            wait_for_timeout=30
        )
        low = out.lower()
        if "pase session established" in low or "session established successfully" in low:
            return OutputSymbol.PASE_COMPLETE
        return OutputSymbol.SESSION_ERROR

    def _comm_arm_failsafe(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-arm-failsafe {s.node_id} {s.pin} {s.ip} {s.port} 900 0",
            wait=FAILSAFE_WAIT
        )
        if self._ok(out):
            return OutputSymbol.COMM_FAILSAFE_ARMED
        return OutputSymbol.SESSION_ERROR

    def _comm_attestation(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-attestation-request {s.node_id} {s.pin} {s.ip} {s.port} hex:{ATTESTATION_NONCE}",
            wait=10
        )
        if self._ok(out):
            return OutputSymbol.COMM_ATTESTATION_SENT
        return OutputSymbol.SESSION_ERROR

    def _comm_cert_dac(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-certificate-chain-request {s.node_id} {s.pin} {s.ip} {s.port} 1",
            wait=10
        )
        if self._ok(out):
            return OutputSymbol.COMM_CERT_DAC_RECEIVED
        return OutputSymbol.SESSION_ERROR

    def _comm_cert_pai(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-certificate-chain-request {s.node_id} {s.pin} {s.ip} {s.port} 2",
            wait=10
        )
        if self._ok(out):
            return OutputSymbol.COMM_CERT_PAI_RECEIVED
        return OutputSymbol.SESSION_ERROR

    def _comm_csr(self) -> OutputSymbol:
        s = self.store
        if os.path.exists(CSR_BIN):
            os.remove(CSR_BIN)
        self._send(
            f"pase send-csr-request {s.node_id} {s.pin} {s.ip} {s.port} hex:{CSR_NONCE}",
            wait=2
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            if os.path.exists(CSR_BIN) and os.path.getsize(CSR_BIN) > 0:
                break
            time.sleep(0.2)
        else:
            logger.warning("_comm_csr: timed out waiting for %s", CSR_BIN)
            return OutputSymbol.SESSION_ERROR
        if not self.store.generate_certs():
            return OutputSymbol.SESSION_ERROR
        self.store.csr_done = True
        return OutputSymbol.COMM_CSR_RECEIVED

    def _comm_add_root(self) -> OutputSymbol:
        if not self.store.rcac_hex:
            return OutputSymbol.INVALID_STATE
        s = self.store
        out = self._send(
            f"pase send-add-trusted-root-cert {s.node_id} {s.pin} {s.ip} {s.port} hex:{s.rcac_hex}",
            wait_for="addtrustedrootcertificate succeeded!",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.COMM_ROOT_CERT_INSTALLED
        return OutputSymbol.SESSION_ERROR

    def _comm_add_noc(self) -> OutputSymbol:
        if not self.store.noc_hex or not self.store.icac_hex:
            return OutputSymbol.INVALID_STATE
        s = self.store
        out = self._send(
            f"pase send-add-noc {s.node_id} {s.pin} {s.ip} {s.port} "
            f"hex:{s.noc_hex} hex:{IPK_HEX} {s.fabric_id} {s.vendor_id} "
            f"--icac-value hex:{s.icac_hex}",
            wait_for="addnoc successful!",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.COMM_NOC_INSTALLED
        return OutputSymbol.SESSION_ERROR

    def _case_start_session(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"case start-session {s.node_id} {s.ip} {s.port}",
            wait_for="\u2705 CASE session created and stored!",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.CASE_SESSION_STARTED
        return OutputSymbol.SESSION_ERROR

    def _case_send_sigma1(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"case send-sigma1 {s.node_id} {s.ip} {s.port}",
            wait_for="\u2705 Sigma1 sent!",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.CASE_SIGMA1_SENT
        return OutputSymbol.SESSION_ERROR

    def _case_send_sigma3(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"case send-sigma3 {s.node_id} {s.ip} {s.port}",
            wait_for="\u2713\u2713\u2713 CASE Session established!",
            wait_for_timeout=30
        )
        if self._ok(out):
            return OutputSymbol.CASE_ESTABLISHED
        return OutputSymbol.SESSION_ERROR

    def _probe_pase_after_commission(self) -> OutputSymbol:
        s = self.store
        out = self._send(f"pase start-session {s.node_id} {s.pin} {s.ip} {s.port}", wait=5)
        if self._ok(out):
            return OutputSymbol.UNEXPECTED_SUCCESS
        return OutputSymbol.OUT_OF_ORDER_REJECTED

    def _probe_comm_before_pase(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-arm-failsafe {s.node_id} {s.pin} {s.ip} {s.port} 900 0",
            wait=FAILSAFE_WAIT
        )
        if self._ok(out):
            return OutputSymbol.UNEXPECTED_SUCCESS
        return OutputSymbol.OUT_OF_ORDER_REJECTED

    def _probe_noc_without_csr(self) -> OutputSymbol:
        s = self.store
        dummy = "aa" * 100
        out = self._send(
            f"pase send-add-noc {s.node_id} {s.pin} {s.ip} {s.port} "
            f"hex:{dummy} hex:{IPK_HEX} {s.fabric_id} {s.vendor_id}",
            wait=10
        )
        if self._ok(out):
            return OutputSymbol.UNEXPECTED_SUCCESS
        return OutputSymbol.OUT_OF_ORDER_REJECTED

    def _probe_csr_twice(self) -> OutputSymbol:
        s = self.store
        out = self._send(
            f"pase send-csr-request {s.node_id} {s.pin} {s.ip} {s.port} hex:{CSR_NONCE}",
            wait=10
        )
        if self._ok(out):
            return OutputSymbol.UNEXPECTED_SUCCESS
        return OutputSymbol.OUT_OF_ORDER_REJECTED