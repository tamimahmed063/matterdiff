import socket
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from learner.alphabet       import InputSymbol, OutputSymbol
from mapper.lifecycle       import LifecycleManager
from mapper.parameter_store import ParameterStore
from mapper.context_manager import ContextManager
from mapper.mapper          import Mapper

logging.getLogger("mapper.lifecycle").setLevel(logging.WARNING)
logging.getLogger("mapper.context_manager").setLevel(logging.WARNING)
logging.getLogger("mapper.mapper").setLevel(logging.WARNING)
logging.getLogger("mapper.parameter_store").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

HOST = "127.0.0.1"
PORT = 7777

PHASE_PREFIXES = {
    "PASE": [
        InputSymbol.PASE_START,
    ],
    "COMMISSIONING": [
        InputSymbol.PASE_START,
        InputSymbol.PASE_PBKDF_REQUEST,
        InputSymbol.PASE_PAKE1,
        InputSymbol.PASE_PAKE3,
    ],
    "CASE": [
        InputSymbol.PASE_START,
        InputSymbol.PASE_PBKDF_REQUEST,
        InputSymbol.PASE_PAKE1,
        InputSymbol.PASE_PAKE3,
        InputSymbol.COMM_ARM_FAILSAFE,
        InputSymbol.COMM_ATTESTATION_REQUEST,
        InputSymbol.COMM_CERT_CHAIN_REQUEST_DAC,
        InputSymbol.COMM_CERT_CHAIN_REQUEST_PAI,
        InputSymbol.COMM_CSR_REQUEST,
        InputSymbol.COMM_ADD_TRUSTED_ROOT_CERT,
        InputSymbol.COMM_ADD_NOC,
        InputSymbol.CASE_START_SESSION,
    ],
}

ERROR_OUTPUTS = {
    OutputSymbol.SESSION_ERROR,
    OutputSymbol.AUTH_FAILED,
    OutputSymbol.TIMEOUT,
    OutputSymbol.INVALID_STATE,
}


class SULServer:
    def __init__(self, lifecycle: LifecycleManager, store: ParameterStore, phase: str = "COMMISSIONING"):
        self.lifecycle      = lifecycle
        self.store          = store
        self.phase          = phase.upper()
        self.prefix         = PHASE_PREFIXES.get(self.phase, [])
        self.mapper         = None
        self.ctx            = None
        self._query_count   = 0
        self._step_count    = 0
        self._query_type    = "MQ"
        self._prefix_failed = False

    def _reset(self, query_type: str = "MQ"):
        self._prefix_failed = False
        self._query_count += 1
        self._step_count  = 0
        self._query_type  = query_type

        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            self.lifecycle.reset()
            self.store.reset()
            self.ctx    = ContextManager()
            self.mapper = Mapper(self.store, self.lifecycle.get_chiptool_proc(), self.ctx)

            logger.info("[%s #%04d] RESET attempt %d/%d  prefix=%d steps",
                        self._query_type, self._query_count, attempt, max_attempts, len(self.prefix))

            success = True
            for sym in self.prefix:
                out = self.mapper.execute(sym)
                if out in ERROR_OUTPUTS:
                    logger.warning("[%s #%04d] PREFIX FAILED at %s -> %s  (attempt %d — restarting device)",
                                   self._query_type, self._query_count, sym.name, out.name, attempt)
                    success = False
                    break

            if success:
                logger.info("[%s #%04d] PREFIX OK (attempt %d)", self._query_type, self._query_count, attempt)
                return

        logger.error("[%s #%04d] PREFIX FAILED after %d attempts — poisoning steps",
                     self._query_type, self._query_count, max_attempts)
        self._prefix_failed = True

    def _step(self, symbol_name: str) -> str:
        if self._prefix_failed:
            logger.warning("[%s #%04d] step %02d  %-38s -> SESSION_ERROR (prefix failed)",
                           self._query_type, self._query_count,
                           self._step_count + 1, symbol_name)
            self._step_count += 1
            return OutputSymbol.SESSION_ERROR.name

        try:
            symbol = InputSymbol[symbol_name]
        except KeyError:
            logger.warning("Unknown symbol: %s", symbol_name)
            return OutputSymbol.SESSION_ERROR.name

        output = self.mapper.execute(symbol)
        self._step_count += 1
        logger.info("[%s #%04d] step %02d  %-38s -> %s",
                    self._query_type, self._query_count,
                    self._step_count, symbol_name, output.name)
        return output.name

    def handle(self, conn: socket.socket):
        f = conn.makefile("rw", buffering=1)
        try:
            for line in f:
                msg = line.strip()
                if not msg:
                    continue
                if msg.startswith("RESET"):
                    qtype = msg.split(":")[1] if ":" in msg else "MQ"
                    self._reset(qtype)
                    f.write("OK\n")
                    f.flush()
                elif msg == "DONE":
                    f.write("OK\n")
                    f.flush()
                elif msg.startswith("STEP:"):
                    symbol_name = msg[5:]
                    result = self._step(symbol_name)
                    f.write(result + "\n")
                    f.flush()
                else:
                    f.write("ERROR\n")
                    f.flush()
        except Exception:
            logger.exception("Error handling connection")
        finally:
            conn.close()

    def serve(self):
        self.lifecycle.start()
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        logger.info("SUL server listening on %s:%d  [phase=%s]", HOST, PORT, self.phase)
        try:
            while True:
                conn, addr = srv.accept()
                logger.info("Learner connected from %s", str(addr))
                self.handle(conn)
        except KeyboardInterrupt:
            logger.info("Server shutting down")
        finally:
            self.lifecycle.stop()
            srv.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(message)s",
    )

    DEVICE_BIN = os.environ.get(
        "DEVICE_BIN",
        os.path.expanduser("~/connectedhomeip/out/linux-x64-all-clusters-app/chip-all-clusters-app"),
    )
    CHIP_TOOL = os.environ.get(
        "CHIP_TOOL",
        os.path.expanduser("~/connectedhomeip/out/linux-x64-chip-tool/chip-tool"),
    )
    PHASE = os.environ.get("PHASE", "COMMISSIONING")

    store = ParameterStore(
        node_id=1, pin=20202021, ip="::1", port=5540,
        chip_tool_path=CHIP_TOOL,
    )
    lifecycle = LifecycleManager(
        device_bin=DEVICE_BIN, chip_tool_bin=CHIP_TOOL, device_ip="::1",
    )

    SULServer(lifecycle, store, phase=PHASE).serve()


if __name__ == "__main__":
    main()