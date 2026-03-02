import logging
from learner.alphabet import InputSymbol, OutputSymbol
from mapper.parameter_store import ParameterStore
from mapper.context_manager import ContextManager
from mapper.lifecycle import LifecycleManager
from mapper.mapper import Mapper

logger = logging.getLogger(__name__)

HAPPY_PATH = [
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
    InputSymbol.CASE_SEND_SIGMA1,
    InputSymbol.CASE_SEND_SIGMA3,
]

# Prefix sequences that bring the device to the right state for each probe
_PASE_PREFIX = HAPPY_PATH[:4]          # up to PASE_COMPLETE
_COMM_PREFIX = HAPPY_PATH[:11]         # up to COMM_ADD_NOC
_CSR_PREFIX  = HAPPY_PATH[:9]          # up to COMM_CSR_REQUEST (first CSR done)
_CASE_PREFIX = HAPPY_PATH[:14]         # full happy path, CASE established

PROBE_SCENARIOS = [
    {
        "name":     "PROBE_COMM_BEFORE_PASE",
        "symbol":   InputSymbol.PROBE_COMM_BEFORE_PASE,
        "prefix":   [],
        "expected": OutputSymbol.OUT_OF_ORDER_REJECTED,
        "desc":     "Commissioning command before PASE — must be rejected",
    },
    {
        "name":     "PROBE_NOC_WITHOUT_CSR",
        "symbol":   InputSymbol.PROBE_NOC_WITHOUT_CSR,
        "prefix":   _PASE_PREFIX,
        "expected": OutputSymbol.OUT_OF_ORDER_REJECTED,
        "desc":     "AddNOC without prior CSR — must be rejected",
    },
    {
        "name":     "PROBE_CSR_TWICE",
        "symbol":   InputSymbol.PROBE_CSR_TWICE,
        "prefix":   _CSR_PREFIX,
        "expected": OutputSymbol.OUT_OF_ORDER_REJECTED,
        "desc":     "Second CSR request after first succeeded — must be rejected",
    },
    {
        "name":     "PROBE_PASE_AFTER_COMMISSION",
        "symbol":   InputSymbol.PROBE_PASE_AFTER_COMMISSION,
        "prefix":   _CASE_PREFIX,
        "expected": OutputSymbol.OUT_OF_ORDER_REJECTED,
        "desc":     "PASE after full commissioning — must be rejected",
    },
]


class QueryExecutor:
    def __init__(self, lifecycle: LifecycleManager, store: ParameterStore):
        self.lifecycle = lifecycle
        self.store     = store

    def _fresh_mapper(self) -> tuple[Mapper, ContextManager]:
        ctx    = ContextManager()
        proc   = self.lifecycle.get_chiptool_proc()
        mapper = Mapper(self.store, proc, ctx)
        return mapper, ctx

    def run(self, symbols: list[InputSymbol]) -> list[OutputSymbol]:
        self.lifecycle.reset()
        self.store.reset()
        mapper, _ = self._fresh_mapper()

        outputs = []
        for symbol in symbols:
            output = mapper.execute(symbol)
            outputs.append(output)
            logger.debug("%-40s -> %s", symbol.name, output.name)
            if output in (OutputSymbol.TIMEOUT, OutputSymbol.SESSION_ERROR):
                remaining = len(symbols) - len(outputs)
                outputs.extend([OutputSymbol.SESSION_ERROR] * remaining)
                logger.warning("Query aborted at %s, filled %d remaining with SESSION_ERROR",
                               symbol.name, remaining)
                break

        return outputs

    def run_happy_path(self) -> list[OutputSymbol]:
        return self.run(HAPPY_PATH)

    def run_probe_tests(self) -> list[dict]:
        results = []
        for scenario in PROBE_SCENARIOS:
            logger.info("Running probe: %s", scenario["name"])

            # Reset device and run prefix to reach required state
            prefix_outputs = self.run(scenario["prefix"]) if scenario["prefix"] else []

            # Check prefix succeeded before sending probe
            prefix_ok = all(
                o not in (OutputSymbol.SESSION_ERROR, OutputSymbol.TIMEOUT,
                          OutputSymbol.INVALID_STATE, OutputSymbol.AUTH_FAILED)
                for o in prefix_outputs
            )

            if scenario["prefix"] and not prefix_ok:
                result = {
                    "name":     scenario["name"],
                    "desc":     scenario["desc"],
                    "output":   OutputSymbol.SESSION_ERROR,
                    "expected": scenario["expected"],
                    "passed":   False,
                    "note":     "Prefix failed — probe not reached",
                }
                results.append(result)
                logger.warning("Probe %s skipped: prefix failed", scenario["name"])
                continue

            # Send the probe symbol on the same mapper instance (same session)
            mapper = Mapper(self.store, self.lifecycle.get_chiptool_proc(),
                            ContextManager() if not scenario["prefix"] else _restore_ctx(scenario["prefix"], prefix_outputs))
            output = mapper.execute(scenario["symbol"])

            passed = (output == scenario["expected"])
            result = {
                "name":     scenario["name"],
                "desc":     scenario["desc"],
                "output":   output,
                "expected": scenario["expected"],
                "passed":   passed,
                "note":     "VULNERABILITY: device accepted out-of-order message" if (
                    output == OutputSymbol.UNEXPECTED_SUCCESS) else "",
            }
            results.append(result)
            logger.info("Probe %-35s -> %-30s %s",
                        scenario["name"], output.name, "PASS" if passed else "FAIL")

        return results


def _restore_ctx(symbols: list[InputSymbol], outputs: list[OutputSymbol]) -> ContextManager:
    ctx = ContextManager()
    for sym, out in zip(symbols, outputs):
        ctx.update(sym, out)
    return ctx