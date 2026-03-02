import logging
from learner.alphabet import InputSymbol, OutputSymbol, SYMBOL_CONTEXT

logger = logging.getLogger(__name__)

ALLOWED_INPUTS = {
    "UNCOMMISSIONED": {
        InputSymbol.PASE_START,
        InputSymbol.PROBE_COMM_BEFORE_PASE,
        InputSymbol.PROBE_NOC_WITHOUT_CSR,
    },
    "PASE": {
        InputSymbol.PASE_PBKDF_REQUEST,
        InputSymbol.PASE_PAKE1,
        InputSymbol.PASE_PAKE3,
        InputSymbol.PROBE_PASE_AFTER_COMMISSION,
    },
    "COMMISSIONING": {
        InputSymbol.COMM_ARM_FAILSAFE,
        InputSymbol.COMM_ATTESTATION_REQUEST,
        InputSymbol.COMM_CERT_CHAIN_REQUEST_DAC,
        InputSymbol.COMM_CERT_CHAIN_REQUEST_PAI,
        InputSymbol.COMM_CSR_REQUEST,
        InputSymbol.COMM_ADD_TRUSTED_ROOT_CERT,
        InputSymbol.COMM_ADD_NOC,
        InputSymbol.PROBE_PASE_AFTER_COMMISSION,
        InputSymbol.PROBE_CSR_TWICE,
        InputSymbol.PROBE_NOC_WITHOUT_CSR,
    },
    "CASE": {
        InputSymbol.CASE_START_SESSION,
        InputSymbol.CASE_SEND_SIGMA1,
        InputSymbol.CASE_SEND_SIGMA3,
    },
    "PROBE": set(),
}

CONTEXT_ADVANCE_OUTPUTS = {
    OutputSymbol.PASE_SESSION_STARTED: "PASE",
    OutputSymbol.PASE_COMPLETE:        "COMMISSIONING",
    OutputSymbol.CASE_SESSION_STARTED: "CASE",
}


class ContextManager:
    def __init__(self):
        self.current = "UNCOMMISSIONED"
        self.history = []

    def reset(self):
        self.current = "UNCOMMISSIONED"
        self.history = []

    def is_allowed(self, symbol: InputSymbol) -> bool:
        symbol_ctx = SYMBOL_CONTEXT.get(symbol)
        if symbol_ctx == "PROBE":
            return True
        return symbol in ALLOWED_INPUTS.get(self.current, set())

    def update(self, symbol: InputSymbol, output: OutputSymbol):
        self.history.append((self.current, symbol, output))
        new_ctx = CONTEXT_ADVANCE_OUTPUTS.get(output)
        if new_ctx and new_ctx != self.current:
            logger.info("Context: %s -> %s", self.current, new_ctx)
            self.current = new_ctx

    def get_current(self) -> str:
        return self.current

    def get_allowed_symbols(self) -> set:
        return ALLOWED_INPUTS.get(self.current, set())