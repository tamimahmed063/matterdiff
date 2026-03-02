from enum import Enum, auto


class InputSymbol(Enum):
    # PASE
    PASE_START          = auto()
    PASE_PBKDF_REQUEST  = auto()
    PASE_PAKE1          = auto()
    PASE_PAKE3          = auto()

    # Commissioning (over PASE session)
    COMM_ARM_FAILSAFE               = auto()
    COMM_ATTESTATION_REQUEST        = auto()
    COMM_CERT_CHAIN_REQUEST_DAC     = auto()
    COMM_CERT_CHAIN_REQUEST_PAI     = auto()
    COMM_CSR_REQUEST                = auto()
    COMM_ADD_TRUSTED_ROOT_CERT      = auto()
    COMM_ADD_NOC                    = auto()

    # CASE
    CASE_START_SESSION  = auto()
    CASE_SEND_SIGMA1    = auto()
    CASE_SEND_SIGMA3    = auto()

    # Out-of-order / security probes
    PROBE_PASE_AFTER_COMMISSION     = auto()
    PROBE_COMM_BEFORE_PASE          = auto()
    PROBE_NOC_WITHOUT_CSR           = auto()
    PROBE_CSR_TWICE                 = auto()


class OutputSymbol(Enum):
    # PASE
    PASE_SESSION_STARTED    = auto()
    PASE_PBKDF_SENT         = auto()
    PASE_PAKE1_SENT         = auto()
    PASE_COMPLETE           = auto()

    # Commissioning
    COMM_FAILSAFE_ARMED         = auto()
    COMM_ATTESTATION_SENT       = auto()
    COMM_CERT_DAC_RECEIVED      = auto()
    COMM_CERT_PAI_RECEIVED      = auto()
    COMM_CSR_RECEIVED           = auto()
    COMM_ROOT_CERT_INSTALLED    = auto()
    COMM_NOC_INSTALLED          = auto()

    # CASE
    CASE_SESSION_STARTED    = auto()
    CASE_SIGMA1_SENT        = auto()
    CASE_ESTABLISHED        = auto()

    # Errors
    AUTH_FAILED             = auto()
    SESSION_ERROR           = auto()
    OUT_OF_ORDER_REJECTED   = auto()
    INVALID_STATE           = auto()
    TIMEOUT                 = auto()
    UNEXPECTED_SUCCESS      = auto()


SYMBOL_CONTEXT = {
    InputSymbol.PASE_START:                     "UNCOMMISSIONED",
    InputSymbol.PASE_PBKDF_REQUEST:             "PASE",
    InputSymbol.PASE_PAKE1:                     "PASE",
    InputSymbol.PASE_PAKE3:                     "PASE",

    InputSymbol.COMM_ARM_FAILSAFE:              "COMMISSIONING",
    InputSymbol.COMM_ATTESTATION_REQUEST:       "COMMISSIONING",
    InputSymbol.COMM_CERT_CHAIN_REQUEST_DAC:    "COMMISSIONING",
    InputSymbol.COMM_CERT_CHAIN_REQUEST_PAI:    "COMMISSIONING",
    InputSymbol.COMM_CSR_REQUEST:               "COMMISSIONING",
    InputSymbol.COMM_ADD_TRUSTED_ROOT_CERT:     "COMMISSIONING",
    InputSymbol.COMM_ADD_NOC:                   "COMMISSIONING",

    InputSymbol.CASE_START_SESSION:             "CASE",
    InputSymbol.CASE_SEND_SIGMA1:               "CASE",
    InputSymbol.CASE_SEND_SIGMA3:               "CASE",

    InputSymbol.PROBE_PASE_AFTER_COMMISSION:    "PROBE",
    InputSymbol.PROBE_COMM_BEFORE_PASE:         "PROBE",
    InputSymbol.PROBE_NOC_WITHOUT_CSR:          "PROBE",
    InputSymbol.PROBE_CSR_TWICE:                "PROBE",
}

EXPECTED_HAPPY_PATH = {
    InputSymbol.PASE_START:                     OutputSymbol.PASE_SESSION_STARTED,
    InputSymbol.PASE_PBKDF_REQUEST:             OutputSymbol.PASE_PBKDF_SENT,
    InputSymbol.PASE_PAKE1:                     OutputSymbol.PASE_PAKE1_SENT,
    InputSymbol.PASE_PAKE3:                     OutputSymbol.PASE_COMPLETE,

    InputSymbol.COMM_ARM_FAILSAFE:              OutputSymbol.COMM_FAILSAFE_ARMED,
    InputSymbol.COMM_ATTESTATION_REQUEST:       OutputSymbol.COMM_ATTESTATION_SENT,
    InputSymbol.COMM_CERT_CHAIN_REQUEST_DAC:    OutputSymbol.COMM_CERT_DAC_RECEIVED,
    InputSymbol.COMM_CERT_CHAIN_REQUEST_PAI:    OutputSymbol.COMM_CERT_PAI_RECEIVED,
    InputSymbol.COMM_CSR_REQUEST:               OutputSymbol.COMM_CSR_RECEIVED,
    InputSymbol.COMM_ADD_TRUSTED_ROOT_CERT:     OutputSymbol.COMM_ROOT_CERT_INSTALLED,
    InputSymbol.COMM_ADD_NOC:                   OutputSymbol.COMM_NOC_INSTALLED,

    InputSymbol.CASE_START_SESSION:             OutputSymbol.CASE_SESSION_STARTED,
    InputSymbol.CASE_SEND_SIGMA1:               OutputSymbol.CASE_SIGMA1_SENT,
    InputSymbol.CASE_SEND_SIGMA3:               OutputSymbol.CASE_ESTABLISHED,
}

PROBE_SYMBOLS = {
    InputSymbol.PROBE_PASE_AFTER_COMMISSION,
    InputSymbol.PROBE_COMM_BEFORE_PASE,
    InputSymbol.PROBE_NOC_WITHOUT_CSR,
    InputSymbol.PROBE_CSR_TWICE,
}

SUCCESS_OUTPUTS = {
    OutputSymbol.PASE_SESSION_STARTED,
    OutputSymbol.PASE_PBKDF_SENT,
    OutputSymbol.PASE_PAKE1_SENT,
    OutputSymbol.PASE_COMPLETE,
    OutputSymbol.COMM_FAILSAFE_ARMED,
    OutputSymbol.COMM_ATTESTATION_SENT,
    OutputSymbol.COMM_CERT_DAC_RECEIVED,
    OutputSymbol.COMM_CERT_PAI_RECEIVED,
    OutputSymbol.COMM_CSR_RECEIVED,
    OutputSymbol.COMM_ROOT_CERT_INSTALLED,
    OutputSymbol.COMM_NOC_INSTALLED,
    OutputSymbol.CASE_SESSION_STARTED,
    OutputSymbol.CASE_SIGMA1_SENT,
    OutputSymbol.CASE_ESTABLISHED,
}