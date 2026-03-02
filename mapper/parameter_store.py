import os
import shutil
import subprocess
import logging

log = logging.getLogger(__name__)

ATTESTATION_NONCE = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
CSR_NONCE         = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
IPK_HEX           = "74656d706f726172792069706b203031"

NOC_BIN   = "/tmp/final_noc.bin"
ICAC_BIN  = "/tmp/final_icac.bin"
RCAC_BIN  = "/tmp/final_rcac.bin"
NOC_HEX   = "/tmp/final_noc.hex"
ICAC_HEX  = "/tmp/final_icac.hex"
RCAC_HEX  = "/tmp/final_rcac.hex"
CSR_BIN   = "/tmp/device_csr.bin"
CERTS_LOG = "/tmp/final_certs.log"


class ParameterStore:
    def __init__(self, node_id: int, pin: int, ip: str, port: int,
                 chip_tool_path: str, fabric_id: int = 1, vendor_id: int = 65521):
        self.node_id   = node_id
        self.pin       = pin
        self.ip        = ip
        self.port      = port
        self.chip_tool = chip_tool_path
        self.fabric_id = fabric_id
        self.vendor_id = vendor_id
        self.noc_hex   = None
        self.icac_hex  = None
        self.rcac_hex  = None
        self.csr_done  = False

    def reset(self):
        self.noc_hex  = None
        self.icac_hex = None
        self.rcac_hex = None
        self.csr_done = False
        for f in [NOC_BIN, ICAC_BIN, RCAC_BIN, NOC_HEX, ICAC_HEX, RCAC_HEX, CSR_BIN, CERTS_LOG]:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

    def generate_certs(self) -> bool:
        if not os.path.exists(CSR_BIN):
            log.warning("generate_certs: CSR_BIN not found at %s", CSR_BIN)
            return False

        csr_hex = subprocess.check_output(
            f"xxd -p {CSR_BIN} | tr -d '\\n'", shell=True
        ).decode().strip()

        # No --storage-directory: writes to default /tmp/chip_tool_kvs,
        # same store the interactive chip-tool session uses.
        result = subprocess.run(
            [self.chip_tool, "pairing", "issue-noc-chain",
             f"hex:{csr_hex}", str(self.node_id)],
            capture_output=True, text=True
        )

        combined = result.stdout + result.stderr
        with open(CERTS_LOG, "w") as f:
            f.write(combined)

        if result.returncode != 0:
            log.warning("issue-noc-chain failed (rc=%d): %s", result.returncode, combined[-500:])
            return False

        def extract(tag, bin_out, hex_out):
            line = next(
                (l for l in combined.splitlines() if f"{tag}: base64:" in l), None
            )
            if not line:
                log.warning("extract: tag '%s' not found in output", tag)
                return None
            b64 = line.split(f"{tag}: base64:")[1].strip()
            raw = subprocess.run(["base64", "-d"], input=b64.encode(), capture_output=True).stdout
            with open(bin_out, "wb") as fh:
                fh.write(raw)
            h = subprocess.check_output(
                f"xxd -p {bin_out} | tr -d '\\n'", shell=True
            ).decode().strip()
            with open(hex_out, "w") as fh:
                fh.write(h)
            return h

        self.noc_hex  = extract("NOC",  NOC_BIN,  NOC_HEX)
        self.icac_hex = extract("ICAC", ICAC_BIN, ICAC_HEX)
        self.rcac_hex = extract("RCAC", RCAC_BIN, RCAC_HEX)

        ok = all([self.noc_hex, self.icac_hex, self.rcac_hex])
        if ok:
            log.info("generate_certs: NOC/ICAC/RCAC extracted successfully")
        else:
            log.warning("generate_certs: one or more certs missing")
        return ok