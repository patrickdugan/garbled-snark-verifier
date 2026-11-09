"""Strict public-output equality checks for experimental Shinigami receipts.

These functions do not verify a STARK, Bitcoin spendability, or an application
state transition. Callers must keep that distinction in every output.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

CAIRO_P = 2**251 + 17 * 2**192 + 1
MAX_MONEY = 2_100_000_000_000_000
DOMAIN = int.from_bytes(b"SHINIGAMI_BITVM3_V1", "big")
FLAGS = 0x518
CSV_SCRIPT = bytes.fromhex("5ab27551")
HASHLOCK_PREFIX = bytes.fromhex("a820")
HASHLOCK_SUFFIX = bytes.fromhex("87")
PRODUCER_REVISION = "7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c"
COMPILED_EXECUTABLE_SHA256 = "a9bdc409d2f7ee443ac62cabdc8df27fb44c85a435ca9350788bee890f61bef3"


def _int(value: int, maximum: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"noncanonical {name}")


def byte_array_words(data: bytes) -> list[int]:
    """Cairo ByteArray Serde: count, full 31-byte felts, pending, length."""
    if type(data) is not bytes:
        raise TypeError("ByteArray must be bytes")
    count, tail = divmod(len(data), 31)
    return ([count]
            + [int.from_bytes(data[i*31:(i+1)*31], "big") for i in range(count)]
            + [int.from_bytes(data[31*count:], "big"), tail])


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


@dataclass(frozen=True)
class ExpectedRequest:
    application: int  # 1: limited Ark CSV pilot, 2: limited UTXORef hashlock pilot
    request_id: int
    raw_transaction: bytes
    prevout_amount: int
    prevout_script: bytes
    prevout_height: int
    network: int = 3

    def validate(self) -> None:
        _int(self.application, 2, "application")
        if self.application == 0:
            raise ValueError("unsupported application")
        _int(self.network, 255, "network")
        if self.network != 3:
            raise ValueError("regtest-only pilot")
        _int(self.request_id, 2**256 - 1, "request_id")
        _int(self.prevout_amount, MAX_MONEY, "prevout_amount")
        _int(self.prevout_height, 2**32-1, "prevout_height")
        if type(self.raw_transaction) is not bytes or len(self.raw_transaction) > 4096:
            raise ValueError("invalid transaction encoding or size")
        if type(self.prevout_script) is not bytes or len(self.prevout_script) > 1024:
            raise ValueError("invalid prevout script encoding or size")
        if self.application == 1 and self.prevout_script != CSV_SCRIPT:
            raise ValueError("Ark pilot requires pinned CSV script")
        if self.application == 2 and not (
            len(self.prevout_script) == 35
            and self.prevout_script.startswith(HASHLOCK_PREFIX)
            and self.prevout_script.endswith(HASHLOCK_SUFFIX)
        ):
            raise ValueError("UTXORef pilot requires one SHA256 hashlock")

    def cairo_words(self) -> list[int]:
        self.validate()
        return ([self.network, self.application,
                 self.request_id & ((1<<128)-1), self.request_id >> 128]
                + byte_array_words(self.raw_transaction)
                + [self.prevout_amount]
                + byte_array_words(self.prevout_script)
                + [self.prevout_height])


def expected_receipt(request: ExpectedRequest, *, accepted: bool = True,
                     error: int = 0) -> list[int]:
    """Exact Cairo Serde of the known outcome; error for rejecting cases must be observed."""
    if type(accepted) is not bool:
        raise TypeError("accepted must be bool")
    _int(error, CAIRO_P-1, "error")
    if accepted and error != 0:
        raise ValueError("successful execution must have zero error")
    digest = int.from_bytes(hash256(request.raw_transaction), "big")
    return ([DOMAIN, 1, 1, FLAGS] + request.cairo_words()
            + [int(accepted), error, digest & ((1<<128)-1), digest >> 128])


def audit_words(observed: list[int], expected: list[int]) -> dict:
    """Compare raw output against independent expectation; remains unauthenticated."""
    if type(observed) is not list or type(expected) is not list:
        raise ValueError("receipt must be a list")
    if not all(type(x) is int and 0 <= x < CAIRO_P for x in observed):
        raise ValueError("invalid Cairo output encoding")
    if observed != expected:
        raise ValueError("receipt differs from expected public statement")
    return {
        "public_output_matches_expected": True,
        "output_felts": len(observed),
        "expected_output_sha256": sha256(b"SHINIGAMI-S3-RAW-OUTPUT-V1\0" + b"".join(
            x.to_bytes(32, "little") for x in expected)).hexdigest(),
        "proof_verified": False,
        "program_binding_verified": False,
        "chain_spendability_verified": False,
        "application_state_verified": False,
    }
