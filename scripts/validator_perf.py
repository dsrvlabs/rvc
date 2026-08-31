#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Estimate consensus-layer performance of a validator set from the Beacon API."""

import argparse
import base64
import re
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TextIO
from urllib.parse import unquote, urlsplit

# ===== § 1. Header, constants, exit codes =====

SCHEMA_VERSION = 1
SECONDS_PER_JULIAN_YEAR = 31_557_600
DEFAULT_EPOCHS = 32
DEFAULT_CONCURRENCY = 4
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RETRY_AFTER = 30.0
GET_ID_CHUNK = 64
BALANCE_TOLERANCE_GWEI = 50_000_000
EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
EXIT_DEGRADED, EXIT_THRESHOLD, EXIT_NO_BEACON = 3, 4, 5

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class NoBeaconAvailable(Exception):
    pass


class BeaconStatus(Exception):
    def __init__(self, status: int, template: str, endpoint_label: str) -> None:
        super().__init__(status, template, endpoint_label)
        self.status = status
        self.template = template
        self.endpoint_label = endpoint_label


class BeaconTransport(Exception):
    pass


class Log:
    def __init__(self, verbosity: int, stream: TextIO) -> None:
        self._verbosity = verbosity
        self._stream = stream

    def error(self, msg: str, *a: object) -> None:
        self._emit(msg, a)

    def warn(self, msg: str, *a: object) -> None:
        if self._verbosity >= 0:
            self._emit(msg, a)

    def info(self, msg: str, *a: object) -> None:
        if self._verbosity >= 1:
            self._emit(msg, a)

    def _emit(self, msg: str, a: tuple[object, ...]) -> None:
        print(msg % a if a else msg, file=self._stream)


# ===== § 3. Parsing and redaction primitives =====

_UINT = re.compile(r"[0-9]+")
_INT = re.compile(r"-?[0-9]+")


def _parse_num(pattern: re.Pattern[str], raw: object, field: str) -> int:
    if not isinstance(raw, str) or pattern.fullmatch(raw) is None:
        raise UsageError(f"invalid {field}: {raw!r}")
    return int(raw)


def parse_uint(raw: object, field: str) -> int:
    return _parse_num(_UINT, raw, field)


def parse_int(raw: object, field: str) -> int:
    return _parse_num(_INT, raw, field)


def opt_int(raw: object, field: str) -> int | None:
    if isinstance(raw, dict):
        if field not in raw:
            return None
        raw = raw[field]
    return parse_int(raw, field)


def normalize_pubkey(raw: str, origin: str) -> str:
    text = raw.lower() if isinstance(raw, str) else ""
    if text.startswith("0x"):
        text = text[2:]
    if re.fullmatch(r"[0-9a-f]{96}", text) is None:
        raise UsageError(f"{origin}: pubkey must be 48-byte hex")
    return "0x" + text


def parse_endpoint(url: str, label: str) -> "Endpoint":
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise UsageError(f"invalid URL: {url!r}") from exc
    if parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    if ":" in host:
        host = f"[{host}]"
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    base_path = parsed.path.rstrip("/")
    auth_header = None
    if parsed.username is not None or parsed.password is not None:
        user = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        auth_header = f"Basic {token}"
    return Endpoint(
        label=label,
        scheme=parsed.scheme,
        host=host,
        port=port,
        base_path=base_path,
        auth_header=auth_header,
    )


def redact(ep: "Endpoint") -> str:
    return f"{ep.scheme}://{ep.host}:{ep.port}"


# ===== § 4. CLI and configuration =====


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Estimate consensus-layer performance of a validator set from the Beacon API.",
    )
    p.add_argument("--pubkey", action="append")
    p.add_argument("--pubkeys-file")
    p.add_argument("--validators-config")
    p.add_argument("--beacon-url", action="append")
    p.add_argument("--config")
    p.add_argument("--epochs", type=int)
    p.add_argument("--from-epoch", type=int)
    p.add_argument("--to-epoch", type=int)
    p.add_argument("--allow-unfinalized", action="store_true")
    p.add_argument("--force-unsafe-window", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--csv")
    p.add_argument("--concurrency", type=int)
    p.add_argument("--request-delay-ms", type=int)
    p.add_argument("--connect-timeout", type=float)
    p.add_argument("--read-timeout", type=float)
    p.add_argument("--degraded-ok", action="store_true")
    p.add_argument("--fail-under", action="append")
    p.add_argument("--liveness-check", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("-v", action="count", default=0, dest="verbose")
    p.add_argument("-q", action="store_true", dest="quiet")
    return p


def _read_source(
    out: list[str],
    seen: set[str],
    items: list[tuple[str, object]],
) -> None:
    for origin, raw in items:
        key = normalize_pubkey(raw if isinstance(raw, str) else "", origin)
        if key not in seen:
            seen.add(key)
            out.append(key)


def _pubkeys_from_file(path: str) -> list[tuple[str, object]]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise UsageError(f"{path}: {e}") from e
    items: list[tuple[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        items.append((f"{path}:{lineno}", text))
    return items


def _pubkeys_from_validators_config(path: str) -> list[tuple[str, object]]:
    try:
        # tomllib.load requires a binary handle; text mode raises TypeError.
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as e:
        raise UsageError(f"{path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise UsageError(f"{path}: {e}") from e
    entries = data.get("validators", [])
    if not isinstance(entries, list):
        raise UsageError(f"{path}: [[validators]] must be an array")
    items: list[tuple[str, object]] = []
    for n, entry in enumerate(entries, start=1):
        origin = f"{path} [[validators]] #{n}"
        raw: object = entry.get("pubkey") if isinstance(entry, dict) else ""
        items.append((origin, raw if raw is not None else ""))
    return items


def load_pubkeys(args: argparse.Namespace) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    _read_source(
        out,
        seen,
        [(f"--pubkey #{n}", raw) for n, raw in enumerate(args.pubkey or [], start=1)],
    )
    if args.pubkeys_file:
        _read_source(out, seen, _pubkeys_from_file(args.pubkeys_file))
    if args.validators_config:
        _read_source(out, seen, _pubkeys_from_validators_config(args.validators_config))
    if not out:
        raise UsageError(
            "no pubkeys: supply --pubkey, --pubkeys-file, or --validators-config"
        )
    return out


# ===== § 5. Transport =====


@dataclass(frozen=True)
class Endpoint:
    label: str
    scheme: str
    host: str
    port: int
    base_path: str = field(repr=False)
    auth_header: str | None = field(repr=False)


@dataclass(frozen=True)
class RawResponse:
    status: int
    body: bytes
    truncated: bool


Transport = Callable[[Endpoint, str, str, bytes | None], RawResponse]

# ===== § 6. BeaconClient =====

# ===== § 7. Chain context and bootstrap =====

# ===== § 8. Window resolution =====

# ===== § 9. Validator resolution =====

# ===== § 10. Attestation metrics — M1–M6 =====

# ===== § 11. Proposals — M7 and M9's proposer component =====

# ===== § 12. Sync committee — M8 =====

# ===== § 13. Balances and effective balance =====

# ===== § 14. Aggregation, APR, thresholds =====

# ===== § 15. Reporting =====

# ===== § 16. main =====


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
