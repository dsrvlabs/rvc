#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Estimate consensus-layer performance of a validator set from the Beacon API."""

import argparse
import base64
import http.client
import json
import math
import random
import re
import socket
import ssl
import sys
import threading
import time
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Literal, TextIO
from urllib.parse import unquote, urlencode, urlsplit

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


def _load_toml(path: str) -> dict:
    try:
        # tomllib.load requires a binary handle; text mode raises TypeError.
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except OSError as e:
        raise UsageError(f"{path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise UsageError(f"{path}: {e}") from e


def _as_url(raw: object, origin: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise UsageError(f"{origin}: invalid beacon URL: {raw!r}")
    return raw


def _urls_from_config(path: str) -> list[str]:
    data = _load_toml(path)
    origin = f"--config {path}"
    if "beacon_nodes" in data:
        nodes = data["beacon_nodes"]
        if not isinstance(nodes, list) or not all(
            isinstance(item, str) for item in nodes
        ):
            raise UsageError(
                f"{origin}: beacon_nodes must be an array of URL strings, got {nodes!r}"
            )
        if nodes:
            return list(nodes)
        # Empty beacon_nodes is a leftover, not "use nothing".
    if "beacon_url" in data:
        url = data["beacon_url"]
        if not isinstance(url, str):
            raise UsageError(f"{origin}: beacon_url must be a string, got {url!r}")
        if url:
            return [url]
    return []


def load_beacon_urls(args: argparse.Namespace) -> list["Endpoint"]:
    if args.beacon_url is not None:
        origin = "--beacon-url"
        raw = list(args.beacon_url)
    elif args.config:
        origin = f"--config {args.config}"
        raw = _urls_from_config(args.config)
    else:
        origin = "--beacon-url"
        raw = []
    if not raw:
        raise UsageError(
            "no beacon URL: supply --beacon-url or --config with beacon_nodes or beacon_url"
        )
    return [
        parse_endpoint(_as_url(url, origin), f"bn{i}") for i, url in enumerate(raw)
    ]


def _validate_combinations(args: argparse.Namespace) -> None:
    # Syntactic only; window bounds need chain data (§8).
    if args.quiet and args.verbose:
        raise UsageError("-v and -q are mutually exclusive")
    if args.epochs is not None and (
        args.from_epoch is not None or args.to_epoch is not None
    ):
        raise UsageError("--epochs cannot be combined with --from-epoch/--to-epoch")


def _verbosity(args: argparse.Namespace) -> int:
    return -1 if args.quiet else args.verbose


@dataclass(frozen=True)
class Options:
    pubkeys: tuple[str, ...]
    endpoints: tuple["Endpoint", ...]
    epochs: int | None
    from_epoch: int | None
    to_epoch: int | None
    allow_unfinalized: bool
    force_unsafe_window: bool
    verbosity: int
    connect_timeout: float
    read_timeout: float
    concurrency: int
    request_delay_ms: int
    dry_run: bool
    json: bool
    csv: str | None
    degraded_ok: bool
    fail_under: tuple[str, ...]
    liveness_check: bool
    no_cache: bool


def build_options(argv: list[str] | None = None) -> Options:
    args = build_parser().parse_args(argv)
    _validate_combinations(args)

    def pick(value, default):
        return default if value is None else value

    return Options(
        pubkeys=tuple(load_pubkeys(args)),
        endpoints=tuple(load_beacon_urls(args)),
        epochs=args.epochs,
        from_epoch=args.from_epoch,
        to_epoch=args.to_epoch,
        allow_unfinalized=args.allow_unfinalized,
        force_unsafe_window=args.force_unsafe_window,
        verbosity=_verbosity(args),
        connect_timeout=pick(args.connect_timeout, DEFAULT_CONNECT_TIMEOUT),
        read_timeout=pick(args.read_timeout, DEFAULT_READ_TIMEOUT),
        concurrency=pick(args.concurrency, DEFAULT_CONCURRENCY),
        request_delay_ms=pick(args.request_delay_ms, 0),
        dry_run=args.dry_run,
        json=args.json,
        csv=args.csv,
        degraded_ok=args.degraded_ok,
        fail_under=tuple(args.fail_under or []),
        liveness_check=args.liveness_check,
        no_cache=args.no_cache,
    )


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
    headers: dict[str, str] = field(default_factory=dict)  # Retry-After (VP-1h)


Transport = Callable[[Endpoint, str, str, bytes | None], RawResponse]


class HttpTransport:
    def __init__(self, connect_timeout: float, read_timeout: float) -> None:
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._local = threading.local()
        self._lock = threading.Lock()
        # close() must reach every thread's map; local storage is not shared.
        self._maps: list[dict[Endpoint, http.client.HTTPConnection]] = []

    def _map(self) -> dict[Endpoint, http.client.HTTPConnection]:
        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = {}
            self._local.conns = conns
            with self._lock:
                self._maps.append(conns)
        return conns

    def _conn_for(self, ep: Endpoint) -> http.client.HTTPConnection:
        conns = self._map()
        conn = conns.get(ep)
        if conn is not None and conn.sock is not None:
            return conn
        if conn is not None:
            conn.close()
        factory = (
            http.client.HTTPSConnection
            if ep.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = factory(ep.host, ep.port, timeout=self._connect_timeout)
        conn.connect()
        conn.sock.settimeout(self._read_timeout)
        conns[ep] = conn
        return conn

    def __call__(
        self, ep: Endpoint, method: str, path: str, body: bytes | None
    ) -> RawResponse:
        conn = self._conn_for(ep)
        headers: dict[str, str] = {}
        if ep.auth_header:
            headers["Authorization"] = ep.auth_header
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, ep.base_path + path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
        getheaders = getattr(resp, "getheaders", None)
        headers = (
            {k.lower(): v for k, v in getheaders()} if callable(getheaders) else {}
        )
        return RawResponse(resp.status, raw, len(raw) > MAX_RESPONSE_BYTES, headers)

    def drop(self, ep: Endpoint) -> None:
        conn = self._map().pop(ep, None)
        if conn is not None:
            conn.close()

    def close(self) -> None:
        with self._lock:
            maps = list(self._maps)
        for conns in maps:
            for conn in list(conns.values()):
                conn.close()
            conns.clear()


# ===== § 6. BeaconClient =====

_REQUEST_SLOT_LOCK = threading.Lock()
_next_request_start = 0.0
_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 0.5


def _await_slot(delay: float) -> None:
    global _next_request_start
    if delay <= 0:
        return
    # Reserve the slot under the lock; sleep after release so workers do not serialize.
    with _REQUEST_SLOT_LOCK:
        now = time.monotonic()
        start = max(now, _next_request_start)
        _next_request_start = start + delay
        wait = start - now
    if wait > 0:
        time.sleep(wait)


def _header(headers: dict[str, str], name: str) -> str | None:
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value
    return None


def _retry_after_delay(headers: dict[str, str], attempt: int) -> float:
    raw = _header(headers, "retry-after")
    if raw is not None:
        try:
            seconds = float(raw)
        except (TypeError, ValueError):
            seconds = float("nan")
        if math.isfinite(seconds) and seconds >= 0.0:
            return min(seconds, MAX_RETRY_AFTER)
    return _BACKOFF_BASE * (2 ** attempt) * (0.5 + random.random())


def _classify(
    status: int | None,
    exc: BaseException | None,
    _is_rewards_route: bool,
) -> Literal["retry", "fail", "semantic"]:
    if exc is not None:
        # SSLError/gaierror subclass OSError; TimeoutError is OSError in 3.10+.
        if isinstance(exc, (ssl.SSLError, socket.gaierror)):
            return "fail"
        if isinstance(exc, (TimeoutError, ConnectionError, http.client.HTTPException)):
            return "retry"
        return "fail"
    if status in (429, 503):
        return "retry"
    if status == 500:
        # Rewards and non-rewards 500 share a one-retry cap in _call.
        return "retry"
    if status in (400, 404, 405, 414):
        return "semantic"
    return "semantic"


class BeaconClient:
    def __init__(
        self,
        endpoints: list[Endpoint],
        transport: Transport,
        *,
        request_delay: float,
        log: Log,
    ) -> None:
        self._endpoints = endpoints
        self._transport = transport
        self._request_delay = request_delay
        self._log = log
        self._lock = threading.Lock()
        self._current = 0
        self._used: list[str] = []

    def _endpoint(self) -> Endpoint:
        with self._lock:
            return self._endpoints[self._current]

    def _call(
        self,
        method: str,
        template: str,
        fmt: dict,
        body: bytes | None,
        *,
        retry_500: bool = False,
        extra: str = "",
    ) -> object:
        path = template.format(**fmt) + extra
        ep = self._endpoint()
        shown = redact(ep)
        with self._lock:
            if shown not in self._used:
                self._used.append(shown)
        label = ep.label
        last_exc: BaseException | None = None
        raw: RawResponse | None = None
        for attempt in range(_MAX_ATTEMPTS):
            self._log.info("%s %s via %s", method, template, redact(ep))
            _await_slot(self._request_delay)
            try:
                raw = self._transport(ep, method, path, body)
            except (
                ssl.SSLError,
                socket.gaierror,
                TimeoutError,
                ConnectionError,
                http.client.HTTPException,
            ) as exc:
                last_exc = exc
                action = _classify(None, exc, retry_500)
                if action == "retry" and attempt + 1 < _MAX_ATTEMPTS:
                    self._transport.drop(ep)
                    time.sleep(_retry_after_delay({}, attempt))
                    continue
                raise BeaconTransport(template, label) from exc
            if raw.truncated:
                # Truncation leaves the keep-alive connection in an unknown state.
                self._transport.drop(ep)
                raise BeaconStatus(raw.status, template, label)
            if raw.status == 204:
                return None
            if 200 <= raw.status < 300:
                try:
                    return json.loads(raw.body)
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise BeaconStatus(raw.status, template, label) from exc
            action = _classify(raw.status, None, retry_500)
            retry_limit = 2 if raw.status == 500 else _MAX_ATTEMPTS
            if action == "retry" and attempt + 1 < retry_limit:
                self._transport.drop(ep)
                time.sleep(_retry_after_delay(raw.headers, attempt))
                continue
            raise BeaconStatus(raw.status, template, label)
        if last_exc is not None:
            raise BeaconTransport(template, label) from last_exc
        if raw is None:
            raise BeaconTransport(template, label)
        raise BeaconStatus(raw.status, template, label)

    def _unwrap_call(
        self,
        method: str,
        template: str,
        fmt: dict,
        body: bytes | None = None,
        *,
        retry_500: bool = False,
        none_on: tuple[int, ...] = (),
    ) -> object:
        try:
            payload = self._call(method, template, fmt, body, retry_500=retry_500)
        except BeaconStatus as exc:
            if exc.status in none_on:
                return None
            raise
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def _as_list(self, payload: object, template: str) -> list:
        if payload is None:
            raise BeaconStatus(204, template, self._endpoint().label)
        rows = (
            payload["data"]
            if isinstance(payload, dict) and "data" in payload
            else payload
        )
        if not isinstance(rows, list):
            raise BeaconStatus(200, template, self._endpoint().label)
        return rows

    def spec(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/config/spec", {})

    def genesis(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/beacon/genesis", {})

    def node_version(self) -> str:
        data = self._unwrap_call("GET", "/eth/v1/node/version", {})
        return data["version"] if isinstance(data, dict) else data

    def syncing(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/node/syncing", {})

    def header(self, block_id: str) -> dict | None:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/headers/{block_id}",
            {"block_id": block_id},
            none_on=(404,),
        )

    def finality_checkpoints(self, state_id: str) -> dict:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            {"state_id": state_id},
        )

    def states_validators(self, state_id: str, ids: Sequence[str]) -> list:
        if isinstance(ids, (str, bytes)):
            raise TypeError("ids must be a sequence of id strings, not str or bytes")
        id_list = list(ids)
        if not id_list:
            raise ValueError("ids must be non-empty")
        template = "/eth/v1/beacon/states/{state_id}/validators"
        fmt = {"state_id": state_id}
        try:
            payload = self._call(
                "POST", template, fmt, json.dumps({"ids": id_list}).encode()
            )
        except BeaconStatus as exc:
            if exc.status not in (404, 405, 414):
                raise
        else:
            return self._as_list(payload, template)
        rows: list = []
        for offset in range(0, len(id_list), GET_ID_CHUNK):
            chunk = id_list[offset : offset + GET_ID_CHUNK]
            query = urlencode([("id", item) for item in chunk])
            payload = self._call("GET", template, fmt, None, extra="?" + query)
            rows.extend(self._as_list(payload, template))
        return rows

    def rewards_attestations(self, epoch: int, ids: Sequence[str]) -> dict:
        return self._unwrap_call(
            "POST",
            "/eth/v1/beacon/rewards/attestations/{epoch}",
            {"epoch": epoch},
            json.dumps(list(ids)).encode(),
            retry_500=True,
        )

    def rewards_block(self, slot: int) -> dict | None:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/rewards/blocks/{slot}",
            {"slot": slot},
            retry_500=True,
            none_on=(404,),
        )

    def rewards_sync_committee(self, slot: int, ids: Sequence[str]) -> list | None:
        return self._unwrap_call(
            "POST",
            "/eth/v1/beacon/rewards/sync_committee/{slot}",
            {"slot": slot},
            json.dumps(list(ids)).encode(),
            retry_500=True,
        )

    def proposer_duties(self, epoch: int) -> list:
        return self._unwrap_call(
            "GET",
            "/eth/v1/validator/duties/proposer/{epoch}",
            {"epoch": epoch},
        )

    def sync_committee(self, state_id: str, epoch: int) -> list:
        data = self._unwrap_call(
            "GET",
            "/eth/v1/beacon/states/{state_id}/sync_committees?epoch={epoch}",
            {"state_id": state_id, "epoch": epoch},
        )
        return data["validators"] if isinstance(data, dict) else data

    def liveness(self, epoch: int, ids: Sequence[str]) -> list:
        return self._unwrap_call(
            "POST",
            "/eth/v1/validator/liveness/{epoch}",
            {"epoch": epoch},
            json.dumps(list(ids)).encode(),
        )

    @property
    def endpoints_used(self) -> list[str]:
        with self._lock:
            return list(self._used)


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
