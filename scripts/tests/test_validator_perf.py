"""Tests for scripts/validator_perf.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import ast
import base64
import http.client
import inspect
import io
import json
import re
import socket
import ssl
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport, SCRIPT, load_script, route_map


def test_exit_codes_are_the_six_documented_values(vp):
    assert (
        vp.EXIT_OK,
        vp.EXIT_ERROR,
        vp.EXIT_USAGE,
        vp.EXIT_DEGRADED,
        vp.EXIT_THRESHOLD,
        vp.EXIT_NO_BEACON,
    ) == (0, 1, 2, 3, 4, 5)


def test_epochs_per_year_constant_absent(vp):
    assert not hasattr(vp, "EPOCHS_PER_YEAR")


def test_log_writes_only_to_the_injected_stream(vp, capsys):
    buf = io.StringIO()
    log = vp.Log(0, buf)
    log.error("failed %s", "bn0")
    log.warn("slow %s", "bn0")
    text = buf.getvalue()
    assert "failed bn0" in text
    assert "slow bn0" in text
    captured = capsys.readouterr()
    assert captured.out == ""


def test_log_quiet_suppresses_warn_and_info(vp):
    buf = io.StringIO()
    log = vp.Log(-1, buf)
    log.warn("warn-line")
    log.info("info-line")
    log.error("error-line")
    text = buf.getvalue()
    assert "error-line" in text
    assert "warn-line" not in text
    assert "info-line" not in text


def test_log_info_requires_verbose(vp):
    default = io.StringIO()
    vp.Log(0, default).info("verbose-only")
    assert default.getvalue() == ""
    verbose = io.StringIO()
    vp.Log(1, verbose).info("verbose-only")
    assert "verbose-only" in verbose.getvalue()


def test_section_banners_in_order():
    source = SCRIPT.read_text(encoding="utf-8")
    found = [int(n) for n in re.findall(r"# ===== § (\d+)\.", source)]
    assert found == list(range(1, 17))


def test_pep723_block_is_exact():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env -S uv run --script\n")
    assert "# /// script\n" in source
    assert 'requires-python = ">=3.11"\n' in source
    assert "dependencies = []\n" in source
    assert "# ///\n" in source


def test_imports_are_stdlib_only():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".", 1)[0])
    extra = sorted({name for name in imported if name not in sys.stdlib_module_names})
    assert extra == []


def test_endpoint_repr_omits_secrets(vp):
    ep = vp.Endpoint(
        "bn0",
        "https",
        "bn.example",
        5052,
        "/abc123SECRET",
        "Basic dXNlcjpzZWNyZXQ=",
    )
    shown = repr(ep) + str(ep)
    assert "/abc123SECRET" not in shown
    assert "dXNlcjpzZWNyZXQ=" not in shown


def test_parse_uint_rejects_underscored_and_padded(vp):
    field = "effective_balance"
    for raw in ("1_000", " 42 ", "+7", "", "0x2a", None, 42):
        with pytest.raises((vp.UsageError, ValueError)) as ei:
            vp.parse_uint(raw, field)
        assert field in str(ei.value)


def test_parse_int_accepts_signed_quoted_gwei(vp):
    assert vp.parse_int("-100", "head") == -100
    assert vp.parse_int("0", "head") == 0
    assert vp.parse_int("1834000", "head") == 1834000
    for raw in ("-", "--1"):
        with pytest.raises((vp.UsageError, ValueError)) as ei:
            vp.parse_int(raw, "head")
        assert "head" in str(ei.value)


def test_opt_int_returns_none_for_absent_key(vp):
    absent = vp.opt_int({}, "inclusion_delay")
    present_zero = vp.opt_int({"inclusion_delay": "0"}, "inclusion_delay")
    assert absent is None
    assert present_zero == 0
    assert absent != present_zero


def test_normalize_pubkey_adds_prefix_and_lowercases(vp):
    raw = "AB" * 48
    assert vp.normalize_pubkey(raw, "keys.txt:1") == "0x" + "ab" * 48


def test_normalize_pubkey_rejects_47_bytes_naming_origin(vp):
    origin = "keys.txt:4"
    with pytest.raises(vp.UsageError) as ei:
        vp.normalize_pubkey("ab" * 47, origin)
    assert origin in str(ei.value)


def test_network_is_blocked():
    with pytest.raises(SocketBlockedError, match="getaddrinfo"):
        socket.getaddrinfo("example.com", 80)


def test_vp_fixture_loads_the_script_by_path(vp):
    assert vp.SCHEMA_VERSION == 1
    assert Path(vp.__file__).resolve() == SCRIPT.resolve()


def test_script_does_not_run_main_on_import(capsys):
    source = SCRIPT.read_text(encoding="utf-8")
    guard_at = source.index('if __name__ == "__main__":')
    assert "sys.exit(main())" in source[guard_at:]
    # session-scoped vp already ran; load again here so capsys sees import I/O
    mod = load_script("validator_perf_guard")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert mod.SCHEMA_VERSION == 1


def test_faketransport_records_calls_in_order(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    first = vp.RawResponse(503, b"retry", False)
    second = vp.RawResponse(200, b"ok", False)
    other = vp.RawResponse(200, b"spec", False)
    transport = FakeTransport(
        route_map(
            **{
                "GET /eth/v1/node/syncing": [first, second],
                "GET /eth/v1/config/spec": [other],
            }
        )
    )
    assert transport(ep, "GET", "/eth/v1/node/syncing", None) is first
    assert transport(ep, "GET", "/eth/v1/config/spec", b"") is other
    assert transport(ep, "GET", "/eth/v1/node/syncing", None) is second
    assert transport.calls == [
        ("bn0", "GET", "/eth/v1/node/syncing", None),
        ("bn0", "GET", "/eth/v1/config/spec", b""),
        ("bn0", "GET", "/eth/v1/node/syncing", None),
    ]
    transport.drop(ep)
    assert transport.drops == [ep]


def test_faketransport_raises_on_an_unscripted_call(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    transport = FakeTransport(
        {("GET", "/eth/v1/node/syncing"): [vp.RawResponse(200, b"", False)]}
    )
    with pytest.raises(KeyError):
        transport(ep, "GET", "/unscripted", None)
    assert transport(ep, "GET", "/eth/v1/node/syncing", None).status == 200
    with pytest.raises(IndexError):
        transport(ep, "GET", "/eth/v1/node/syncing", None)


def test_faketransport_query_strip_is_validators_get_only(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    validators = vp.RawResponse(200, b"[]", False)
    syncing = vp.RawResponse(200, b"{}", False)
    transport = FakeTransport(
        {
            ("GET", "/eth/v1/beacon/states/head/validators"): [validators],
            ("GET", "/eth/v1/node/syncing"): [syncing],
        }
    )
    got = transport(
        ep, "GET", "/eth/v1/beacon/states/head/validators?id=1&id=2", None
    )
    assert got is validators
    with pytest.raises(KeyError, match="unscripted"):
        transport(ep, "GET", "/eth/v1/node/syncing?lag=1", None)


def test_faketransport_satisfies_the_transport_alias(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    body = vp.RawResponse(200, b"{}", False)
    transport = FakeTransport({("GET", "/x"): [body]})
    assert list(inspect.signature(transport).parameters) == [
        "ep",
        "method",
        "path",
        "body",
    ]
    got = transport(ep, "GET", "/x", b"payload")
    assert got is body
    assert isinstance(got, vp.RawResponse)


def test_redact_emits_scheme_host_port_only(vp):
    ep = vp.parse_endpoint(
        "https://user:secret@bn.example:5052/abc123SECRET/",
        "bn0",
    )
    shown = vp.redact(ep)
    assert shown == "https://bn.example:5052"
    assert "secret" not in shown
    assert "abc123SECRET" not in shown


def test_parse_endpoint_percent_decodes_userinfo_before_base64(vp):
    ep = vp.parse_endpoint("https://u:p%40ss@h:5052/", "bn0")
    expected = "Basic " + base64.b64encode(b"u:p@ss").decode("ascii")
    literal = "Basic " + base64.b64encode(b"u:p%40ss").decode("ascii")
    assert ep.auth_header == expected
    assert ep.auth_header != literal


def test_parse_endpoint_readds_ipv6_brackets(vp):
    ep = vp.parse_endpoint("http://[::1]:5052", "bn0")
    assert ep.host == "[::1]"


def test_parse_endpoint_keeps_base_path(vp):
    ep = vp.parse_endpoint("https://h:5052/abc123SECRET/", "bn0")
    assert ep.base_path == "/abc123SECRET"


def test_parse_endpoint_defaults_port_by_scheme(vp):
    assert vp.parse_endpoint("https://h", "bn0").port == 443
    assert vp.parse_endpoint("http://h", "bn1").port == 80


def test_parse_endpoint_rejects_unknown_scheme(vp):
    with pytest.raises(vp.UsageError):
        vp.parse_endpoint("ftp://h", "bn0")


def test_parse_endpoint_malformed_netloc_raises_usage_error(vp):
    url = "https://h:99999"
    with pytest.raises(vp.UsageError) as ei:
        vp.parse_endpoint(url, "bn0")
    assert url in str(ei.value)
    with pytest.raises(vp.UsageError) as ei:
        vp.parse_endpoint("https://h:abc", "bn1")
    assert "https://h:abc" in str(ei.value)


def test_parse_endpoint_absent_userinfo_has_no_auth(vp):
    assert vp.parse_endpoint("https://h:5052", "bn0").auth_header is None


def test_endpoint_label_is_positional(vp):
    a = vp.parse_endpoint("http://same.example:5052", "bn0")
    b = vp.parse_endpoint("http://same.example:5052", "bn1")
    assert a.label == "bn0"
    assert b.label == "bn1"
    assert a.host == b.host == "same.example"


def test_endpoint_is_frozen(vp):
    ep = vp.parse_endpoint("http://h", "bn0")
    with pytest.raises(FrozenInstanceError):
        ep.base_path = "/abc123SECRET"


FIXTURES = Path(__file__).resolve().parent / "fixtures"

PK1 = "0x" + "11" * 48
PK2 = "0x" + "22" * 48
PK3 = "0x" + "33" * 48
PK4 = "0x" + "44" * 48

_DOCUMENTED_FLAGS = {
    "--pubkey",
    "--pubkeys-file",
    "--validators-config",
    "--beacon-url",
    "--config",
    "--epochs",
    "--from-epoch",
    "--to-epoch",
    "--allow-unfinalized",
    "--force-unsafe-window",
    "--json",
    "--csv",
    "--concurrency",
    "--request-delay-ms",
    "--connect-timeout",
    "--read-timeout",
    "--degraded-ok",
    "--fail-under",
    "--liveness-check",
    "--dry-run",
    "--no-cache",
    "-v",
    "-q",
}


def _load_pubkeys(vp, argv):
    return vp.load_pubkeys(vp.build_parser().parse_args(argv))


def test_pubkey_union_across_three_sources_in_input_order(vp):
    # --pubkey ∪ --pubkeys-file ∪ --validators-config, first-seen; file dups PK1.
    toml = str(FIXTURES / "validators__three_entries.toml")
    pubfile = str(FIXTURES / "pubkeys__two_one_dup.txt")
    expected = [PK4, PK1, PK2, PK3]
    assert (
        _load_pubkeys(
            vp,
            ["--pubkey", PK4, "--pubkeys-file", pubfile, "--validators-config", toml],
        )
        == expected
    )
    # Argv order must not change operand order; second --pubkey is append + de-dup.
    assert (
        _load_pubkeys(
            vp,
            [
                "--validators-config",
                toml,
                "--pubkeys-file",
                pubfile,
                "--pubkey",
                PK4,
                "--pubkey",
                PK1,
            ],
        )
        == expected
    )


def test_short_pubkey_exits_2_naming_source_and_line(vp):
    path = str(FIXTURES / "pubkeys__short_hex.txt")
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--pubkeys-file", path])
    msg = str(ei.value)
    assert path in msg
    assert f"{path}:3" in msg
    assert vp.EXIT_USAGE == 2


def test_short_cli_pubkey_names_flag_origin(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--pubkey", "aa" * 47])
    assert "--pubkey #1" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_short_toml_pubkey_names_table_origin(vp, tmp_path):
    path = str(tmp_path / "validators__short.toml")
    Path(path).write_text(f'[[validators]]\npubkey = "{"aa" * 47}"\n', encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--validators-config", path])
    assert f"{path} [[validators]] #1" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_pubkeys_file_ignores_blanks_and_comments(vp):
    path = str(FIXTURES / "pubkeys__two_one_dup.txt")
    assert _load_pubkeys(vp, ["--pubkeys-file", path]) == [PK1, PK4]


def test_validators_config_accepts_unprefixed_pubkey(vp):
    path = str(FIXTURES / "validators__unprefixed.toml")
    assert _load_pubkeys(vp, ["--validators-config", path]) == [
        "0x" + "aa" * 48,
    ]


def test_no_pubkeys_exits_2(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, [])
    assert "pubkey" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2


def test_validators_config_opened_in_binary_mode(vp, monkeypatch):
    path = str(FIXTURES / "validators__three_entries.toml")
    modes: list[str] = []
    real_load = vp.tomllib.load

    def spy(fp, *a, **kw):
        modes.append(getattr(fp, "mode", ""))
        return real_load(fp, *a, **kw)

    monkeypatch.setattr(vp.tomllib, "load", spy)
    assert _load_pubkeys(vp, ["--validators-config", path]) == [PK1, PK2, PK3]
    assert any("b" in mode for mode in modes)


def test_parser_declares_every_documented_flag(vp):
    parser = vp.build_parser()
    names = {opt for action in parser._actions for opt in action.option_strings}
    dests = {action.dest: list(action.option_strings) for action in parser._actions}
    assert _DOCUMENTED_FLAGS <= names
    assert "--prometheus" not in names
    assert names - _DOCUMENTED_FLAGS <= {"-h", "--help"}
    assert dests["verbose"] == ["-v"]
    assert dests["quiet"] == ["-q"]


def _https_ep(vp, *, label="bn0", host="bn.example", base_path="", auth_header=None):
    return vp.Endpoint(label, "https", host, 5052, base_path, auth_header)


def _patch_https(monkeypatch, vp, *, status=200, body=b"{}"):
    constructed = []

    class FakeSock:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

    class FakeResp:
        def __init__(self):
            self.status = status
            self.read_amt = None

        def read(self, amt=None):
            self.read_amt = amt
            if amt is None:
                return body
            return body[:amt]

    class FakeHTTPSConnection:
        def __init__(self, host, port=None, timeout=None, **_kwargs):
            constructed.append(self)
            self.host = host
            self.port = port
            self.timeout = timeout
            self.sock = None
            self.closed = False
            self.requests = []
            self.response = FakeResp()

        def connect(self):
            self.sock = FakeSock()

        def request(self, method, url, body=None, headers=None, **_kwargs):
            self.requests.append((method, url, body, dict(headers or {})))

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True
            self.sock = None

    monkeypatch.setattr(vp.http.client, "HTTPSConnection", FakeHTTPSConnection)
    return constructed


def test_transport_reuses_one_connection_per_thread_per_endpoint(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    for _ in range(5):
        raw = transport(ep, "GET", "/eth/v1/config/spec", None)
        assert raw.status == 200
        assert raw.truncated is False
    assert len(constructed) == 1


def test_transport_opens_separate_connections_per_thread(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    errors: list[Exception] = []

    def worker():
        try:
            transport(ep, "GET", "/eth/v1/config/spec", None)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(constructed) == 2


def test_transport_sets_read_timeout_on_the_socket_after_connect(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    connect_timeout = 1.25
    read_timeout = 4.5
    transport = vp.HttpTransport(connect_timeout, read_timeout)
    transport(_https_ep(vp), "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    conn = constructed[0]
    assert conn.timeout == connect_timeout
    assert conn.sock is not None
    assert conn.sock.timeouts == [read_timeout]


def test_transport_marks_truncated_over_the_cap(vp, monkeypatch):
    cap = 32
    monkeypatch.setattr(vp, "MAX_RESPONSE_BYTES", cap)
    payload = b"x" * (cap + 1)
    constructed = _patch_https(monkeypatch, vp, body=payload)
    transport = vp.HttpTransport(1.25, 4.5)
    raw = transport(_https_ep(vp), "GET", "/eth/v1/config/spec", None)
    assert raw.truncated is True
    assert constructed[0].response.read_amt == cap + 1


def test_transport_sends_authorization_and_base_path(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    auth = "Basic " + base64.b64encode(b"user:secret").decode("ascii")
    ep = _https_ep(vp, base_path="/abc123SECRET", auth_header=auth)
    transport = vp.HttpTransport(1.25, 4.5)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed[0].requests) == 1
    method, url, body, headers = constructed[0].requests[0]
    assert method == "GET"
    assert url == "/abc123SECRET/eth/v1/config/spec"
    assert body is None
    assert headers["Authorization"] == auth


def test_drop_closes_and_forgets_the_connection(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    transport.drop(ep)
    assert constructed[0].closed is True
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2


def test_close_from_main_thread_closes_worker_connections(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    errors: list[Exception] = []

    def worker():
        try:
            transport(ep, "GET", "/eth/v1/config/spec", None)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(constructed) == 2
    assert all(not conn.closed for conn in constructed)
    transport.close()
    assert all(conn.closed for conn in constructed)


def test_transport_separate_connections_per_endpoint_drop_is_selective(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep0 = _https_ep(vp, label="bn0", host="bn0.example")
    ep1 = _https_ep(vp, label="bn1", host="bn1.example")
    transport(ep0, "GET", "/eth/v1/config/spec", None)
    transport(ep1, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2
    transport.drop(ep0)
    assert constructed[0].closed is True
    assert constructed[1].closed is False
    transport(ep1, "GET", "/eth/v1/node/version", None)
    assert len(constructed) == 2
    transport(ep0, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 3


def test_transport_sets_content_type_only_on_body(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    transport(ep, "POST", "/eth/v1/beacon/states/head/validators", b'{"ids":[]}')
    get_headers = constructed[0].requests[0][3]
    post_headers = constructed[0].requests[1][3]
    assert "Content-Type" not in get_headers
    assert post_headers["Content-Type"] == "application/json"
    assert constructed[0].requests[1][2] == b'{"ids":[]}'


def test_transport_rebuilds_when_cached_sock_is_none(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    constructed[0].sock = None
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2
    assert constructed[0].closed is True
    assert constructed[1].sock is not None
    assert constructed[1].sock.timeouts == [4.5]
    assert constructed[1].timeout == 1.25


def test_transport_module_contains_no_log_call():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# ===== § 5\. Transport =====(.*?)# ===== § 6\.",
        source,
        re.DOTALL,
    )
    assert match is not None
    assert "log." not in match.group(1)


def test_socket_blocked(vp):
    from pytest_socket import SocketBlockedError, disable_socket, enable_socket

    disable_socket()
    try:
        transport = vp.HttpTransport(0.1, 0.1)
        ep = vp.Endpoint("bn0", "https", "example.invalid", 443, "", None)
        with pytest.raises(SocketBlockedError):
            transport(ep, "GET", "/eth/v1/config/spec", None)
    finally:
        enable_socket()


def _load_beacon_urls(vp, argv):
    return vp.load_beacon_urls(vp.build_parser().parse_args(argv))


def _minimal_opts_argv(*extra):
    return ["--pubkey", PK1, "--beacon-url", "http://h:5052", *extra]


def test_beacon_nodes_beats_beacon_url_in_config(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["alpha.example", "beta.example"]
    assert all(e.host != "primary.example" for e in eps)


def test_beacon_url_flag_beats_the_config_file_entirely(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(
        vp,
        ["--config", path, "--beacon-url", "http://flag.example:5052"],
    )
    assert [e.host for e in eps] == ["flag.example"]


def test_empty_beacon_nodes_falls_through_to_beacon_url(vp):
    path = str(FIXTURES / "config__empty_nodes.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["only.example"]


def test_no_beacon_url_exits_2_not_5(vp, tmp_path):
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(["--pubkey", PK1])
    assert ei.type is vp.UsageError
    assert not isinstance(ei.value, vp.NoBeaconAvailable)
    assert "beacon" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2
    assert vp.EXIT_NO_BEACON == 5
    assert vp.EXIT_USAGE != vp.EXIT_NO_BEACON
    empty = tmp_path / "config__no_urls.toml"
    empty.write_text('network = "hoodi"\n', encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(["--pubkey", PK1, "--config", str(empty)])
    assert "beacon" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2


def test_epochs_with_from_epoch_exits_2(vp):
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(_minimal_opts_argv("--epochs", "4", "--from-epoch", "1"))
    assert "epoch" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2
    with pytest.raises(vp.UsageError):
        vp.build_options(_minimal_opts_argv("--epochs", "4", "--to-epoch", "10"))


def test_verbose_and_quiet_together_exits_2(vp):
    with pytest.raises(vp.UsageError):
        vp.build_options(_minimal_opts_argv("-v", "-q"))
    assert vp.EXIT_USAGE == 2


def test_options_is_frozen(vp):
    opts = vp.build_options(_minimal_opts_argv())
    with pytest.raises(FrozenInstanceError):
        opts.verbosity = 1
    assert isinstance(opts.pubkeys, tuple)
    assert isinstance(opts.endpoints, tuple)
    assert isinstance(opts.fail_under, tuple)


def test_endpoint_labels_are_bn0_bn1_in_config_order(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.label for e in eps] == ["bn0", "bn1"]
    assert [e.host for e in eps] == ["alpha.example", "beta.example"]


def test_verbosity_tiers(vp):
    assert vp.build_options(_minimal_opts_argv()).verbosity == 0
    assert vp.build_options(_minimal_opts_argv("-q")).verbosity == -1
    assert vp.build_options(_minimal_opts_argv("-v")).verbosity == 1
    assert vp.build_options(_minimal_opts_argv("-vv")).verbosity == 2


def test_unset_window_fields_are_none(vp):
    opts = vp.build_options(_minimal_opts_argv())
    assert opts.epochs is None
    assert opts.from_epoch is None
    assert opts.to_epoch is None


def test_from_and_to_epoch_without_epochs_ok(vp):
    opts = vp.build_options(
        _minimal_opts_argv("--from-epoch", "10", "--to-epoch", "20")
    )
    assert opts.epochs is None
    assert opts.from_epoch == 10
    assert opts.to_epoch == 20


def test_two_beacon_url_flags_ignore_config(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(
        vp,
        [
            "--config",
            path,
            "--beacon-url",
            "http://flag0.example:5052",
            "--beacon-url",
            "http://flag1.example:5052",
        ],
    )
    assert [e.host for e in eps] == ["flag0.example", "flag1.example"]
    assert [e.label for e in eps] == ["bn0", "bn1"]


def test_beacon_url_only_config(vp):
    path = str(FIXTURES / "config__beacon_url_only.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["solo.example"]
    assert [e.label for e in eps] == ["bn0"]


def test_non_str_beacon_nodes_entry_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__int_node.toml"
    path.write_text("beacon_nodes = [5052]\n", encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "5052" in msg
    assert "beacon" in msg.lower()


def test_non_list_beacon_nodes_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__string_nodes.toml"
    path.write_text(
        'beacon_nodes = "http://string.example:5052"\n'
        'beacon_url = "http://fallback.example:5052"\n',
        encoding="utf-8",
    )
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "beacon_nodes" in msg


def test_non_str_beacon_url_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__int_url.toml"
    path.write_text("beacon_url = 5052\n", encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "5052" in msg
    assert "beacon_url" in msg


def test_empty_beacon_url_flag_raises_usage_error(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--beacon-url", ""])
    msg = str(ei.value)
    assert "--beacon-url" in msg
    assert "beacon" in msg.lower()


# ----- VP-1h: §6 _call retry matrix -----

_REWARDS_TEMPLATE = "/eth/v1/beacon/rewards/attestations/{epoch}"
_SPEC_TEMPLATE = "/eth/v1/config/spec"
_VERSION_TEMPLATE = "/eth/v1/node/version"
_SECRET_URL = "https://user:secret@bn.example:5052/abc123SECRET/"


def _boom(exc: BaseException):
    def inner():
        raise exc

    return inner


def _raw(vp, status, body=b"{}", truncated=False, headers=None):
    return vp.RawResponse(status, body, truncated, headers or {})


def _client(vp, transport, *, request_delay=0.0, verbosity=1, ep=None, stream=None):
    buf = stream if stream is not None else io.StringIO()
    if ep is None:
        ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    log = vp.Log(verbosity, buf)
    return vp.BeaconClient([ep], transport, request_delay=request_delay, log=log), buf


def _no_sleep(monkeypatch, vp):
    slept = []
    monkeypatch.setattr(vp.time, "sleep", lambda s: slept.append(s))
    return slept


def test_retry_on_429_honours_capped_retry_after(vp, monkeypatch):
    slept = _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {
            ("GET", path): [
                _raw(vp, 429, headers={"Retry-After": "7200"}),
                _raw(vp, 200, b'{"data": true}'),
            ]
        }
    )
    client, _ = _client(vp, transport)
    got = client._call("GET", path, {}, None)
    assert got == {"data": True}
    assert len(transport.calls) == 2
    assert slept == [vp.MAX_RETRY_AFTER]
    assert vp.MAX_RETRY_AFTER == 30.0


def test_retry_on_503_backs_off_then_succeeds(vp, monkeypatch):
    slept = _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    body = b'{"ok": true}'
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 503), _raw(vp, 503), _raw(vp, 200, body)]}
    )
    client, _ = _client(vp, transport)
    got = client._call("GET", path, {}, None)
    assert got == {"ok": True}
    assert len(transport.calls) == 3
    assert slept  # exponential backoff, not a real wait


def test_500_from_a_rewards_route_retries_exactly_once(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    fmt = {"epoch": 7}
    path = _REWARDS_TEMPLATE.format(**fmt)
    transport = FakeTransport(
        {("POST", path): [_raw(vp, 500), _raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("POST", _REWARDS_TEMPLATE, fmt, b"[]", retry_500=True)
    assert ei.value.status == 500
    assert ei.value.template == _REWARDS_TEMPLATE
    assert len(transport.calls) == 2


def test_500_elsewhere_retries_once_then_raises(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 500), _raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None, retry_500=False)
    assert ei.value.status == 500
    assert len(transport.calls) == 2


def test_400_and_404_and_405_and_414_are_never_retried(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    for status in (400, 404, 405, 414):
        transport = FakeTransport(
            {("GET", path): [_raw(vp, status), _raw(vp, 200)]}
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconStatus) as ei:
            client._call("GET", path, {}, None)
        assert ei.value.status == status
        assert ei.value.template == path
        assert len(transport.calls) == 1


def test_204_returns_none_before_json_loads(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    loaded = []
    real = vp.json.loads

    def spy(raw, *a, **k):
        loaded.append(raw)
        return real(raw, *a, **k)

    monkeypatch.setattr(vp.json, "loads", spy)
    path = _VERSION_TEMPLATE
    transport = FakeTransport({("GET", path): [_raw(vp, 204, b"")]})
    client, _ = _client(vp, transport)
    assert client._call("GET", path, {}, None) is None
    assert loaded == []


def test_ssl_error_and_gaierror_fail_fast(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _VERSION_TEMPLATE
    cases = (
        ssl.SSLError("certificate verify failed"),
        socket.gaierror(-2, "Name or service not known"),
    )
    for exc in cases:
        transport = FakeTransport(
            {("GET", path): [_boom(exc), _boom(exc), _boom(exc)]}
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconTransport):
            client._call("GET", path, {}, None)
        assert len(transport.calls) == 1
        assert transport.drops == []


def test_timeout_and_connection_error_retry_to_max_attempts(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _VERSION_TEMPLATE
    for exc in (
        TimeoutError("timed out"),
        ConnectionError("reset"),
        http.client.IncompleteRead(b""),
    ):
        transport = FakeTransport({("GET", path): [_boom(exc) for _ in range(5)]})
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconTransport):
            client._call("GET", path, {}, None)
        assert len(transport.calls) == 3
        assert len(transport.drops) == 2


def test_drop_called_before_every_retry(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 503), _raw(vp, 503), _raw(vp, 200, b"{}")]}
    )
    client, _ = _client(vp, transport)
    client._call("GET", path, {}, None)
    assert len(transport.calls) == 3
    assert len(transport.drops) == 2


def test_truncated_body_is_a_hard_error(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    loaded = []
    real = vp.json.loads

    def spy(raw, *a, **k):
        loaded.append(raw)
        return real(raw, *a, **k)

    monkeypatch.setattr(vp.json, "loads", spy)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 200, b'{"ok": true}', truncated=True)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None)
    assert ei.value.template == path
    assert loaded == []
    assert len(transport.calls) == 1
    assert len(transport.drops) == 1


def test_empty_200_body_is_beacon_status(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport({("GET", path): [_raw(vp, 200, b"")]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None)
    assert ei.value.status == 200
    assert ei.value.template == path
    assert len(transport.calls) == 1


def test_no_url_or_secret_in_any_retry_log_line(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    ep = vp.parse_endpoint(_SECRET_URL, "bn0")
    buf = io.StringIO()
    templates = []

    def run(method, template, fmt, body, queue, **call_kw):
        path = template.format(**fmt)
        transport = FakeTransport({(method, path): queue})
        client, _ = _client(vp, transport, ep=ep, stream=buf)
        try:
            client._call(method, template, fmt, body, **call_kw)
        except (vp.BeaconStatus, vp.BeaconTransport):
            pass
        templates.append(template)

    ok = _raw(vp, 200)
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 429, headers={"Retry-After": "7200"}), ok])
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 503), _raw(vp, 503), ok])
    run(
        "POST",
        _REWARDS_TEMPLATE,
        {"epoch": 9},
        b"[]",
        [_raw(vp, 500), _raw(vp, 500)],
        retry_500=True,
    )
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 500), _raw(vp, 500)])
    for status in (400, 404, 405, 414):
        run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, status)])
    run("GET", _VERSION_TEMPLATE, {}, None, [_raw(vp, 204, b"")])
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(ssl.SSLError("bad cert"))])
    run(
        "GET",
        _VERSION_TEMPLATE,
        {},
        None,
        [_boom(socket.gaierror(-2, "Name or service not known"))],
    )
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(TimeoutError())] * 3)
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(ConnectionError())] * 3)
    run(
        "GET",
        _VERSION_TEMPLATE,
        {},
        None,
        [_boom(http.client.IncompleteRead(b""))] * 3,
    )
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 200, b"{}", truncated=True)])
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 200, b"")])

    text = buf.getvalue()
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "user:secret" not in text
    for template in templates:
        assert template in text
    assert _REWARDS_TEMPLATE.format(epoch=9) not in text
    assert "/abc123SECRET" not in text


def test_request_spacing_lock_enforces_minimum_gap(vp, monkeypatch):
    clock = {"t": 10.0}
    vp._next_request_start = 0.0
    monkeypatch.setattr(vp.time, "monotonic", lambda: clock["t"])

    def sleep(seconds):
        clock["t"] += seconds

    monkeypatch.setattr(vp.time, "sleep", sleep)
    starts = []
    path = _VERSION_TEMPLATE

    def ok():
        starts.append(clock["t"])
        return _raw(vp, 200)

    transport = FakeTransport({("GET", path): [ok, ok]})
    client, _ = _client(vp, transport, request_delay=0.05)
    client._call("GET", path, {}, None)
    client._call("GET", path, {}, None)
    assert len(starts) == 2
    assert starts[1] - starts[0] >= 0.05


# ----- VP-1i: §6 typed calls -----

_VALIDATORS_PATH = "/eth/v1/beacon/states/head/validators"
_PROPOSER_TEMPLATE = "/eth/v1/validator/duties/proposer/{epoch}"


def _query_ids(path: str) -> list[str]:
    return parse_qs(urlsplit(path).query).get("id", [])


def _data_raw(vp, data, status=200):
    return _raw(vp, status, json.dumps({"data": data}).encode())


def test_states_validators_posts_an_object_not_an_array(vp):
    ids = ["0x" + "ab" * 48, "0x" + "cd" * 48]
    att_path = _REWARDS_TEMPLATE.format(epoch=4)
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_data_raw(vp, [])],
            ("POST", att_path): [_data_raw(vp, {})],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    client.rewards_attestations(4, ids)
    validators_body = json.loads(transport.calls[0][3])
    rewards_body = json.loads(transport.calls[1][3])
    assert validators_body == {"ids": ids}
    assert isinstance(validators_body, dict)
    assert not isinstance(validators_body, list)
    assert rewards_body == ids
    assert isinstance(rewards_body, list)


def test_200_keys_produce_exactly_one_post(vp):
    ids = [str(i) for i in range(200)]
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [_data_raw(vp, [])]})
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == "POST"
    assert transport.calls[0][2] == _VALIDATORS_PATH
    assert json.loads(transport.calls[0][3]) == {"ids": ids}


def test_post_414_falls_back_to_four_chunked_gets(vp):
    ids = [str(i) for i in range(200)]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [_data_raw(vp, []) for _ in range(4)],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    posts = [c for c in transport.calls if c[1] == "POST"]
    gets = [c for c in transport.calls if c[1] == "GET"]
    assert len(posts) == 1
    assert posts[0][2] == _VALIDATORS_PATH
    assert len(gets) == 4
    seen = []
    sizes = []
    for _label, _method, path, _body in gets:
        chunk = _query_ids(path)
        assert len(chunk) <= vp.GET_ID_CHUNK
        assert vp.GET_ID_CHUNK == 64
        sizes.append(len(chunk))
        seen.extend(chunk)
    assert sizes == [64, 64, 64, 8]
    assert seen == ids


def test_post_404_and_405_also_trigger_the_get_fallback(vp):
    ids = ["10", "11", "12"]
    for status in (404, 405):
        transport = FakeTransport(
            {
                ("POST", _VALIDATORS_PATH): [_raw(vp, status)],
                ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
            }
        )
        client, _ = _client(vp, transport)
        client.states_validators("head", ids)
        assert [c[1] for c in transport.calls] == ["POST", "GET"]
        assert transport.calls[0][2] == _VALIDATORS_PATH
        assert _query_ids(transport.calls[1][2]) == ids


def test_states_validators_rejects_empty_ids(vp):
    transport = FakeTransport({})
    client, _ = _client(vp, transport)
    with pytest.raises(ValueError):
        client.states_validators("head", [])
    with pytest.raises(ValueError):
        client.states_validators("head", iter([]))
    with pytest.raises(TypeError):
        client.states_validators("head", "0xabcd")
    with pytest.raises(TypeError):
        client.states_validators("head", b"0xabcd")
    assert transport.calls == []


def test_no_method_reaches_the_validators_route_unfiltered():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            chunk = ast.get_source_segment(source, node) or ""
            if "/validators" in chunk:
                found.append(node.name)
    assert found == ["states_validators"]


def test_header_returns_none_on_404(vp):
    path = "/eth/v1/beacon/headers/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    assert client.header("123") is None
    assert len(transport.calls) == 1


def test_rewards_block_returns_none_on_404(vp):
    path = "/eth/v1/beacon/rewards/blocks/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    assert client.rewards_block(123) is None
    assert len(transport.calls) == 1


def test_rewards_routes_pass_retry_500(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    att_path = _REWARDS_TEMPLATE.format(epoch=3)
    transport = FakeTransport({("POST", att_path): [_raw(vp, 500), _raw(vp, 500)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.rewards_attestations(3, ["1"])
    assert ei.value.status == 500
    assert len(transport.calls) == 2

    duty_path = _PROPOSER_TEMPLATE.format(epoch=3)
    transport = FakeTransport({("GET", duty_path): [_raw(vp, 500), _raw(vp, 500)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.proposer_duties(3)
    assert ei.value.status == 500
    assert len(transport.calls) == 2

    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_raw(vp, 400), _raw(vp, 200, b'{"data": {}}')]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.spec()
    assert ei.value.status == 400
    assert len(transport.calls) == 1

    for name in (
        "rewards_attestations",
        "rewards_block",
        "rewards_sync_committee",
    ):
        assert "retry_500=True" in inspect.getsource(getattr(vp.BeaconClient, name))
    assert "retry_500=True" not in inspect.getsource(vp.BeaconClient.proposer_duties)
    assert "retry_500=True" not in inspect.getsource(vp.BeaconClient.spec)


def test_endpoints_used_records_redacted_strings_only(vp):
    ep = vp.parse_endpoint(_SECRET_URL, "bn0")
    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_data_raw(vp, {"SLOTS_PER_EPOCH": "32"})]}
    )
    client, _ = _client(vp, transport, ep=ep)
    client.spec()
    used = client.endpoints_used
    assert used == ["https://bn.example:5052"]
    blob = " ".join(used)
    assert "secret" not in blob
    assert "user:secret" not in blob
    assert "abc123SECRET" not in blob
    assert "/abc123SECRET" not in blob
    used.append("leaked")
    assert "leaked" not in client.endpoints_used


def test_states_validators_post_204_raises_not_none(vp):
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [_raw(vp, 204, b"")]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.states_validators("head", ["1"])
    assert ei.value.status == 204
    assert [c[1] for c in transport.calls] == ["POST"]


def test_states_validators_get_chunk_204_raises_not_empty_list(vp):
    ids = [str(i) for i in range(65)]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [
                _data_raw(vp, [{"index": "0"}]),
                _raw(vp, 204, b""),
            ],
        }
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.states_validators("head", ids)
    assert ei.value.status == 204
    assert [c[1] for c in transport.calls] == ["POST", "GET", "GET"]


def test_post_400_and_500_do_not_get_fallback(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    ids = ["1", "2"]
    for status in (400, 500):
        transport = FakeTransport(
            {
                ("POST", _VALIDATORS_PATH): [_raw(vp, status), _raw(vp, status)],
                ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
            }
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconStatus) as ei:
            client.states_validators("head", ids)
        assert ei.value.status == status
        assert all(c[1] == "POST" for c in transport.calls)
        assert not any(c[1] == "GET" for c in transport.calls)


def test_header_400_still_raises(vp):
    path = "/eth/v1/beacon/headers/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 400)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.header("123")
    assert ei.value.status == 400
    assert len(transport.calls) == 1


def test_rewards_sync_committee_404_raises(vp):
    path = "/eth/v1/beacon/rewards/sync_committee/5"
    transport = FakeTransport({("POST", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.rewards_sync_committee(5, ["1"])
    assert ei.value.status == 404
    assert len(transport.calls) == 1


def test_current_stays_zero_on_500(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus):
        client.spec()
    assert client._current == 0


def test_get_fallback_query_not_passed_through_str_format(vp):
    ids = ["foo{bar}", "baz"]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    assert [c[1] for c in transport.calls] == ["POST", "GET"]
    assert _query_ids(transport.calls[1][2]) == ids
