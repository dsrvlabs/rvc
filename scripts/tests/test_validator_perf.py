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
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport, SCRIPT, load_script, raw_response, route_map


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


def _client(
    vp,
    transport,
    *,
    request_delay=0.0,
    verbosity=1,
    ep=None,
    stream=None,
    endpoints=None,
):
    buf = stream if stream is not None else io.StringIO()
    if endpoints is None:
        if ep is None:
            ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
        endpoints = [ep]
    log = vp.Log(verbosity, buf)
    return vp.BeaconClient(endpoints, transport, request_delay=request_delay, log=log), buf


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


# ----- VP-1j: §7 Spec, ChainContext, select_endpoint -----

_GENESIS_PATH = "/eth/v1/beacon/genesis"
_HEADER_HEAD_PATH = "/eth/v1/beacon/headers/head"
_FINALITY_PATH = "/eth/v1/beacon/states/head/finality_checkpoints"
_SYNCING_PATH = "/eth/v1/node/syncing"


def _chain_transport(vp, *, spec="spec__mainnet", spec_body=None):
    spec_resp = (
        _raw(vp, 200, spec_body)
        if spec_body is not None
        else raw_response(vp, spec)
    )
    return FakeTransport(
        route_map(
            **{
                f"GET {_SPEC_TEMPLATE}": [spec_resp],
                f"GET {_GENESIS_PATH}": [raw_response(vp, "genesis__mainnet")],
                f"GET {_HEADER_HEAD_PATH}": [raw_response(vp, "headers__head")],
                f"GET {_FINALITY_PATH}": [
                    raw_response(vp, "finality_checkpoints__head")
                ],
            }
        )
    )


def _load_ctx(vp, *, spec="spec__mainnet", spec_body=None):
    transport = _chain_transport(vp, spec=spec, spec_body=spec_body)
    client, _ = _client(vp, transport)
    ctx = vp.load_chain_context(client)
    return ctx, transport, client


def test_epochs_per_year_is_82181_25_on_mainnet_timing(vp):
    ctx, _, _ = _load_ctx(vp, spec="spec__mainnet")
    assert ctx.spec.seconds_per_slot == 12
    assert ctx.spec.slots_per_epoch == 32
    assert ctx.spec.epochs_per_year == 82181.25


def test_epochs_per_year_halves_at_six_second_slots(vp):
    ctx, _, _ = _load_ctx(vp, spec="spec__spe8")
    assert ctx.spec.seconds_per_slot == 6
    assert ctx.spec.slots_per_epoch == 8
    assert ctx.spec.epochs_per_year == 31_557_600 / 48


def test_load_chain_context_issues_exactly_four_calls(vp):
    ctx, transport, _ = _load_ctx(vp)
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _SPEC_TEMPLATE),
        ("GET", _GENESIS_PATH),
        ("GET", _HEADER_HEAD_PATH),
        ("GET", _FINALITY_PATH),
    ]
    assert ctx.genesis_time == 1606824023
    assert ctx.network_name == "mainnet"
    assert ctx.finalized_epoch == 99
    assert ctx.rewards_api == ""


def test_head_epoch_derived_from_header_slot_not_clock(vp):
    ctx, transport, _ = _load_ctx(vp, spec="spec__mainnet")
    assert ctx.head_slot == 3232
    assert ctx.head_epoch == 101
    assert ctx.spec.slots_per_epoch == 32
    src = inspect.getsource(vp.load_chain_context)
    assert "time.time" not in src
    assert "datetime" not in src
    clock_epoch = int(vp.time.time() - ctx.genesis_time) // (
        ctx.spec.seconds_per_slot * ctx.spec.slots_per_epoch
    )
    assert clock_epoch != 101
    assert [c[2] for c in transport.calls] == [
        _SPEC_TEMPLATE,
        _GENESIS_PATH,
        _HEADER_HEAD_PATH,
        _FINALITY_PATH,
    ]


def test_select_endpoint_skips_a_syncing_node(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "syncing.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "ready.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse"),
                    raw_response(vp, "node_version__lighthouse"),
                ],
                f"GET {_SYNCING_PATH}": [
                    raw_response(vp, "node_syncing__is_syncing"),
                    raw_response(vp, "node_syncing__ready"),
                ],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn0", "bn1", "bn1"]
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
    ]
    assert client._current == 1
    assert client._endpoint().label == "bn1"


def test_all_endpoints_failing_raises_no_beacon_available(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "dead0.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "dead1.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [_raw(vp, 404), _raw(vp, 404)],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn1"]


def test_missing_spec_key_names_the_key(vp, load):
    payload = load("spec__mainnet")
    key = "EPOCHS_PER_SYNC_COMMITTEE_PERIOD"
    del payload["data"][key]
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert key in str(ei.value)
    assert not isinstance(ei.value, vp.NoBeaconAvailable)


def test_network_name_is_none_without_config_name(vp, load):
    payload = load("spec__mainnet")
    payload["data"].pop("CONFIG_NAME")
    ctx, _, _ = _load_ctx(vp, spec_body=json.dumps(payload).encode())
    assert ctx.network_name is None


def test_head_header_404_and_204_are_not_usage_error_missing_slot(vp):
    for status in (404, 204):
        transport = _chain_transport(vp)
        transport.routes[("GET", _HEADER_HEAD_PATH)] = [_raw(vp, status, b"")]
        client, _ = _client(vp, transport)
        with pytest.raises(vp.NoBeaconAvailable) as ei:
            vp.load_chain_context(client)
        assert ei.type is vp.NoBeaconAvailable
        assert not isinstance(ei.value, vp.UsageError)
        assert "missing slot" not in str(ei.value)


@pytest.mark.parametrize(
    "path",
    [_SPEC_TEMPLATE, _GENESIS_PATH, _FINALITY_PATH],
)
def test_phase1_204_is_no_beacon_available(vp, path):
    transport = _chain_transport(vp)
    transport.routes[("GET", path)] = [_raw(vp, 204, b"")]
    client, _ = _client(vp, transport)
    with pytest.raises(vp.NoBeaconAvailable) as ei:
        vp.load_chain_context(client)
    assert "missing slot" not in str(ei.value)


def test_select_then_load_records_lighthouse_version(vp):
    transport = _chain_transport(vp)
    transport.routes[("GET", _VERSION_TEMPLATE)] = [
        raw_response(vp, "node_version__lighthouse")
    ]
    transport.routes[("GET", _SYNCING_PATH)] = [
        raw_response(vp, "node_syncing__ready")
    ]
    client, _ = _client(vp, transport)
    vp.select_endpoint(client)
    ctx = vp.load_chain_context(client)
    assert ctx.node_version == "Lighthouse/v5.3.0-aa11a3b"
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
        ("GET", _SPEC_TEMPLATE),
        ("GET", _GENESIS_PATH),
        ("GET", _HEADER_HEAD_PATH),
        ("GET", _FINALITY_PATH),
    ]


def test_select_endpoint_ready_node_is_exactly_two_calls(vp):
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse")
                ],
                f"GET {_SYNCING_PATH}": [raw_response(vp, "node_syncing__ready")],
            }
        )
    )
    client, _ = _client(vp, transport)
    vp.select_endpoint(client)
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
    ]
    assert client._current == 0
    assert client._selected_version == "Lighthouse/v5.3.0-aa11a3b"


def test_all_syncing_endpoints_raise_no_beacon_available(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "sync0.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "sync1.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse"),
                    raw_response(vp, "node_version__lighthouse"),
                ],
                f"GET {_SYNCING_PATH}": [
                    raw_response(vp, "node_syncing__is_syncing"),
                    raw_response(vp, "node_syncing__is_syncing"),
                ],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn0", "bn1", "bn1"]
    assert client._selected_version == ""


def test_select_endpoint_skips_nonempty_version_required(vp):
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [_raw(vp, 204, b"")],
                f"GET {_SYNCING_PATH}": [raw_response(vp, "node_syncing__ready")],
            }
        )
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[2] for c in transport.calls] == [_VERSION_TEMPLATE]
    assert client._selected_version == ""


def test_spec_is_frozen(vp):
    ctx, _, _ = _load_ctx(vp)
    with pytest.raises(FrozenInstanceError):
        ctx.spec.slots_per_epoch = 8
    with pytest.raises(FrozenInstanceError):
        ctx.spec.epochs_per_year = 1.0


def test_spec_underscored_uint_names_the_key(vp, load):
    payload = load("spec__mainnet")
    payload["data"]["SLOTS_PER_EPOCH"] = "1_000"
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert "SLOTS_PER_EPOCH" in str(ei.value)


def test_non_positive_slots_per_epoch_names_the_key(vp, load):
    payload = load("spec__mainnet")
    payload["data"]["SLOTS_PER_EPOCH"] = "0"
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert "SLOTS_PER_EPOCH" in str(ei.value)


# ----- VP-1k: §8 resolve_window -----


def _spec_from_fixture(vp, load, name="spec__mainnet"):
    raw = load(name)["data"]
    return vp.Spec(
        slots_per_epoch=int(raw["SLOTS_PER_EPOCH"]),
        seconds_per_slot=int(raw["SECONDS_PER_SLOT"]),
        epochs_per_sync_committee_period=int(raw["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"]),
        min_epochs_to_inactivity_penalty=int(raw["MIN_EPOCHS_TO_INACTIVITY_PENALTY"]),
        raw=raw,
    )


def _chain_ctx(
    vp,
    load,
    *,
    spec="spec__mainnet",
    head_epoch=100,
    finalized_epoch=97,
    head_slot=None,
):
    spec_obj = _spec_from_fixture(vp, load, spec)
    if head_slot is None:
        head_slot = head_epoch * spec_obj.slots_per_epoch
    return vp.ChainContext(
        spec=spec_obj,
        genesis_time=0,
        network_name=spec_obj.raw.get("CONFIG_NAME"),
        head_slot=head_slot,
        head_epoch=head_epoch,
        finalized_epoch=finalized_epoch,
        node_version="",
        rewards_api="",
    )


def _window_opts(vp, **kw):
    return replace(vp.build_options(_minimal_opts_argv()), **kw)


def test_default_window_is_66_to_97(vp, load):
    w = vp.resolve_window(_window_opts(vp), _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (66, 97)
    assert w.finalized_only is True
    assert w.epochs == 32


def test_allow_unfinalized_gives_67_to_98(vp, load):
    opts = _window_opts(vp, allow_unfinalized=True)
    w = vp.resolve_window(opts, _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (67, 98)
    assert w.finalized_only is False


def test_epochs_4_lookback(vp, load):
    w = vp.resolve_window(_window_opts(vp, epochs=4), _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (94, 97)
    assert w.epochs == 4
    assert len(list(w)) == 4


def test_to_epoch_equal_max_safe_is_allowed(vp, load):
    ctx = _chain_ctx(vp, load)
    w = vp.resolve_window(_window_opts(vp, to_epoch=98), ctx)
    assert w.to_epoch == 98
    assert w.from_epoch == 67
    assert w.forced_unsafe is False


def test_to_epoch_99_exits_2_naming_max_safe_epoch_98(vp, load):
    opts = _window_opts(vp, to_epoch=99)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert "MAX_SAFE_EPOCH=98" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_force_unsafe_window_downgrades_to_a_warning_and_sets_forced_unsafe(vp, load):
    ctx = _chain_ctx(vp, load)
    with pytest.raises(vp.UsageError):
        vp.resolve_window(_window_opts(vp, to_epoch=99), ctx)
    buf = io.StringIO()
    log = vp.Log(0, buf)
    opts = _window_opts(vp, to_epoch=99, force_unsafe_window=True)
    w = vp.resolve_window(opts, ctx, log)
    assert w.forced_unsafe is True
    assert w.to_epoch == 99
    assert "MAX_SAFE_EPOCH=98" in buf.getvalue()


def test_snapshot_slots_are_3232_and_4256(vp, load):
    # RD-4: from*SPE / to*SPE would be 3200 / 4192.
    ctx = _chain_ctx(vp, load, head_epoch=133, finalized_epoch=131)
    opts = _window_opts(vp, from_epoch=100, to_epoch=131)
    w = vp.resolve_window(opts, ctx)
    assert (w.from_epoch, w.to_epoch) == (100, 131)
    assert w.start_slot == 3232
    assert w.end_slot == 4256


def test_spe8_shifts_every_derived_slot(vp, load):
    ctx = _chain_ctx(
        vp, load, spec="spec__spe8", head_epoch=133, finalized_epoch=131
    )
    assert ctx.spec.slots_per_epoch == 8
    opts = _window_opts(vp, from_epoch=100, to_epoch=131)
    w = vp.resolve_window(opts, ctx)
    assert w.start_slot == (100 + 1) * 8 == 808
    assert w.end_slot == (131 + 2) * 8 == 1064


def test_from_greater_than_to_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=10, to_epoch=5)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError


def test_negative_epoch_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=-1, to_epoch=5)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError


def test_future_epoch_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=90, to_epoch=101)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError
    assert "MAX_SAFE_EPOCH" not in str(ei.value)


def test_end_slot_reachable_false_only_under_force_unsafe(vp, load):
    ctx = _chain_ctx(vp, load)
    assert vp.resolve_window(_window_opts(vp), ctx).end_slot_reachable is True
    forced = _window_opts(vp, to_epoch=99, force_unsafe_window=True)
    w = vp.resolve_window(forced, ctx, vp.Log(0, io.StringIO()))
    assert w.end_slot_reachable is False
    assert w.forced_unsafe is True


def test_window_iterates_inclusively(vp, load):
    w = vp.resolve_window(_window_opts(vp), _chain_ctx(vp, load))
    epochs = list(w)
    assert epochs == list(range(w.from_epoch, w.to_epoch + 1))
    assert len(epochs) == w.epochs == w.to_epoch - w.from_epoch + 1


# ----- VP-1l: §9 resolve_validators + ValidatorRef -----

_FAR_FUTURE_EPOCH = 2**64 - 1


def _resolve(vp, pubkeys, *, name=None, payload=None, verbosity=1):
    if name is not None:
        resp = raw_response(vp, name)
    else:
        resp = _raw(vp, 200, json.dumps(payload).encode())
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [resp]})
    client, buf = _client(vp, transport, verbosity=verbosity)
    refs = vp.resolve_validators(client, pubkeys)
    return refs, transport, buf


def test_resolve_returns_index_status_eb_and_activation_window(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK2, PK3], name="states_validators__basic"
    )
    assert len(refs) == 3
    a, b, c = refs
    assert a.pubkey == PK1
    assert a.index == 1
    assert a.status == "active_ongoing"
    assert a.effective_balance_gwei == 32_000_000_000
    assert a.activation_epoch == 0
    assert a.exit_epoch == _FAR_FUTURE_EPOCH
    assert a.slashed is False
    assert a.rewards_eligible is True
    assert b.pubkey == PK2
    assert b.index == 2
    assert b.status == "active_exiting"
    assert b.effective_balance_gwei == 2_048_000_000_000
    assert b.activation_epoch == 10
    assert b.exit_epoch == 200
    assert c.pubkey == PK3
    assert c.index == 3
    assert c.status == "pending_queued"
    assert c.effective_balance_gwei == 32_000_000_000
    assert c.activation_epoch == 500
    assert c.exit_epoch == _FAR_FUTURE_EPOCH
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == "POST"


def test_unknown_pubkey_is_null_index_unknown_status_and_run_continues(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK4, PK2], name="states_validators__unknown_pubkey"
    )
    assert [r.pubkey for r in refs] == [PK1, PK4, PK2]
    assert refs[0].index == 1
    assert refs[0].status == "active_ongoing"
    assert refs[1].index is None
    assert refs[1].status == "unknown"
    assert refs[1].effective_balance_gwei is None
    assert refs[1].activation_epoch is None
    assert refs[1].exit_epoch is None
    assert refs[1].rewards_eligible is False
    assert refs[1].is_active_at(0) is False
    assert refs[1].is_active_at(100) is False
    assert refs[1].active_epochs_in([100, 131]) == 0
    assert refs[2].index == 2
    assert refs[2].status == "active_ongoing"
    assert len(transport.calls) == 1


def test_results_keyed_by_pubkey_not_position(vp, load):
    payload = load("states_validators__basic")
    by_pk = {row["validator"]["pubkey"]: row for row in payload["data"]}
    # Neither request order nor reverse(request): zip would assign 2, 3, 1.
    order = [PK2, PK3, PK1]
    assert order != [PK1, PK2, PK3]
    assert order != list(reversed([PK1, PK2, PK3]))
    payload["data"] = [by_pk[pk] for pk in order]
    refs, _, _ = _resolve(vp, [PK1, PK2, PK3], payload=payload)
    assert [r.pubkey for r in refs] == [PK1, PK2, PK3]
    assert {r.pubkey: r.index for r in refs} == {PK1: 1, PK2: 2, PK3: 3}


def test_unrecognised_status_passes_through(vp, load):
    payload = load("states_validators__basic")
    for row in payload["data"]:
        pk = row["validator"]["pubkey"]
        if pk == PK1:
            row["status"] = "active_weird"
        elif pk == PK3:
            row["status"] = ""
    quiet, _, quiet_buf = _resolve(
        vp, [PK1, PK2, PK3], payload=payload, verbosity=0
    )
    by_pk = {r.pubkey: r for r in quiet}
    assert by_pk[PK1].status == "active_weird"
    assert by_pk[PK2].status == "active_exiting"
    assert by_pk[PK3].status == ""
    assert by_pk[PK3].status != "unknown"
    assert "active_weird" not in quiet_buf.getvalue()
    _, _, verbose_buf = _resolve(
        vp, [PK1, PK2, PK3], payload=payload, verbosity=1
    )
    text = verbose_buf.getvalue()
    assert "active_weird" in text
    assert PK1 in text


def test_is_active_at_respects_activation_and_exit(vp):
    refs, _, _ = _resolve(
        vp, [PK1], name="states_validators__mid_window_activation"
    )
    ref = refs[0]
    assert ref.activation_epoch == 116
    assert ref.is_active_at(115) is False
    assert ref.is_active_at(116) is True
    assert ref.is_active_at(131) is True
    assert ref.active_epochs_in([100, 131]) == 16
    window = type("W", (), {"from_epoch": 100, "to_epoch": 131})()
    assert ref.active_epochs_in(window) == 16
    exiting = vp.ValidatorRef(
        PK2, 2, "active_exiting", 32_000_000_000, 0, 110, False
    )
    assert exiting.is_active_at(109) is True
    assert exiting.is_active_at(110) is False
    assert exiting.active_epochs_in([100, 131]) == 10


def test_rewards_eligible_false_for_eb_zero(vp):
    payload = {
        "data": [
            {
                "index": "1",
                "balance": "0",
                "status": "pending_initialized",
                "validator": {
                    "pubkey": PK1,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "0",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": str(_FAR_FUTURE_EPOCH),
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            }
        ]
    }
    refs, _, _ = _resolve(vp, [PK1], payload=payload)
    assert refs[0].index == 1
    assert refs[0].effective_balance_gwei == 0
    assert refs[0].rewards_eligible is False
    direct = vp.ValidatorRef(
        PK1, 1, "active_ongoing", 0, 0, _FAR_FUTURE_EPOCH, False
    )
    assert direct.rewards_eligible is False


def test_resolve_empty_pubkeys_makes_zero_calls(vp):
    transport = FakeTransport({})
    client, _ = _client(vp, transport)
    assert vp.resolve_validators(client, []) == []
    assert transport.calls == []


def test_validator_ref_is_frozen(vp):
    ref = vp.ValidatorRef(
        PK1, 1, "active_ongoing", 32_000_000_000, 0, _FAR_FUTURE_EPOCH, False
    )
    with pytest.raises(FrozenInstanceError):
        ref.index = 99


def test_state_id_is_head(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK2, PK3], name="states_validators__basic"
    )
    assert refs
    assert len(transport.calls) == 1
    _label, method, path, body = transport.calls[0]
    assert method == "POST"
    assert path == "/eth/v1/beacon/states/head/validators"
    assert path == _VALIDATORS_PATH
    assert re.search(r"/states/\d+/validators", path) is None
    assert json.loads(body) == {"ids": [PK1, PK2, PK3]}


# ----- VP-1m: §7 probe_rewards_api -----

_BLOCKS_HEAD_PATH = "/eth/v1/beacon/rewards/blocks/head"


def _status_queue(vp, status, body=None):
    if body is None:
        body = b'{"data": {}}' if 200 <= status < 300 else b"{}"
    # Rewards 500 retries once (RD-9); script the second response too.
    if status == 500:
        return [_raw(vp, 500, body), _raw(vp, 500, body)]
    return [_raw(vp, status, body)]


def _probe_transport(vp, *, blocks, att, head_epoch=100, extra=None):
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    routes = {
        ("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, blocks),
        ("POST", att_path): _status_queue(vp, att),
    }
    if extra:
        routes.update(extra)
    return FakeTransport(routes), att_path


def _run_probe(vp, *, blocks, att, head_epoch=100, ids=("1",), extra=None):
    transport, _ = _probe_transport(
        vp, blocks=blocks, att=att, head_epoch=head_epoch, extra=extra
    )
    client, _ = _client(vp, transport)
    verdict = vp.probe_rewards_api(client, head_epoch, list(ids))
    return verdict, transport


def _raw_from_probe_leg(vp, leg):
    return _raw(vp, leg["status"], json.dumps(leg["body"]).encode())


def _run_probe_fixture(vp, load, name, *, head_epoch=100, ids=("1",)):
    pair = load(name)
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    transport = FakeTransport(
        {
            ("GET", _BLOCKS_HEAD_PATH): [_raw_from_probe_leg(vp, pair["blocks"])],
            ("POST", att_path): [_raw_from_probe_leg(vp, pair["attestations"])],
        }
    )
    client, _ = _client(vp, transport)
    verdict = vp.probe_rewards_api(client, head_epoch, list(ids))
    return verdict, transport


def test_probe_404_and_404_is_route_absent(vp, load):
    pair = load("probe__route_absent")
    assert pair["blocks"]["status"] == 404
    assert pair["attestations"]["status"] == 404
    verdict, transport = _run_probe_fixture(vp, load, "probe__route_absent")
    assert verdict == "route_absent"
    assert len(transport.calls) == 2


def test_probe_200_and_404_is_state_unavailable(vp, load):
    pair = load("probe__state_unavailable")
    assert pair["blocks"]["status"] == 200
    assert pair["attestations"]["status"] == 404
    verdict, transport = _run_probe_fixture(vp, load, "probe__state_unavailable")
    assert verdict == "state_unavailable"
    assert len(transport.calls) == 2


def test_probe_200_and_200_is_available(vp):
    verdict, _ = _run_probe(vp, blocks=200, att=200)
    assert verdict == "available"


def test_probe_404_blocks_but_200_attestations_is_available(vp):
    verdict, _ = _run_probe(vp, blocks=404, att=200)
    assert verdict == "available"


def test_probe_500_and_400_fold_into_state_unavailable(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    # Lodestar 500 / Nimbus 400 on attestations, even when blocks is 2xx.
    lodestar, _ = _run_probe(vp, blocks=200, att=500)
    nimbus, _ = _run_probe(vp, blocks=200, att=400)
    assert lodestar == "state_unavailable"
    assert nimbus == "state_unavailable"
    # Non-2xx + non-2xx must not collapse to route_absent (the 4-row 2xx table trap).
    both_miss, _ = _run_probe(vp, blocks=404, att=500)
    nimbus_absent, _ = _run_probe(vp, blocks=404, att=400)
    assert both_miss == "state_unavailable"
    assert nimbus_absent == "state_unavailable"


def test_probe_issues_exactly_two_requests(vp):
    verdict, transport = _run_probe(vp, blocks=200, att=200, ids=("1",))
    assert verdict == "available"
    assert len(transport.calls) == 2
    assert [c[1] for c in transport.calls] == ["GET", "POST"]
    assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
    assert json.loads(transport.calls[1][3]) == ["1"]


def test_probe_empty_ids_skips_attestations_post(vp):
    # POST [] is the unfiltered rewards form; do not script a POST so a call fails.
    for blocks, expected in ((200, "state_unavailable"), (404, "route_absent")):
        transport = FakeTransport(
            {("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, blocks)}
        )
        client, _ = _client(vp, transport)
        verdict = vp.probe_rewards_api(client, 100, [])
        assert verdict == expected
        assert len(transport.calls) == 1
        assert transport.calls[0][1] == "GET"
        assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
        assert transport.calls[0][3] is None
        assert not any(c[1] == "POST" for c in transport.calls)
        assert not any(c[3] == b"[]" for c in transport.calls)


def test_probe_attestations_204_is_not_2xx(vp):
    # Teku 204 (store not ready) unwraps to None; that is not a 2xx success.
    unavailable, t_ok = _run_probe(vp, blocks=200, att=204)
    assert unavailable == "state_unavailable"
    assert t_ok.calls[1][1] == "POST"
    absent, t_404 = _run_probe(vp, blocks=404, att=204)
    assert absent == "route_absent"
    assert t_404.calls[1][1] == "POST"


def test_probe_body_carries_a_resolved_eb_nonzero_index(vp):
    payload = {
        "data": [
            {
                "index": "10",
                "balance": "0",
                "status": "pending_initialized",
                "validator": {
                    "pubkey": PK1,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "0",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": str(_FAR_FUTURE_EPOCH),
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            },
            {
                "index": "20",
                "balance": "32000000000",
                "status": "active_ongoing",
                "validator": {
                    "pubkey": PK2,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "32000000000",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": "0",
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            },
        ]
    }
    head_epoch = 100
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [
                _raw(vp, 200, json.dumps(payload).encode())
            ],
            ("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, 200),
            ("POST", att_path): _status_queue(vp, 200),
        }
    )
    client, _ = _client(vp, transport)
    refs = vp.resolve_validators(client, [PK1, PK2])
    assert refs[0].rewards_eligible is False
    assert refs[1].rewards_eligible is True
    ids = [str(r.index) for r in refs if r.rewards_eligible]
    assert ids == ["20"]
    verdict = vp.probe_rewards_api(client, head_epoch, ids)
    assert verdict == "available"
    rewards_calls = [c for c in transport.calls if "rewards" in c[2]]
    assert len(rewards_calls) == 2
    body = json.loads(rewards_calls[1][3])
    assert body == ["20"]
    assert "10" not in body


def test_probe_uses_head_minus_two(vp):
    head_epoch = 101
    verdict, transport = _run_probe(vp, blocks=200, att=200, head_epoch=head_epoch)
    assert verdict == "available"
    assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
    assert transport.calls[1][2] == _REWARDS_TEMPLATE.format(epoch=99)
    assert "/100" not in transport.calls[1][2]
    assert "/101" not in transport.calls[1][2]
    src = inspect.getsource(vp.probe_rewards_api)
    assert "head_epoch - 2" in src
    assert "head_epoch - 1" not in src


def test_probe_non_2xx_does_not_raise(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    cases = (
        (404, 404, "route_absent"),
        (200, 404, "state_unavailable"),
        (200, 500, "state_unavailable"),
        (200, 400, "state_unavailable"),
        (404, 200, "available"),
    )
    for blocks, att, expected in cases:
        verdict, _ = _run_probe(vp, blocks=blocks, att=att)
        assert verdict == expected
        assert verdict in ("available", "route_absent", "state_unavailable")


# ----- VP-1n: §16 main + --dry-run + exits 0/2/5 -----

# headers__head slot 3232 / spec__mainnet SPE 32 → head_epoch 101; probe uses 99.
_DRY_RUN_HEAD_EPOCH = 101
_DRY_RUN_ATT_PATH = _REWARDS_TEMPLATE.format(epoch=_DRY_RUN_HEAD_EPOCH - 2)


def _dry_run_argv(*extra, url="https://bn.example:5052"):
    return [
        "--validators-config",
        str(FIXTURES / "validators__three_entries.toml"),
        "--beacon-url",
        url,
        "--dry-run",
        *extra,
    ]


def _dry_run_routes(vp, *, probe="probe__state_unavailable"):
    pair = json.loads((FIXTURES / f"{probe}.json").read_text())
    return {
        ("GET", _VERSION_TEMPLATE): [raw_response(vp, "node_version__lighthouse")],
        ("GET", _SYNCING_PATH): [raw_response(vp, "node_syncing__ready")],
        ("GET", _SPEC_TEMPLATE): [raw_response(vp, "spec__mainnet")],
        ("GET", _GENESIS_PATH): [raw_response(vp, "genesis__mainnet")],
        ("GET", _HEADER_HEAD_PATH): [raw_response(vp, "headers__head")],
        ("GET", _FINALITY_PATH): [
            raw_response(vp, "finality_checkpoints__head")
        ],
        ("POST", _VALIDATORS_PATH): [raw_response(vp, "states_validators__basic")],
        ("GET", _BLOCKS_HEAD_PATH): [_raw_from_probe_leg(vp, pair["blocks"])],
        ("POST", _DRY_RUN_ATT_PATH): [
            _raw_from_probe_leg(vp, pair["attestations"])
        ],
    }


def _run_dry_run(vp, *, probe="probe__state_unavailable", extra=(), url=None):
    transport = FakeTransport(_dry_run_routes(vp, probe=probe))
    argv = _dry_run_argv(*extra, url=url or "https://bn.example:5052")
    code = vp.main(argv, transport=transport)
    return code, transport


def test_dry_run_prints_window_endpoint_verdict_and_keys(vp, capsys):
    code, transport = _run_dry_run(vp, probe="probe__state_unavailable")
    assert code == 0
    captured = capsys.readouterr()
    out, err = captured.out, captured.err
    # table on stdout; diagnostics stay on stderr (silent at default verbosity)
    assert err == ""
    assert "window: epochs 68–99 (slots 2208, 3232)" in out
    assert "https://bn.example:5052" in out
    assert "state_unavailable" in out
    assert "Lighthouse/v5.3.0-aa11a3b" in out
    expected = (
        (PK1, "1", "active_ongoing", "32000000000"),
        (PK2, "2", "active_exiting", "2048000000000"),
        (PK3, "3", "pending_queued", "32000000000"),
    )
    for pk, index, status, eb in expected:
        matches = [ln for ln in out.splitlines() if pk in ln]
        assert len(matches) == 1, pk
        line = matches[0]
        assert index in line
        assert status in line
        assert eb in line
        assert line not in err
    # architecture §7: probe body is the first rewards_eligible index only
    att_posts = [
        c for c in transport.calls if c[1] == "POST" and "rewards/attestations" in c[2]
    ]
    assert len(att_posts) == 1
    assert json.loads(att_posts[0][3]) == ["1"]


def test_dry_run_exits_0(vp, capsys):
    code, transport = _run_dry_run(vp)
    assert code == vp.EXIT_OK == 0
    assert transport.calls
    capsys.readouterr()


def test_usage_error_exits_2(vp, capsys):
    code = vp.main([])
    assert code == vp.EXIT_USAGE == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "pubkey" in captured.err.lower()


def test_no_beacon_exits_5(vp, capsys):
    transport = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_raw(vp, 404)]}
    )
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.out
    assert "https://" not in captured.err
    assert captured.err.strip() != ""


def test_unexpected_exception_exits_1_without_traceback_on_stdout(vp, capsys):
    transport = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_boom(RuntimeError("boom"))]}
    )
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_ERROR == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "boom" in captured.err


def test_bootstrap_failure_exits_5_not_3(vp, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    routes = _dry_run_routes(vp)
    routes[("GET", _SPEC_TEMPLATE)] = [_raw(vp, 500), _raw(vp, 500)]
    transport = FakeTransport(routes)
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    assert code != vp.EXIT_DEGRADED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.out
    assert "HTTP 500" in captured.err
    assert _SPEC_TEMPLATE in captured.err
    assert "(500," not in captured.err
    assert "https://" not in captured.err


def test_probe_404_does_not_exit_5(vp, capsys):
    code, _transport = _run_dry_run(vp, probe="probe__route_absent")
    assert code == vp.EXIT_OK == 0
    captured = capsys.readouterr()
    assert "route_absent" in captured.out
    assert "route_absent" not in captured.err


def test_dry_run_leaks_no_secret(vp, capsys):
    code, _transport = _run_dry_run(
        vp, extra=("-v",), url=_SECRET_URL
    )
    assert code == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "https://bn.example:5052" in captured.out
    assert "window:" in captured.out
    assert "via https://bn.example:5052" in captured.err
    assert "GET" not in captured.out


def test_transport_closed_on_every_path(vp, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    success = FakeTransport(_dry_run_routes(vp))
    assert vp.main(_dry_run_argv(), transport=success) == 0
    assert success.closed is True

    boom = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_boom(RuntimeError("boom"))]}
    )
    assert vp.main(_dry_run_argv(), transport=boom) == vp.EXIT_ERROR
    assert boom.closed is True

    usage = FakeTransport(_dry_run_routes(vp))
    assert vp.main(_dry_run_argv("--to-epoch", "100"), transport=usage) == (
        vp.EXIT_USAGE
    )
    assert usage.closed is True
    capsys.readouterr()


def test_main_body_has_no_metric_logic():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# ===== § 16\. main =====(.*)$",
        source,
        re.DOTALL,
    )
    assert match is not None
    body = match.group(1)
    for token in (
        "participation",
        "estimated_apr",
        "flag_actual",
        "flag_ideal",
        "rewards_gwei",
        "inactivity_gwei",
        "consensus_reward",
        "collect_attestations",
        "evaluate_epoch",
        "BALANCE_TOLERANCE",
    ):
        assert token not in body
    for name in (
        "build_options",
        "select_endpoint",
        "load_chain_context",
        "resolve_window",
        "resolve_validators",
        "probe_rewards_api",
        "_render_dry_run",
        "replace(",
    ):
        assert name in body
    order = [
        "select_endpoint",
        "load_chain_context",
        "resolve_window",
        "resolve_validators",
        "probe_rewards_api",
    ]
    positions = [body.index(name) for name in order]
    assert positions == sorted(positions)

