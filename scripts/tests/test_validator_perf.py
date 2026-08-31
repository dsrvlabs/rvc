"""Tests for scripts/validator_perf.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import ast
import base64
import inspect
import io
import re
import socket
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

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
    transport = FakeTransport({("GET", "/eth/v1/node/syncing"): [vp.RawResponse(200, b"", False)]})
    with pytest.raises(KeyError):
        transport(ep, "GET", "/unscripted", None)
    assert transport(ep, "GET", "/eth/v1/node/syncing", None).status == 200
    with pytest.raises(IndexError):
        transport(ep, "GET", "/eth/v1/node/syncing", None)


def test_faketransport_satisfies_the_transport_alias(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    body = vp.RawResponse(200, b"{}", False)
    transport = FakeTransport({("GET", "/x"): [body]})
    assert list(inspect.signature(transport).parameters) == ["ep", "method", "path", "body"]
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
    assert _load_pubkeys(
        vp,
        ["--pubkey", PK4, "--pubkeys-file", pubfile, "--validators-config", toml],
    ) == expected
    # Argv order must not change operand order; second --pubkey is append + de-dup.
    assert _load_pubkeys(
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
    ) == expected


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
