"""Prelude tests for scripts/validator_perf.py (VP-1a).

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import ast
import importlib.util
import io
import re
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "validator_perf.py"


def load_vp():
    spec = importlib.util.spec_from_file_location("validator_perf", SCRIPT)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def vp():
    return load_vp()


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
