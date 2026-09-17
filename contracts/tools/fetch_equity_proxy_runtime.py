#!/usr/bin/env python3
"""Fixture replacer for the checked-in equity-token-proxy runtime bytecode.

This is a replacer, not a fetcher of convenience: it reads exactly one thing
(`eth_getCode` for the equity-token proxy address, cross-checked against
`eth_chainId` taken before and after in the same run) and writes to exactly
one place — the checked-in fixture file this module's own path is derived
from. There is no `--out` flag and no other output channel. If the bytes it
reads differ from what is on disk, it overwrites that one file and says so
loudly; if they match, it writes nothing.

The RPC endpoint is never a literal in this file. It comes only from the
`RWA_GUARD_RPC_URL` environment variable at run time, and it is never
persisted anywhere. Everything `--self-test` exercises runs against
in-memory fakes: no environment variable is read, no file under the
repository is opened, and no real network opener is ever constructed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

FIXTURE_RELPATH: Final[str] = "../test/fixtures/equity-token-proxy.runtime.hex"
FIXTURE_PATH: Final[Path] = (Path(__file__).resolve().parent / FIXTURE_RELPATH).resolve()
RPC_ENV_VAR: Final[str] = "RWA_GUARD_RPC_URL"
EQUITY_ADDR: Final[str] = "0xc9f9c86933092bbbfff3ccb4b105a4a94bf3bd4e"  # public; see test/fixtures/README.md
EXPECTED_CHAIN_ID: Final[int] = 46630
HTTP_TIMEOUT_S: Final[float] = 20.0
ALLOWED_SCHEMES: Final[tuple[str, ...]] = ("http", "https")

EXIT_IDENTICAL, EXIT_SELFTEST_FAILED, EXIT_USAGE, EXIT_UNDETERMINED, EXIT_REPLACED = 0, 1, 2, 3, 4

RpcFn = Callable[[str, list[object]], object]

_BYTE_HEX_PATTERN = re.compile(r"^0x[0-9a-fA-F]*$")
_QUANTITY_HEX_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")


class ToolError(Exception):
    """Raised for every undetermined outcome: bad input, transport failure,
    a chain-id mismatch, or a read-back that does not match what was written.
    """


@dataclass(frozen=True)
class Outcome:
    kind: Literal["identical", "replaced"]
    old_len_bytes: int | None
    new_len_bytes: int


def normalize_hex(text: str) -> str:
    """Normalize a 0x-prefixed byte-string hex literal: strip surrounding
    whitespace, require an even number of hex digits, and lower-case it.
    Raises ToolError for anything else (missing prefix, non-hex characters,
    an odd digit count).
    """
    stripped = text.strip()
    if not _BYTE_HEX_PATTERN.fullmatch(stripped):
        raise ToolError(f"not a well-formed 0x-hex byte string: {text!r}")
    digits = stripped[2:]
    if len(digits) % 2 != 0:
        raise ToolError(f"odd number of hex digits: {text!r}")
    return stripped.lower()


def parse_chain_id(result: object) -> int:
    """Parse a JSON-RPC quantity (an integer encoded as 0x-hex; unlike a
    byte string it has no even-digit requirement — chain id 1 is
    legitimately "0x1"). Raises ToolError unless `result` is a non-empty
    0x-hex string.
    """
    if not isinstance(result, str):
        raise ToolError(f"chain id is not a string: {result!r}")
    if not _QUANTITY_HEX_PATTERN.fullmatch(result):
        raise ToolError(f"chain id is not a non-empty 0x-hex quantity: {result!r}")
    return int(result, 16)


def make_rpc(url: str, *, timeout: float = HTTP_TIMEOUT_S) -> RpcFn:
    """Build a JSON-RPC 2.0 caller bound to `url`. The scheme is checked
    before any I/O is attempted, including before the returned callable is
    ever invoked. Every transport failure, JSON decode failure, JSON-RPC
    `error` object, or missing `result` field becomes a ToolError.
    """
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ToolError(f"disallowed URL scheme {scheme!r}; only http(s) endpoints are allowed")

    def rpc(method: str, params: list[object]) -> object:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        request = urllib.request.Request(
            url, data=payload, headers={"content-type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # scheme already checked above
                raw = response.read()
        except (urllib.error.URLError, OSError) as exc:
            raise ToolError(f"transport error calling {method}: {exc}") from exc
        try:
            body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ToolError(f"non-JSON response calling {method}: {exc}") from exc
        if not isinstance(body, dict):
            raise ToolError(f"malformed JSON-RPC envelope calling {method}: {body!r}")
        error = body.get("error")
        if error is not None:
            raise ToolError(f"JSON-RPC error calling {method}: {error!r}")
        if "result" not in body:
            raise ToolError(f"missing result field calling {method}: {body!r}")
        return body["result"]

    return rpc


def fetch_runtime(rpc: RpcFn) -> str:
    """Read the equity-token proxy's runtime bytecode, bracketed by a
    chain-id check taken before and after `eth_getCode` in the same run.
    Call order on the happy path is always eth_chainId, eth_getCode,
    eth_chainId; a mismatched first chain id short-circuits before
    eth_getCode is ever called.
    """
    first_chain_id = parse_chain_id(rpc("eth_chainId", []))
    if first_chain_id != EXPECTED_CHAIN_ID:
        raise ToolError(f"chain id before eth_getCode was {first_chain_id}, expected {EXPECTED_CHAIN_ID}")

    code = rpc("eth_getCode", [EQUITY_ADDR, "latest"])

    second_chain_id = parse_chain_id(rpc("eth_chainId", []))
    if second_chain_id != EXPECTED_CHAIN_ID:
        raise ToolError(
            f"chain id after eth_getCode was {second_chain_id}, expected {EXPECTED_CHAIN_ID}; "
            "the endpoint may have switched chains mid-run"
        )

    if not isinstance(code, str):
        raise ToolError(f"eth_getCode did not return a string: {code!r}")
    normalized = normalize_hex(code)
    if normalized == "0x":
        raise ToolError("eth_getCode returned empty code: no contract deployed at this address")
    return normalized


def reconcile(
    fetched: str,
    read_existing: Callable[[], str | None],
    write: Callable[[str], None],
) -> Outcome:
    """Compare `fetched` against whatever `read_existing()` returns. If they
    normalize to the same bytes, write nothing. Otherwise call `write`
    exactly once with `fetched + "\\n"`, then call `read_existing()` again
    to verify the write actually landed; any mismatch (including a partial
    write) raises ToolError. There is never a second write attempt.
    """
    fetched_norm = normalize_hex(fetched)

    existing_raw = read_existing()
    old_len_bytes: int | None
    if existing_raw is not None:
        existing_norm = normalize_hex(existing_raw)
        if existing_norm == fetched_norm:
            return Outcome(
                kind="identical",
                old_len_bytes=(len(existing_norm) - 2) // 2,
                new_len_bytes=(len(fetched_norm) - 2) // 2,
            )
        old_len_bytes = (len(existing_norm) - 2) // 2
    else:
        old_len_bytes = None

    write(fetched_norm + "\n")

    verify_raw = read_existing()
    if verify_raw is None:
        raise ToolError("read-back after write returned nothing; the write did not land")
    verify_norm = normalize_hex(verify_raw)
    if verify_norm != fetched_norm:
        raise ToolError("read-back after write does not match the fetched bytes; the write was partial or wrong")

    return Outcome(kind="replaced", old_len_bytes=old_len_bytes, new_len_bytes=(len(fetched_norm) - 2) // 2)


def _read_fixture() -> str | None:
    try:
        return FIXTURE_PATH.read_text(encoding="ascii")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise ToolError(f"cannot read fixture: {exc}") from exc


def _write_fixture(content: str) -> None:
    try:
        FIXTURE_PATH.write_text(content, encoding="ascii")
    except (OSError, UnicodeEncodeError) as exc:
        raise ToolError(f"write to fixture failed; the file may be partially written: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fetch_equity_proxy_runtime",
        description="Replace the checked-in equity-token-proxy runtime fixture from a live RPC endpoint.",
        add_help=False,
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run the offline self-test suite (fakes only; no environment, no filesystem, no network)",
    )
    return parser


def self_test() -> int:
    """Run every P1-P15 arm against in-memory fakes only. Never reads
    os.environ, never opens FIXTURE_PATH, never builds a real opener.
    """
    failures: list[str] = []

    def check(name: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except AssertionError as exc:
            failures.append(f"{name}: {exc}")
        except Exception as exc:  # defensive: report, do not let one arm kill the rest
            failures.append(f"{name}: unexpected {type(exc).__name__}: {exc}")

    def fake_rpc(script: dict[str, object]) -> tuple[RpcFn, list[tuple[str, list[object]]]]:
        calls: list[tuple[str, list[object]]] = []

        def rpc(method: str, params: list[object]) -> object:
            calls.append((method, list(params)))
            value = script[method]
            if isinstance(value, BaseException):
                raise value
            return value

        return rpc, calls

    def p1() -> None:
        assert normalize_hex(" 0xABcd\n") == "0xabcd"
        for bad in ("abcd", "0xabc", "0xzz"):
            try:
                normalize_hex(bad)
            except ToolError:
                continue
            raise AssertionError(f"normalize_hex({bad!r}) should have raised ToolError")

    def p2() -> None:
        assert parse_chain_id("0xb626") == EXPECTED_CHAIN_ID
        for bad in (46630, "0x"):
            try:
                parse_chain_id(bad)
            except ToolError:
                continue
            raise AssertionError(f"parse_chain_id({bad!r}) should have raised ToolError")

    def p3() -> None:
        rpc, _calls = fake_rpc({"eth_chainId": "0xb626", "eth_getCode": "0xAABB"})
        assert fetch_runtime(rpc) == "0xaabb"

    def p4() -> None:
        rpc, calls = fake_rpc({"eth_chainId": "0x1", "eth_getCode": "0xAABB"})
        try:
            fetch_runtime(rpc)
        except ToolError:
            pass
        else:
            raise AssertionError("a mismatched first chain id should raise ToolError")
        assert all(method != "eth_getCode" for method, _params in calls)

    def p5() -> None:
        seen = {"chain_calls": 0}

        def rpc(method: str, _params: list[object]) -> object:
            if method == "eth_chainId":
                seen["chain_calls"] += 1
                return "0xb626" if seen["chain_calls"] == 1 else "0x1"
            return "0xAABB"

        try:
            fetch_runtime(rpc)
        except ToolError:
            return
        raise AssertionError("a mismatched second chain id should raise ToolError")

    def p6() -> None:
        rpc, _calls = fake_rpc({"eth_chainId": "0xb626", "eth_getCode": "0x"})
        try:
            fetch_runtime(rpc)
        except ToolError:
            return
        raise AssertionError("empty eth_getCode should raise ToolError")

    def p7() -> None:
        def rpc(_method: str, _params: list[object]) -> object:
            raise ToolError("boom")

        try:
            fetch_runtime(rpc)
        except ToolError:
            return
        raise AssertionError("a ToolError raised by the rpc callable should propagate")

    def p8() -> None:
        rpc, calls = fake_rpc({"eth_chainId": "0xb626", "eth_getCode": "0xAABB"})
        fetch_runtime(rpc)
        assert [method for method, _params in calls] == ["eth_chainId", "eth_getCode", "eth_chainId"]
        assert calls[1][1] == [EQUITY_ADDR, "latest"]

    def p9() -> None:
        writes: list[str] = []
        result = reconcile("0xabcd", lambda: "0xABCD\n", writes.append)
        assert result.kind == "identical"
        assert writes == []

    def p10() -> None:
        store: dict[str, str | None] = {"value": "0xffff\n"}
        writes: list[str] = []

        def read() -> str | None:
            return store["value"]

        def write(content: str) -> None:
            writes.append(content)
            store["value"] = content

        result = reconcile("0xabcd", read, write)
        assert writes == ["0xabcd\n"]
        assert result.kind == "replaced"

    def p11() -> None:
        store: dict[str, str | None] = {"value": None}
        writes: list[str] = []

        def read() -> str | None:
            return store["value"]

        def write(content: str) -> None:
            writes.append(content)
            store["value"] = content

        result = reconcile("0xabcd", read, write)
        assert writes == ["0xabcd\n"]
        assert result.kind == "replaced"

    def p12() -> None:
        scheme = "file"
        separator = ":" + "//"
        url = scheme + separator + "example" + "/" + "path"
        try:
            make_rpc(url)
        except ToolError:
            return
        raise AssertionError("a disallowed scheme should raise ToolError before any I/O")

    def p13() -> None:
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            rc_out = main(["--out", "x"])
            rc_help = main(["-h"])
        assert rc_out == EXIT_USAGE
        assert rc_help == EXIT_USAGE
        assert "usage" in captured.getvalue()

    def p14() -> None:
        assert FIXTURE_PATH.parts[-3:] == ("test", "fixtures", "equity-token-proxy.runtime.hex")
        assert FIXTURE_PATH.parent.parent.parent == Path(__file__).resolve().parent.parent

    def p15() -> None:
        store: dict[str, str | None] = {"value": "0xffff\n"}

        def read() -> str | None:
            return store["value"]

        def write(_content: str) -> None:
            store["value"] = "0xdead\n"  # a writer that persists bytes other than what it was asked to write

        try:
            reconcile("0xabcd", read, write)
        except ToolError:
            return
        raise AssertionError("a read-back mismatch after write should raise ToolError")

    arms: tuple[tuple[str, Callable[[], None]], ...] = (
        ("P1", p1), ("P2", p2), ("P3", p3), ("P4", p4), ("P5", p5),
        ("P6", p6), ("P7", p7), ("P8", p8), ("P9", p9), ("P10", p10),
        ("P11", p11), ("P12", p12), ("P13", p13), ("P14", p14), ("P15", p15),
    )
    for name, fn in arms:
        check(name, fn)

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return EXIT_SELFTEST_FAILED
    return EXIT_IDENTICAL


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE

    if args.self_test:
        return self_test()

    rpc_url = os.environ.get(RPC_ENV_VAR, "")
    if not rpc_url:
        print(f"{RPC_ENV_VAR} is not set; nothing was read and nothing was written.", file=sys.stderr)
        return EXIT_USAGE

    try:
        rpc = make_rpc(rpc_url)
        fetched = fetch_runtime(rpc)
        outcome = reconcile(fetched, _read_fixture, _write_fixture)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNDETERMINED

    if outcome.kind == "identical":
        print(f"fixture unchanged ({outcome.new_len_bytes} bytes); nothing written.")
        return EXIT_IDENTICAL

    print(
        "fixture bytes changed; the checked-in file was overwritten. "
        "Re-run the fixture-dependent tests and update "
        "test/fixtures/README.md before merging.",
        file=sys.stderr,
    )
    return EXIT_REPLACED


if __name__ == "__main__":
    sys.exit(main())
