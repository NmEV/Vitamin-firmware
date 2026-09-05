#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple stress test tool for the usbnet web service.

Targets the Pico's web server (default 192.168.7.1:80), which exposes:
    POST /write   persist a JSON form (fields: name, value) to flash (<= 2 KiB);
                  the success response returns the pk/sk (hex) receipt that
                  sealed the record
    GET  /print   return the stored data
    POST /clear   erase the stored data, but only with the exact pk/sk receipt
                  returned by the /write of the current record (wrong keys ->
                  403, data untouched; empty record -> 200 no-op; GET -> 405)

Modes:
    cycle (default)  one full cycle per iteration: POST /write with random
                     payload, then GET /print, verify what came back equals
                     the payload that was written.
    write            POST /write only (raw write throughput).
    print            GET /print only.
    clear            POST /clear with the receipt: the keys returned by the
                     last /write of this run, or --pk/--sk for a receipt from
                     an earlier session.

The tool always remembers the pk/sk receipt of its last successful /write, so
a plain "python stress_test.py --mode clear" wipes whatever this run wrote.

Verification of the returned data is only meaningful with a single worker
(--workers 1); with more workers the shared storage is contended and
mismatches are counted separately as "contended".

Examples:
    python stress_test.py                     # 100 cycles, 1 worker
    python stress_test.py -n 500 -s 512       # 500 cycles, 512-byte values
    python stress_test.py -n 2000 -w 4 --mode write
    python stress_test.py --host 192.168.7.1 --port 80 -v

Dependencies: Python 3.8+ standard library only (urllib).
"""

import argparse
import json
import random
import statistics
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import error as uerr
from urllib import request as ureq

VALUE_CHARS = string.ascii_letters + string.digits
# Kept away from '"' and '\\': the server re-serialises the extracted fields
# and escapes those characters, so a strict byte-for-byte comparison would
# otherwise fail on them.
# NOTE on the 2 KiB limit: the server's cap applies to the STORED JSON
# (field names + quotes + braces included), which is ~29 bytes longer than the
# value itself for the payload this tool sends. Hence a value of 2048+ chars is
# rejected with 413 even though it is "2 KiB"; find_max_value_len() probes the
# real boundary at preflight time.


def http_call(base, method, path, body=None, timeout=10):
    """Perform one HTTP request; returns (status_code, response_bytes).

    Performs a plain urllib call, catching HTTP error responses (4xx/5xx),
    which urllib raises as HTTPError. Network/connection errors propagate.
    """
    data = body.encode("utf-8") if body is not None else None
    req = ureq.Request(
        base + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with ureq.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except uerr.HTTPError as e:
        return e.code, e.read()


def valid_json(body):
    """True when body decodes and parses as exactly one JSON document.

    json.loads() rejects trailing junk and raw control characters, so this is
    a good regression check for the server's response framing: error bodies
    used to carry extra bytes because their Content-Length was hand-counted
    too long, which left stray NULs / adjacent-string bytes at the end.
    """
    try:
        json.loads(body.decode("utf-8"))
        return True
    except Exception:
        return False


# pk/sk receipt returned by the last successful /write. POST /clear only
# erases a valid record when the body carries exactly this pair (the device
# compares it against the keys stored in the record header); wrong or missing
# keys are refused with 403/400 and the data stays intact.
LAST_PK = None
LAST_SK = None
LAST_LOCK = threading.Lock()


def parse_write_receipt(body):
    """Remember the pk/sk receipt from a /write response, if present."""
    global LAST_PK, LAST_SK
    try:
        doc = json.loads(body.decode("utf-8"))
        pk, sk = doc.get("pk"), doc.get("sk")
        if isinstance(pk, str) and isinstance(sk, str) and len(pk) == 64 and len(sk) == 64:
            with LAST_LOCK:
                LAST_PK, LAST_SK = pk, sk
            return True
    except Exception:
        pass
    return False


def clear_body(pk=None, sk=None):
    """JSON body for POST /clear, or None when no receipt is available."""
    if pk and sk:
        return json.dumps({"pk": pk, "sk": sk}, separators=(",", ":"))
    return None


def check_escape_roundtrip(base, timeout):
    """/write then /print must round-trip JSON-escaped values byte for byte.

    Regression check: the server used to decode only the backslash of an
    escape (so a value sent with an escaped newline was stored with a literal
    'n', silently losing the newline) and dropped control characters when
    re-encoding. The value below mixes every named escape the server accepts
    (double quote, backslash, slash, backspace, form feed, newline, carriage
    return, tab) with plain characters; /print must return exactly the request
    body. The server deliberately rejects \\uXXXX escapes on input (400), so
    none are used here.
    """
    value = "a\nb\t\"q\\s\r\f\b"
    payload = json.dumps({"name": "n12345678", "value": value},
                         separators=(",", ":"), ensure_ascii=False)
    status, body = http_call(base, "POST", "/write", payload, timeout)
    if status != 200:
        return False, f"escape write -> {status} {body!r}"
    parse_write_receipt(body)
    status, body = http_call(base, "GET", "/print", None, timeout)
    if status != 200:
        return False, f"escape read -> {status} {body!r}"
    if body.decode("utf-8", "replace") != payload:
        return False, f"round-trip mismatch: sent {payload!r}, got {body!r}"
    return True, None


NAME_LEN = 9  # "n" + 8 random chars, matches make_payload() below


def make_payload(value_len):
    """A compact JSON object with exactly the fields the server extracts."""
    name = "n" + "".join(random.choice(VALUE_CHARS) for _ in range(NAME_LEN - 1))
    value = "".join(random.choice(VALUE_CHARS) for _ in range(value_len))
    return json.dumps({"name": name, "value": value}, separators=(",", ":"))


def find_max_value_len(base, timeout=10):
    """Largest value length for which /write returns 200 (binary search).

    The server rejects a payload with 413 once the STORED JSON exceeds 2 KiB
    (and 413 once the whole request exceeds its receive buffer), so mid-size
    values can be probed cheaply with ~12 requests. Returns the boundary.
    """
    def works(v):
        try:
            status, body = http_call(base, "POST", "/write", make_payload(v), timeout)
            if status == 200:
                parse_write_receipt(body)  # keep the receipt of the latest write
            return status == 200
        except Exception:
            return False

    low, high = 1, 4096  # low must succeed, high must fail
    assert works(low), "preflight: even a 1-char write fails - server broken?"
    assert not works(high), "preflight: 4096-char write unexpectedly accepted"
    while high - low > 1:
        mid = (low + high) // 2
        if works(mid):
            low = mid
        else:
            high = mid
    return low


class Tally:
    """Thread-safe collection of per-operation latencies and failures."""

    def __init__(self):
        self.lock = threading.Lock()
        self.lat = {}      # op -> list[ms]
        self.errors = {}   # reason -> count
        self.counts = {}   # op -> executed count
        self.ok = 0
        self.mismatch = 0  # write/readback mismatch
        self.contended = 0 # mismatch under concurrency

    def add(self, op, ms, ok=True, error=None):
        with self.lock:
            self.lat.setdefault(op, []).append(ms)
            self.counts[op] = self.counts.get(op, 0) + 1
            if ok:
                self.ok += 1
            elif error is not None:
                self.errors[error] = self.errors.get(error, 0) + 1

    def mismatch_seen(self, contended):
        with self.lock:
            if contended:
                self.contended += 1
            else:
                self.mismatch += 1


def run_cycle(args, base, tally, contended):
    """One full write -> print -> verify cycle. Returns None."""
    payload = make_payload(args.size)
    t0 = time.perf_counter()
    try:
        status, body = http_call(base, "POST", "/write", payload, args.timeout)
    except Exception as e:
        tally.add("write", 0, ok=False, error=f"write: {e}")
        return
    ms = (time.perf_counter() - t0) * 1000.0
    ok = status == 200 and b'"status":"ok"' in body
    if ok:
        parse_write_receipt(body)
    tally.add("write", ms, ok=ok, error=None if ok else f"write={status}")

    t0 = time.perf_counter()
    try:
        status, body = http_call(base, "GET", "/print", None, args.timeout)
    except Exception as e:
        tally.add("print", 0, ok=False, error=f"print: {e}")
        return
    ms = (time.perf_counter() - t0) * 1000.0
    ok = status == 200
    tally.add("print", ms, ok=ok, error=None if ok else f"print={status}")

    if ok and status == 200:
        if body.decode("utf-8", "replace") == payload:
            pass  # good
        else:
            tally.mismatch_seen(contended)


def run_single(args, base, tally, op):
    """One single-operation request (write / print / clear)."""
    if op == "write":
        body = make_payload(args.size)
        path, method, req_body = "/write", "POST", body
    elif op == "print":
        path, method, req_body = "/print", "GET", None
    else:  # clear: destructive, so it is POST-only and needs the receipt
        path, method = "/clear", "POST"
        with LAST_LOCK:
            pk, sk = args.pk or LAST_PK, args.sk or LAST_SK
        req_body = clear_body(pk, sk)

    t0 = time.perf_counter()
    try:
        status, resp = http_call(base, method, path, req_body, args.timeout)
    except Exception as e:
        tally.add(op, 0, ok=False, error=f"{op}: {e}")
        return
    ms = (time.perf_counter() - t0) * 1000.0
    ok = status == 200
    if ok and op == "write":
        parse_write_receipt(resp)
    tally.add(op, ms, ok=ok, error=None if ok else f"{op}={status}")


def preflight_checks(base, args, tally):
    """Verify the server is reachable and the key-protected /clear contract.

    Runs: checks that GET /clear is refused (405), writes a probe record and
    checks that /clear with wrong keys is refused (403) while the data stays
    intact, that /clear with the exact receipt wipes the record, that a second
    /clear on the now-empty slot is an idempotent no-op, that a 404 comes back
    as one clean JSON document, verifies JSON-escape round-trips (single
    worker), probes the largest accepted value length, then checks that /write
    rejects a value beyond it with a clean 413. Any record present at startup
    (whose receipt this run does not know) is overwritten by the probe write.
    Returns (ok, max_value_len).
    """
    ok_all = True

    # GET /print only exists in firmware built with DEBUG=1 (tusb_config.h).
    # Detect a DEBUG=0 build up front, so the rest of the checks do not turn
    # into a wall of confusing 404 failures.
    status, _ = http_call(base, "GET", "/print", None, args.timeout)
    if status == 404:
        print("[Preflight] FAIL: firmware has no /print endpoint (tusb_config.h "
              "DEBUG=0); set DEBUG=1 and reflash to run this tool")
        return False, None

    # A stray GET must never wipe the record: it is answered 405.
    status, _ = http_call(base, "GET", "/clear", None, args.timeout)
    if status != 405:
        ok_all = False
        print(f"[Preflight] FAIL: GET /clear -> {status} (expected 405)")

    # A record from an earlier session cannot be cleared (its receipt was not
    # kept); the probe write below overwrites it instead.
    status, body = http_call(base, "GET", "/print", None, args.timeout)
    if status == 200 and body != b'{"status":"empty"}':
        print("[Preflight]  note: existing record overwritten by the probe write")

    # Probe write: the response must carry the pk/sk receipt.
    probe = make_payload(16)
    status, body = http_call(base, "POST", "/write", probe, args.timeout)
    if status != 200 or not parse_write_receipt(body):
        ok_all = False
        print(f"[Preflight] FAIL: /write without key-pair receipt -> {status} {body!r}")
    else:
        # Wrong keys: 403, and the record must be untouched afterwards.
        status, body = http_call(base, "POST", "/clear",
                                 clear_body("0" * 64, "1" * 64), args.timeout)
        if status != 403:
            ok_all = False
            print(f"[Preflight] FAIL: /clear with wrong keys -> {status} (expected 403) {body!r}")
        status, body = http_call(base, "GET", "/print", None, args.timeout)
        if status != 200 or body.decode("utf-8", "replace") != probe:
            ok_all = False
            print(f"[Preflight] FAIL: rejected /clear altered the data -> {status} {body!r}")

        # The exact receipt wipes the record...
        with LAST_LOCK:
            cur_pk, cur_sk = LAST_PK, LAST_SK
        status, body = http_call(base, "POST", "/clear",
                                 clear_body(cur_pk, cur_sk), args.timeout)
        if status != 200:
            ok_all = False
            print(f"[Preflight] FAIL: /clear with the receipt -> {status} (expected 200) {body!r}")
        status, body = http_call(base, "GET", "/print", None, args.timeout)
        empty = status == 200 and b'"status":"empty"' in body
        if not empty:
            ok_all = False
            print(f"[Preflight] FAIL: /print after authorized /clear -> {status} {body!r}")

        # ...and a second clear on the now-empty slot is an idempotent no-op.
        status, body = http_call(base, "POST", "/clear",
                                 clear_body(cur_pk, cur_sk), args.timeout)
        if status != 200:
            ok_all = False
            print(f"[Preflight] FAIL: repeated /clear on empty slot -> {status} (expected 200) {body!r}")

    # A 404 must come back as one clean, parseable JSON document.
    status, body = http_call(base, "GET", "/definitely-not-a-route", None, args.timeout)
    if status != 404 or not valid_json(body):
        ok_all = False
        print(f"[Preflight] FAIL: 404 body is not clean JSON -> {status} {body!r}")

    # Escaped values must survive /write -> /print unchanged. Only meaningful
    # with a single worker (the shared storage is contended otherwise).
    if args.workers == 1:
        ok, msg = check_escape_roundtrip(base, args.timeout)
        if not ok:
            ok_all = False
            print(f"[Preflight] FAIL: escape round-trip: {msg}")

    max_val = find_max_value_len(base, args.timeout)
    stored_overhead = 29  # {"name":"n12345678","value":"...",""} minus the value
    print(f"[Preflight]  max accepted value length ~ {max_val}"
          f" (stored JSON limit 2048 bytes = value + ~{stored_overhead} bytes overhead)")

    # One value above the boundary must be rejected with a clean 413 body.
    big = make_payload(max_val + 64)
    status, body = http_call(base, "POST", "/write", big, args.timeout)
    if status != 413:
        ok_all = False
        print(f"[Preflight] FAIL: oversized /write -> {status} (expected 413) {body!r}")
    elif not valid_json(body):
        ok_all = False
        print(f"[Preflight] FAIL: oversized /write 413 body is not clean JSON -> {body!r}")
    else:
        print(f"[Preflight]  oversized /write rejected with 413 (expected, "
              f"part of the limit check)")

    if not ok_all:
        print("[Preflight] preflight checks failed; aborting run")
    return ok_all, max_val


def summarize(args, tally, wall, total_ops, max_val=None):
    def pct(op, p):
        lat = sorted(tally.lat.get(op, []))
        if not lat:
            return "-"
        idx = min(len(lat) - 1, int((p / 100.0) * len(lat)))
        return f"{lat[idx]:.1f}ms"

    print()
    print("=" * 62)
    print(f"  mode={args.mode}  iterations={args.iters}  workers={args.workers}"
          f"  value_len={args.size}"
          + (f"  (max accepted ~ {max_val})" if max_val else ""))
    print(f"  wall={wall:.2f}s  total_requests={total_ops}")
    for op in ("write", "print", "clear"):
        n = tally.counts.get(op, 0)
        if not n:
            continue
        lat = tally.lat[op]
        print(f"  {op:6s} n={n:5d}  ok/req={tally.counts.get(op):5d}"
              f"  avg={statistics.mean(lat):.2f}ms"
              f"  min={min(lat):.2f}ms  max={max(lat):.2f}ms"
              f"  p50={pct(op, 50)}  p95={pct(op, 95)}")
    print(f"  throughput={total_ops / wall:.1f} req/s   ok={tally.ok}"
          f"   mismatch={tally.mismatch}   contended={tally.contended}")
    if tally.errors:
        print(f"  errors ({sum(tally.errors.values())})")
        for reason, count in sorted(tally.errors.items()):
            print(f"      {count:5d}  {reason}")
    if any("413" in r for r in tally.errors):
        print("  NOTE: a 413 during the run means a write exceeded the server's")
        print("        2 KiB stored-JSON limit; lower --size and rerun.")
    print("=" * 62)


def main():
    ap = argparse.ArgumentParser(description="usbnet web service stress test")
    ap.add_argument("--host", default="192.168.7.1", help="Pico address (default 192.168.7.1)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("-n", "--n", type=int, default=100, dest="iters", help="iterations (default 100)")
    ap.add_argument("-w", "--workers", type=int, default=1, help="concurrent workers (default 1)")
    ap.add_argument("-s", "--size", type=int, default=100,
                    help="value length per write (default 100; the accepted "
                         "maximum is 2017 chars, probed exactly at preflight)")
    ap.add_argument("--mode", choices=["cycle", "write", "print", "clear"], default="cycle")
    ap.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (seconds)")
    ap.add_argument("--pk", default=None,
                    help="public-key half of a /write receipt (64 hex chars); "
                         "POST /clear needs it to erase a valid record")
    ap.add_argument("--sk", default=None,
                    help="secret-key half of a /write receipt (64 hex chars); "
                         "POST /clear needs it to erase a valid record")
    ap.add_argument("--no-preflight", action="store_true",
                    help="skip the /clear-contract checks (the write limit is still enforced)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every result")
    args = ap.parse_args()
    if bool(args.pk) != bool(args.sk):
        ap.error("--pk and --sk must be given together (the /write receipt)")

    # Hard analytic cap for this tool's payload: the server's 2 KiB limit
    # applies to the STORED JSON, which is 31 bytes of overhead (field names,
    # quotes, braces) plus the value, i.e. value <= 2048 - 31 = 2017. A larger
    # value is rejected with 413 by design, so refuse to run such a
    # configuration instead of producing a stream of 413s.
    if args.size > 2017:
        ap.error(f"--size {args.size} cannot be stored: the server's 2 KiB limit "
                 f"applies to the stored JSON (value + 31 bytes of field/quotes "
                 f"overhead), so the maximum value length is 2017")

    base = f"http://{args.host}:{args.port}"
    tally = Tally()

    max_val = None
    if not args.no_preflight:
        ok, max_val = preflight_checks(base, args, tally)
        if not ok:
            return 1
        if args.size > max_val:
            print(f"ERROR: --size {args.size} exceeds the largest accepted value "
                  f"length ({max_val}); the server's 2 KiB limit applies to the "
                  f"stored JSON (value + 31 bytes of field/quotes overhead). "
                  f"Use --size {max_val} or less.")
            return 1

    contended = args.workers > 1

    def task(idx):
        if args.mode == "cycle":
            run_cycle(args, base, tally, contended)
        else:
            run_single(args, base, tally, args.mode)

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(task, i) for i in range(args.iters)]
        for fut in as_completed(futures):
            fut.result()  # exceptions are already caught inside task()
    wall = time.perf_counter() - t0

    total_ops = sum(tally.counts.values())
    summarize(args, tally, wall, total_ops, max_val)

    failures = tally.mismatch + sum(tally.errors.values())
    if failures:
        print(f"RESULT: FAIL ({failures} problem(s); see above)")
        return 1
    print("RESULT: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
