"""Command line interface.

Every command degrades to a clear message plus a non-zero exit code instead of a
traceback. ``--debug`` re-raises for bug reports.
"""

import argparse
import datetime
import json
import os
import sys
import time

from . import __version__, evm, metrics, report
from .rpc import CHAINS, RpcError, RpcPool, RpcUnavailable, probe

DEFAULT_CHUNK = 5000
MAX_CHUNK = 5000


# ------------------------------------------------------------------ helpers --
def _ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _err(msg):
    sys.stderr.write("error: %s\n" % msg)


def _warn(msg):
    sys.stderr.write("warning: %s\n" % msg)


def _table(headers, rows, aligns=None):
    """Tiny fixed-width table printer (no dependencies)."""
    if not rows:
        print("  (no rows)")
        return
    aligns = aligns or ["l"] * len(headers)
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt(cells):
        out = []
        for i, cell in enumerate(cells):
            text = str(cell)
            out.append(text.rjust(widths[i]) if aligns[i] == "r" else text.ljust(widths[i]))
        return "  ".join(out).rstrip()

    print(fmt(headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt(row))


def _make_pool(args):
    endpoints = None
    if getattr(args, "rpc", None):
        endpoints = [u.strip() for u in args.rpc.split(",") if u.strip()]
    return RpcPool(
        chain=args.chain,
        endpoints=endpoints,
        timeout=args.timeout,
        verbose=getattr(args, "verbose", False),
    )


def _progress_printer(label):
    """Progress on stderr, only when stderr is a terminal.

    Piped output stays clean: nobody wants carriage-return spam in a log file.
    """
    last = [0.0]
    tty = sys.stderr.isatty()
    width = 0

    def cb(*args):
        nonlocal width
        now = time.time()
        if not tty:
            return
        if now - last[0] < 1.0:
            return
        last[0] = now
        if len(args) == 3:
            start, end, count = args
            text = "%s: blocks %d-%d, %d logs" % (label, start, end, count)
        else:
            done, total = args
            text = "%s: balances %d/%d" % (label, done, total)
        pad = max(0, width - len(text))
        sys.stderr.write("\r" + text + " " * pad)
        width = len(text)
        sys.stderr.flush()

    return cb


def _finish_progress():
    if sys.stderr.isatty():
        sys.stderr.write("\r" + " " * 78 + "\r")
        sys.stderr.flush()


def _logs_endpoint_summary(transfer_stats):
    """Which endpoints actually served eth_getLogs, with chunk counts."""
    endpoints = (transfer_stats or {}).get("endpoints") or {}
    if not endpoints:
        return None
    return ", ".join("%s (%d chunks)" % (name, count)
                     for name, count in sorted(endpoints.items()))


def _check_chain(chain):
    if chain not in CHAINS:
        raise ValueError("unknown chain %r (known: %s)" % (chain, ", ".join(sorted(CHAINS))))


def _check_token(token):
    """Fail fast on a malformed address instead of scanning for nothing."""
    addr = metrics.normalise_address(token)
    if not addr:
        raise ValueError(
            "invalid token address %r: expected 0x followed by 40 hex characters" % (token,)
        )
    return addr


def _write(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ----------------------------------------------------------------- commands --
def cmd_holders(args):
    _check_chain(args.chain)
    args.token = _check_token(args.token)
    pool = _make_pool(args)
    started = time.time()
    result = evm.run_holders(
        pool, args.chain, args.token,
        blocks=args.blocks, from_block=args.from_block, top=args.top,
        chunk_size=args.chunk_size, concurrency=args.concurrency,
        progress=_progress_printer("scan") if not args.quiet else None,
    )
    if not args.quiet:
        _finish_progress()
    analysis = result["analysis"]
    holders = analysis["holders"]
    meta = result["meta"]
    window = result["window"]

    if not args.quiet:
        print("%s (%s) on %s" % (meta["symbol"], meta["address"], args.chain))
        print("window %d-%d (%d blocks), %d Transfer logs, %d chunks"
              % (window["from_block"], window["to_block"], window["blocks"],
                 analysis["transfer_stats"].get("raw_logs", 0),
                 analysis["transfer_stats"].get("chunks", 0)))
        print("")
        _table(
            ["metric", "value"],
            [
                ("unique addresses in window", holders["unique_addresses_seen"]),
                ("balances read", holders["balances_read"]),
                ("balances failed", holders["balances_failed"]),
                ("holders (balance > 0)", holders["nonzero_holders"]),
                ("tracked supply", holders["tracked_supply"]),
                ("total supply", holders["total_supply"]),
                ("coverage of totalSupply", metrics.pct(holders["coverage_of_total_supply"])),
                ("top 1 share", metrics.pct(holders["top1_share"])),
                ("top 5 share", metrics.pct(holders["top5_share"])),
                ("top 10 share", metrics.pct(holders["top10_share"])),
                ("top 50 share", metrics.pct(holders["top50_share"])),
                ("gini", "%.4f" % holders["gini"]),
                ("hhi", "%.4f" % holders["hhi"]),
                ("dust wallets (<0.01%)", holders["dust_wallets"]),
            ],
            aligns=["l", "r"],
        )
        print("")
        print("verdict: %s - %s" % (holders["verdict"], holders["verdict_reason"]))
        if holders["unique_addresses_seen"] == 0:
            print("")
            print("no Transfer events for this address in the scanned window. Either the "
                  "address is not an ERC-20 contract, or it had no transfers in these "
                  "%d blocks (try a larger --blocks)." % window["blocks"])
        print("")
        _table(
            ["#", "address", "balance", "share"],
            [(r["rank"], r["address"], r["balance"], metrics.pct(r["share"]))
             for r in holders["rows"][:args.top]],
            aligns=["r", "l", "r", "r"],
        )

    if args.json:
        model = report.build_model(
            args.chain, args.token, meta, result, None, None,
            context={
                "command": _command_string(),
                "generated_at": _iso_now(),
                "chain": args.chain,
                "token": args.token,
                "rpc_endpoint": result.get("head_endpoint"),
                "logs_endpoints": _logs_endpoint_summary(analysis["transfer_stats"]),
                "block_range": "%d-%d" % (window["from_block"], window["to_block"]),
                "duration": "%.1fs" % (time.time() - started),
                "dexscreener": result.get("dexscreener_endpoint"),
                "rpc_summary": pool.summary(),
            },
        )
        model["holders"] = holders
        _write(args.json, report.to_json(model))
        if not args.quiet:
            print("\njson written to %s" % args.json)

    if args.out:
        model = report.build_model(
            args.chain, args.token, meta, result, None, None,
            context={
                "command": _command_string(),
                "generated_at": _iso_now(),
                "chain": args.chain,
                "token": args.token,
                "rpc_endpoint": result.get("head_endpoint"),
                "logs_endpoints": _logs_endpoint_summary(analysis["transfer_stats"]),
                "block_range": "%d-%d" % (window["from_block"], window["to_block"]),
                "duration": "%.1fs" % (time.time() - started),
                "dexscreener": result.get("dexscreener_endpoint"),
                "rpc_summary": pool.summary(),
            },
        )
        _write(args.out, report.build_report(model))
        if not args.quiet:
            print("html written to %s" % args.out)
    return 0


def cmd_report(args):
    _check_chain(args.chain)
    args.token = _check_token(args.token)
    pool = _make_pool(args)
    started = time.time()
    ctx = {
        "command": _command_string(),
        "generated_at": _iso_now(),
        "chain": args.chain,
        "token": args.token,
        "rpc_endpoint": None,
        "block_range": None,
        "duration": None,
        "dexscreener": None,
        "rpc_summary": {},
    }
    warnings = []

    if not args.quiet:
        sys.stderr.write("scanning holders...\n")
    holders_result = evm.run_holders(
        pool, args.chain, args.token,
        blocks=args.blocks, from_block=args.from_block, top=args.top,
        chunk_size=args.chunk_size, concurrency=args.concurrency,
        progress=_progress_printer("holders") if not args.quiet else None,
    )
    if not args.quiet:
        _finish_progress()
    ctx["rpc_endpoint"] = holders_result.get("head_endpoint")
    ctx["logs_endpoints"] = _logs_endpoint_summary(
        holders_result["analysis"].get("transfer_stats"))
    window = holders_result["window"]
    ctx["block_range"] = "%d-%d (%d blocks)" % (
        window["from_block"], window["to_block"], window["blocks"])
    ctx["dexscreener"] = holders_result.get("dexscreener_endpoint")

    # Lite edition: holders only. LP-burn analysis and the early-buyer sweep
    # ship as CLI commands in the Pro pack.
    lp_result = None
    insiders_result = None

    stats = holders_result["analysis"]["transfer_stats"]
    if stats.get("raw_logs") == 0:
        warnings.append(
            "no Transfer events were found in this window: the address may not be an "
            "ERC-20 contract, or it did not move in these blocks (try a larger --blocks)"
        )
    if stats.get("skipped_blocks"):
        warnings.append("%d block(s) were skipped because they held more logs than "
                        "the RPC would return" % len(stats["skipped_blocks"]))
    if stats.get("failovers"):
        warnings.append("%d RPC failover(s) occurred; the window is still complete "
                        "unless a chunk failed" % stats["failovers"])
    for w in holders_result["meta"].get("warnings") or []:
        warnings.append(w)

    ctx["duration"] = "%.1fs" % (time.time() - started)
    ctx["rpc_summary"] = pool.summary()

    model = report.build_model(
        args.chain, args.token, holders_result["meta"], holders_result, lp_result,
        insiders_result, ctx, warnings=warnings,
    )
    html_text = report.build_report(model)
    _write(args.out, html_text)

    json_path = args.json
    if json_path is None and args.json_alongside:
        json_path = os.path.splitext(args.out)[0] + ".json"
    if json_path:
        _write(json_path, report.to_json(model))

    if not args.quiet:
        h = model["holders"]
        print("report: %s" % args.out)
        if json_path:
            print("json:   %s" % json_path)
        print("token:  %s (%s)" % (model["symbol"], model["token"]))
        print("window: %s" % ctx["block_range"])
        print("holders: %d, top10 %s, verdict %s"
              % (h.get("nonzero_holders", 0),
                 metrics.pct(h.get("top10_share")), h.get("verdict")))
        print("size:   %.1f KB" % (len(html_text) / 1024.0))
        for w in warnings:
            print("warning: %s" % w)
    return 0


def _command_string():
    argv = list(sys.argv)
    prog = os.path.basename(argv[0]) if argv else "forensics"
    parts = [prog] + argv[1:]
    return " ".join(parts)


# ------------------------------------------------------------------- parser --
def build_parser():
    parser = argparse.ArgumentParser(
        prog="forensics",
        description="Holder concentration for EVM tokens, rebuilt from raw Transfer logs, "
                    "plus a self-contained HTML report. Stdlib only, public endpoints only, "
                    "no API keys. (Lite edition: holders + report.)",
        epilog="examples:\n"
               "  forensics holders --chain base --token 0x... --blocks 50000\n"
               "  forensics holders --chain base --token 0x... --from-block 12000000\n"
               "  forensics report  --chain base --token 0x... --out report.html\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="forensics %s" % __version__)
    sub = parser.add_subparsers(dest="command", metavar="command")

    def common(p, needs_token=True):
        if needs_token:
            p.add_argument("--token", required=True, help="token contract address")
        p.add_argument("--chain", default="base", choices=sorted(CHAINS),
                       help="EVM chain (default: base)")
        p.add_argument("--rpc", default=None,
                       help="comma-separated RPC endpoints overriding the built-in list")
        p.add_argument("--timeout", type=float, default=30.0, help="per-request timeout (s)")
        p.add_argument("--quiet", action="store_true", help="suppress human-readable output")
        p.add_argument("--verbose", action="store_true", help="log RPC failover decisions")
        p.add_argument("--json", dest="json", default=None, help="write JSON output here")

    p = sub.add_parser("holders", help="holder concentration from Transfer logs")
    common(p)
    p.add_argument("--blocks", type=int, default=50000, help="blocks back from head (default 50000)")
    p.add_argument("--from-block", type=int, default=None, help="explicit start block")
    p.add_argument("--top", type=int, default=50, help="rows to print (default 50)")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK,
                   help="blocks per eth_getLogs request (default 5000, auto-shrinks)")
    p.add_argument("--concurrency", type=int, default=8, help="balanceOf threads (default 8)")
    p.add_argument("--out", default=None, help="write an HTML report here")
    p.set_defaults(func=cmd_holders)

    p = sub.add_parser("report", help="one self-contained HTML report")
    common(p)
    p.add_argument("--blocks", type=int, default=50000, help="blocks back from head")
    p.add_argument("--from-block", type=int, default=None, help="explicit start block")
    p.add_argument("--top", type=int, default=50, help="holder rows to include")
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK, help="blocks per log request")
    p.add_argument("--concurrency", type=int, default=8, help="balanceOf threads")
    p.add_argument("--out", default="report.html", help="HTML output path")
    p.add_argument("--json-alongside", action="store_true",
                   help="also write <report>.json next to the HTML")
    p.set_defaults(func=cmd_report)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except RpcUnavailable as exc:
        _err(str(exc))
        _err("pass --rpc with your own endpoint if the public pool is rate limited")
        return 1
    except RpcError as exc:
        _err(str(exc))
        return 1
    except ValueError as exc:
        _err(str(exc))
        return 2
    except BrokenPipeError:
        return 0
    except Exception as exc:  # noqa: BLE001 - last line of defence
        if getattr(args, "verbose", False) or os.environ.get("FORENSICS_DEBUG"):
            raise
        _err("%s: %s" % (type(exc).__name__, exc))
        _err("re-run with --verbose or FORENSICS_DEBUG=1 for a traceback")
        return 1


if __name__ == "__main__":
    sys.exit(main())
