"""Self-contained HTML report: inline CSS, inline SVG, zero external requests.

Rules:
* every dynamic string goes through ``esc()`` (html.escape) - token names are
  attacker-controlled input and end up in the report;
* no CDN, no webfonts, no <script>; the file opens correctly offline;
* numbers are formatted once, in Python, so the HTML has no logic in it.
"""

import datetime
import html
import json

from . import __version__, metrics

CSS = """
:root{
  --bg:#0d1117; --panel:#161b22; --panel2:#1c2230; --line:#2a3140;
  --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff;
  --ok:#3fb950; --warn:#d29922; --bad:#f85149; --purple:#a371f7;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}
h1{font-size:22px;margin:0 0 6px;letter-spacing:-.2px}
h2{font-size:15px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
  margin:32px 0 12px;font-weight:600}
h3{font-size:14px;margin:0 0 8px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.sub{color:var(--muted);font-size:13px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .k{color:var(--muted);font-size:11.5px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:20px;font-weight:600;margin-top:4px;letter-spacing:-.3px}
.card .n{color:var(--muted);font-size:11.5px;margin-top:2px}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;
  font-weight:600;letter-spacing:.04em;border:1px solid}
.b-extreme{color:var(--bad);border-color:var(--bad);background:rgba(248,81,73,.12)}
.b-high{color:#ff9b6a;border-color:#ff9b6a;background:rgba(255,155,106,.12)}
.b-moderate{color:var(--warn);border-color:var(--warn);background:rgba(210,153,34,.12)}
.b-distributed{color:var(--ok);border-color:var(--ok);background:rgba(63,185,80,.12)}
.b-unknown{color:var(--muted);border-color:var(--line);background:var(--panel2)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:11.5px;
  text-transform:uppercase;letter-spacing:.06em;padding:8px 10px;border-bottom:1px solid var(--line)}
td{padding:7px 10px;border-bottom:1px solid #1f2531;vertical-align:top}
tr:hover td{background:#151a23}
td.num,th.num{text-align:right;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.bar{height:7px;border-radius:4px;background:var(--accent);display:inline-block;vertical-align:middle}
.note{background:var(--panel2);border-left:3px solid var(--accent);padding:10px 14px;
  border-radius:0 8px 8px 0;color:var(--muted);font-size:13px;margin:12px 0}
.warnbox{border-left-color:var(--warn)}
.badbox{border-left-color:var(--bad)}
ul{margin:8px 0 0 18px;padding:0}
li{margin:5px 0;color:var(--muted);font-size:13px}
li b{color:var(--fg)}
footer{margin-top:48px;border-top:1px solid var(--line);padding-top:16px;
  color:var(--muted);font-size:12px}
.pill{display:inline-block;padding:2px 8px;border-radius:6px;background:var(--panel2);
  color:var(--muted);font-size:11px;margin-right:6px}
svg{display:block;max-width:100%}
"""


def esc(value):
    """HTML-escape any value. None becomes an empty string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _fmt_pct(value, digits=2):
    if value is None:
        return "n/a"
    try:
        return ("{:." + str(digits) + "f}%").format(float(value) * 100)
    except (TypeError, ValueError):
        return "n/a"


def _fmt_int(value):
    try:
        return "{:,}".format(int(value))
    except (TypeError, ValueError):
        return "n/a"


def _short(addr, head=6, tail=4):
    if not addr:
        return ""
    text = str(addr)
    if len(text) <= head + tail + 2:
        return text
    return text[:head] + "\u2026" + text[-tail:]


def _badge_class(verdict):
    return "b-" + (verdict or "unknown").lower()


EXPLORERS = {
    "base": "https://basescan.org/address/%s",
    "ethereum": "https://etherscan.io/address/%s",
    "arbitrum": "https://arbiscan.io/address/%s",
    "optimism": "https://optimistic.etherscan.io/address/%s",
}


def _explorer(chain, address):
    """Chain-aware explorer link. Never fetches anything, just a hyperlink."""
    template = EXPLORERS.get((chain or "base").lower())
    if not template:
        return esc(address)
    return '<a href="%s" rel="noopener">%s</a>' % (
        esc(template % address), esc(address))


# ------------------------------------------------------------------- charts --
def svg_bar_chart(rows, width=900, row_h=26, label_w=150, value_w=130):
    """Horizontal bars for the top holders. Pure SVG, no JS."""
    rows = rows[:10]
    if not rows:
        return '<p class="sub">no holder rows to chart</p>'
    height = len(rows) * row_h + 12
    chart_w = width - label_w - value_w
    top_share = max((r.get("share") or 0) for r in rows) or 1.0
    parts = [
        '<svg viewBox="0 0 %d %d" width="%d" height="%d" role="img" '
        'aria-label="top holders by share of tracked supply">' % (width, height, width, height)
    ]
    for i, row in enumerate(rows):
        y = i * row_h + 6
        share = row.get("share") or 0.0
        bar_w = max(1.5, (share / top_share) * chart_w)
        label = row.get("label") or _short(row.get("address"))
        color = "#f85149" if i == 0 else ("#d29922" if i < 3 else "#58a6ff")
        parts.append(
            '<text x="0" y="%d" fill="#8b949e" font-size="11.5" '
            'font-family="ui-monospace,Menlo,monospace">%s</text>'
            % (y + 12, esc(label))
        )
        parts.append(
            '<rect x="%d" y="%d" width="%d" height="14" rx="3" fill="%s" opacity="0.9"/>'
            % (label_w, y + 2, bar_w, color)
        )
        parts.append(
            '<text x="%d" y="%d" fill="#e6edf3" font-size="11.5" text-anchor="end" '
            'font-family="ui-monospace,Menlo,monospace">%s</text>'
            % (width - 4, y + 13, esc(_fmt_pct(share, 2)))
        )
    parts.append("</svg>")
    return "".join(parts)


def svg_gauge(value, label="top-10 share", size=210):
    """Semicircular gauge for a 0..1 fraction."""
    try:
        value = max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        value = 0.0
    cx, cy, r = size / 2.0, size / 2.0, size / 2.0 - 18
    import math
    start = math.pi
    angle = start + math.pi * value
    x1, y1 = cx - r, cy
    x2, y2 = cx + r * math.cos(angle), cy + r * math.sin(angle)
    large = 1 if value > 0.5 else 0
    if value >= 0.999:
        color = "#f85149"
    elif value >= 0.8:
        color = "#ff9b6a"
    elif value >= 0.5:
        color = "#d29922"
    else:
        color = "#3fb950"
    return (
        '<svg viewBox="0 0 %(s)d %(sh)d" width="%(s)d" height="%(sh)d" '
        'role="img" aria-label="%(label)s gauge">'
        '<path d="M %(x1).1f %(cy).1f A %(r).1f %(r).1f 0 0 1 %(x2r).1f %(cy).1f" '
        'fill="none" stroke="#2a3140" stroke-width="16" stroke-linecap="round"/>'
        '<path d="M %(x1).1f %(cy).1f A %(r).1f %(r).1f 0 %(large)d 1 %(x2).1f %(y2).1f" '
        'fill="none" stroke="%(color)s" stroke-width="16" stroke-linecap="round"/>'
        '<text x="%(cx).1f" y="%(cyv).1f" fill="#e6edf3" font-size="26" font-weight="600" '
        'text-anchor="middle">%(pct)s</text>'
        '<text x="%(cx).1f" y="%(cyl).1f" fill="#8b949e" font-size="11" '
        'text-anchor="middle">%(label)s</text>'
        "</svg>"
    ) % {
        "s": size, "sh": int(size * 0.62), "x1": x1, "cy": cy, "r": r,
        "x2r": cx + r, "x2": x2, "y2": y2, "large": large, "color": color,
        "cx": cx, "cyv": cy - 2, "cyl": cy + 18, "pct": _fmt_pct(value, 1),
        "label": esc(label),
    }


# ------------------------------------------------------------------- pieces --
def _kv_rows(pairs):
    return "".join(
        '<tr><td class="sub">%s</td><td class="mono">%s</td></tr>' % (esc(k), v)
        for k, v in pairs
    )


def _meta_section(ctx):
    rows = [
        ("command", '<span class="mono">%s</span>' % esc(ctx.get("command"))),
        ("generated (UTC)", esc(ctx.get("generated_at"))),
        ("tool version", esc("forensics %s" % __version__)),
        ("chain", esc(ctx.get("chain"))),
        ("token", '<span class="mono">%s</span>' % esc(ctx.get("token"))),
        ("rpc endpoint", '<span class="mono">%s</span>' % esc(ctx.get("rpc_endpoint"))),
        ("block range", esc(ctx.get("block_range"))),
        ("duration", esc(ctx.get("duration"))),
    ]
    if ctx.get("logs_endpoints"):
        rows.insert(6, ("logs served by", '<span class="mono">%s</span>'
                        % esc(ctx["logs_endpoints"])))
    if ctx.get("dexscreener"):
        rows.append(("dexscreener", '<span class="mono">%s</span>' % esc(ctx["dexscreener"])))
    return ('<table>%s</table>' % _kv_rows(rows))


def _holders_section(holders, decimals, chain="base"):
    if not holders:
        return '<div class="note badbox">Holder analysis unavailable.</div>'
    cards = [
        ("holders", _fmt_int(holders.get("nonzero_holders")),
         "%d addresses seen in window" % holders.get("unique_addresses_seen", 0)),
        ("top 1", _fmt_pct(holders.get("top1_share")), "of tracked supply"),
        ("top 10", _fmt_pct(holders.get("top10_share")), "of tracked supply"),
        ("top 50", _fmt_pct(holders.get("top50_share")), "of tracked supply"),
        ("gini", "%.3f" % (holders.get("gini") or 0.0), "0 = flat, 1 = one wallet"),
        ("dust wallets", _fmt_int(holders.get("dust_wallets")), "each < 0.01% of supply"),
        ("tracked supply", esc(holders.get("tracked_supply")),
         "sum of balances read"),
        ("coverage", _fmt_pct(holders.get("coverage_of_total_supply")),
         "of totalSupply()"),
    ]
    cards_html = "".join(
        '<div class="card"><div class="k">%s</div><div class="v">%s</div>'
        '<div class="n">%s</div></div>' % (esc(k), v, esc(n))
        for k, v, n in cards
    )
    rows = holders.get("rows") or []
    table_rows = []
    max_share = max([r.get("share") or 0 for r in rows[:50]] or [1]) or 1
    for r in rows[:50]:
        bar = int(round((r.get("share") or 0) / max_share * 90)) or 1
        table_rows.append(
            '<tr><td class="num">%d</td>'
            '<td class="mono">%s</td>'
            '<td class="num">%s</td>'
            '<td class="num">%s</td>'
            '<td><span class="bar" style="width:%dpx"></span></td></tr>'
            % (r.get("rank", 0), _explorer(chain, r.get("address")),
               esc(r.get("balance")), _fmt_pct(r.get("share")), bar)
        )
    return (
        '<div class="grid">%s</div>'
        '<div style="display:flex;gap:28px;flex-wrap:wrap;margin-top:22px;align-items:center">'
        '<div style="flex:1;min-width:420px"><h3>Top 10 holders</h3>%s</div>'
        '<div>%s</div></div>'
        '<h3 style="margin-top:24px">Holder table (top %d of %d)</h3>'
        '<table><thead><tr><th class="num">#</th><th>address</th>'
        '<th class="num">balance</th><th class="num">share</th><th></th></tr></thead>'
        "<tbody>%s</tbody></table>"
        % (cards_html, svg_bar_chart(rows),
           svg_gauge(holders.get("top10_share") or 0.0),
           min(50, len(rows)), len(rows), "".join(table_rows))
    )


def _lp_section(lp):
    if not lp:
        return '<div class="note">LP analysis not requested.</div>'
    pairs = lp.get("pairs") or []
    notes = lp.get("notes") or []
    if not pairs:
        return ('<div class="note warnbox">No DexScreener pairs found for this token. '
                'Liquidity may be on a dex DexScreener does not index, or the token may '
                'not be trading.</div>')
    pair_rows = []
    for p in pairs[:12]:
        pair_rows.append(
            '<tr><td>%s</td><td class="mono">%s</td><td>%s/%s</td>'
            '<td class="num">%s</td><td class="num">%s</td><td class="num">%s</td></tr>'
            % (esc(p.get("dex")), esc(_short(p.get("pair_address"), 10, 6)),
               esc(p.get("base_symbol")), esc(p.get("quote_symbol")),
               esc(metrics.format_usd(p.get("liquidity_usd"))),
               esc(metrics.format_usd(p.get("volume_24h_usd"))),
               esc(metrics.format_usd(p.get("fdv"))))
        )
    top = lp.get("lp_pair") or lp.get("top_pair") or {}
    lpinfo = lp.get("lp") or {}
    if lpinfo.get("determined") and lpinfo.get("known"):
        cards = [
            ("LP token", '<span class="mono" style="font-size:13px">%s</span>'
             % esc(_short(lpinfo.get("address"), 8, 6)), esc(top.get("dex"))),
            ("burned", _fmt_pct(lpinfo.get("burned_pct")), "sent to 0x0 / dEaD"),
            ("held by pool", _fmt_pct(lpinfo.get("locked_pct")), "pair contract balance"),
            ("floating", _fmt_pct(lpinfo.get("floating_pct")), "everything else"),
        ]
        cards_html = "".join(
            '<div class="card"><div class="k">%s</div><div class="v">%s</div>'
            '<div class="n">%s</div></div>' % (esc(k), v, esc(n)) for k, v, n in cards
        )
        body = '<div class="grid">%s</div>' % cards_html
    else:
        body = ('<div class="note warnbox"><b>LP token could not be determined.</b> %s</div>'
                % esc(lpinfo.get("reason") or "unknown pool type"))
    notes_html = "".join('<li>%s</li>' % esc(n) for n in notes)
    return (
        body
        + '<h3 style="margin-top:22px">Pairs (%d, deepest first)</h3>' % len(pairs)
        + '<table><thead><tr><th>dex</th><th>pair</th><th>tokens</th>'
          '<th class="num">liquidity</th><th class="num">vol 24h</th>'
          '<th class="num">fdv</th></tr></thead><tbody>%s</tbody></table>' % "".join(pair_rows)
        + ('<ul>%s</ul>' % notes_html if notes_html else "")
    )


def _insiders_section(ins, chain="base"):
    if not ins:
        return ('<div class="note">Early-buyer analysis not run (window too large or '
                'not requested).</div>')
    summary = ins.get("summary") or {}
    rows = ins.get("rows") or []
    if not rows:
        return ('<div class="note warnbox">No transfers from a known pool/router were found '
                'in this window, so no early buyers could be identified. The token may have '
                'launched before the window, or all liquidity sits in a pool type this tool '
                'does not recognise.</div>')
    body = "".join(
        '<tr><td class="num">%d</td>'
        '<td class="mono">%s</td>'
        '<td class="num">%s</td><td class="num">%s</td><td class="num">%s</td>'
        '<td>%s</td></tr>'
        % (i, _explorer(chain, r.get("address")),
           esc(r.get("first_block")), esc(r.get("current_balance")),
           _fmt_pct(r.get("share_of_supply")),
           '<span style="color:#3fb950">holds</span>' if r.get("still_holds")
           else '<span style="color:#8b949e">exited</span>')
        for i, r in enumerate(rows[:50], start=1)
    )
    return (
        '<div class="note">These are <b>early buyers</b>, not insiders. A transfer out of a '
        'pool proves a swap happened; it proves nothing about who knew what.</div>'
        '<div class="grid">'
        '<div class="card"><div class="k">early buyers found</div><div class="v">%s</div>'
        '<div class="n">requested %s</div></div>'
        '<div class="card"><div class="k">still holding</div><div class="v">%s</div>'
        '<div class="n">%s exited</div></div>'
        '<div class="card"><div class="k">combined supply</div><div class="v">%s</div>'
        '<div class="n">of total supply</div></div></div>'
        '<table style="margin-top:20px"><thead><tr><th class="num">#</th><th>address</th>'
        '<th class="num">first block</th><th class="num">balance now</th>'
        '<th class="num">%% supply</th><th>status</th></tr></thead><tbody>%s</tbody></table>'
        % (_fmt_int(summary.get("found")), _fmt_int(summary.get("requested")),
           _fmt_int(summary.get("still_holding")), _fmt_int(summary.get("exited")),
           _fmt_pct(summary.get("combined_share_of_supply")), body)
    )


CAVEATS = [
    ("CEX wallets look like whales.",
     "A top holder may be a Binance/Coinbase omnibus wallet. This tool does not "
     "label addresses, so treat every large row as unverified."),
    ("balanceOf is current state, not history.",
     "Balances are read at the report's head block. A wallet that held 5% last week "
     "and dumped shows 0 here."),
    ("The log window can miss earlier transfers.",
     "Holders are discovered from Transfer logs inside the scanned range only. "
     "Wallets that received tokens before --from-block are invisible, which is why "
     "coverage of totalSupply is printed and often below 100%."),
    ("Pool/router detection is heuristic.",
     "We exclude pair addresses returned by DexScreener plus a short list of known "
     "routers. Undiscovered pools and fresh routers still appear as holders."),
    ("Fee-on-transfer and rebasing tokens distort shares.",
     "We read balances, not the amounts that moved, so reflections and burns are "
     "only visible through the balance delta."),
    ("Contract-held supply is not insider supply.",
     "Vesting contracts, treasuries, bridges and staking contracts are single "
     "addresses. High concentration can be legitimate lock-up."),
    ("LP burn is not LP safety.",
     "Burned LP with a mintable token, or a 100%-burned LP in a pool whose owner can "
     "still migrate it, is not protection. LP token ownership is only one signal."),
    ("Early buyers are not insiders.",
     "Anyone can be the first buyer in a block. No wallet clustering, no funding "
     "graph and no off-chain identity is used here."),
    ("Public RPC endpoints are rate limited.",
     "If a chunk failed, the window is incomplete. Re-run with a larger --chunk-size "
     "budget or a private endpoint and compare."),
]


def _caveats_section():
    return "<ul>%s</ul>" % "".join(
        "<li><b>%s</b> %s</li>" % (esc(t), esc(d)) for t, d in CAVEATS
    )


def _warnings_section(model):
    warnings = list(model.get("warnings") or [])
    stats = model.get("transfer_stats") or {}
    if stats.get("skipped_blocks"):
        warnings.append("%d block(s) had more Transfer logs than the RPC would return "
                        "and were skipped: %s"
                        % (len(stats["skipped_blocks"]),
                           ", ".join(str(b) for b in stats["skipped_blocks"][:5])))
    if not warnings:
        return ""
    return '<div class="note warnbox"><b>Run warnings</b><ul>%s</ul></div>' % "".join(
        "<li>%s</li>" % esc(w) for w in warnings
    )


def build_report(model):
    """model -> complete HTML string."""
    ctx = model.get("context") or {}
    holders = (model.get("holders") or {})
    verdict = holders.get("verdict") or "UNKNOWN"
    token_label = "%s (%s)" % (model.get("symbol") or "?", _short(model.get("token"), 10, 8))
    return """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>forensics - %(title)s</title>
<style>%(css)s</style></head><body><div class="wrap">
<header>
  <div class="sub">token forensics report</div>
  <h1>%(symbol)s <span class="mono sub">%(short_token)s</span></h1>
  <div style="margin-top:10px">
    <span class="badge %(badge)s">%(verdict)s concentration</span>
    <span class="pill">%(chain)s</span>
    <span class="pill">%(holders_n)s holders</span>
    <span class="pill">top-10 %(top10)s</span>
  </div>
  <div class="sub" style="margin-top:8px">%(reason)s</div>
</header>

%(warnings)s

<h2>Run context</h2>
%(meta)s

<h2>Holder concentration</h2>
%(holders_html)s

<h2>Liquidity / LP</h2>
%(lp)s

<h2>Early buyers</h2>
%(insiders)s

<h2>What this report cannot tell you</h2>
%(caveats)s

<footer>
  Generated by forensics %(version)s &middot; %(generated)s &middot;
  stdlib only, no API keys, no telemetry.<br>
  Every number above is reproducible with the command shown under "Run context".
  If an endpoint was rate limited the run warnings say so.
</footer>
</div></body></html>
""" % {
        "title": esc(token_label),
        "css": CSS,
        "symbol": esc(model.get("symbol") or "UNKNOWN"),
        "short_token": esc(_short(model.get("token"), 10, 8)),
        "badge": _badge_class(verdict),
        "verdict": esc(verdict),
        "chain": esc(model.get("chain") or "base"),
        "holders_n": _fmt_int(holders.get("nonzero_holders") or 0),
        "top10": _fmt_pct(holders.get("top10_share")),
        "reason": esc(holders.get("verdict_reason") or ""),
        "warnings": _warnings_section(model),
        "meta": _meta_section(ctx),
        "holders_html": _holders_section(holders, model.get("decimals"), model.get("chain")),
        "lp": _lp_section(model.get("lp")),
        "insiders": _insiders_section(model.get("insiders"), model.get("chain")),
        "caveats": _caveats_section(),
        "version": esc(__version__),
        "generated": esc(ctx.get("generated_at")),
    }


def build_model(chain, token, meta, holders_result, lp_result, insiders_result,
                context, warnings=None):
    """Assemble the JSON model that both --json and the HTML report consume.

    Keeping one model for both outputs means the JSON file is a faithful
    machine-readable copy of the HTML, not a second implementation.
    """
    analysis = (holders_result or {}).get("analysis") or {}
    holders = analysis.get("holders") or {}
    return {
        "schema": "forensics.report/1",
        "tool": "forensics",
        "version": __version__,
        "generated_at": context.get("generated_at")
        or datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "chain": chain,
        "token": token,
        "symbol": (meta or {}).get("symbol"),
        "name": (meta or {}).get("name"),
        "decimals": (meta or {}).get("decimals", 18),
        "total_supply_raw": (meta or {}).get("total_supply_raw", 0),
        "context": context,
        "window": (holders_result or {}).get("window") or {},
        "holders": holders,
        "transfer_stats": analysis.get("transfer_stats") or {},
        "pairs": (holders_result or {}).get("pairs") or [],
        "lp": (lp_result or {}).get("lp") or {},
        "insiders": insiders_result,
        "warnings": warnings or [],
        "rpc": context.get("rpc_summary") or {},
    }


def to_json(model):
    return json.dumps(model, indent=2, sort_keys=False, default=str)
