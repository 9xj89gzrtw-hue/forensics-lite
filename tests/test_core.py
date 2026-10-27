"""Offline unit tests. No network access, no fixtures on disk.

Run:  python3 -m unittest discover -s tests -v
      (or ./run-tests.sh)
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(HERE), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from forensics import evm, metrics, report  # noqa: E402
from forensics.rpc import (  # noqa: E402
    RangeLimited,
    RangeTooLarge,
    RpcPool,
    RpcProtocolError,
    RetryableRpcError,
    Endpoint,
)


# ------------------------------------------------------------------- gini ---
class TestGini(unittest.TestCase):
    def test_perfect_equality_is_zero(self):
        self.assertAlmostEqual(metrics.gini([10, 10, 10, 10]), 0.0, places=9)

    def test_one_holder_takes_all(self):
        # n=4, one wallet with everything -> (n-1)/n = 0.75
        self.assertAlmostEqual(metrics.gini([0, 0, 0, 100]), 0.75, places=9)

    def test_two_holders_half_each(self):
        self.assertAlmostEqual(metrics.gini([50, 50]), 0.0, places=9)

    def test_empty_and_zero_lists(self):
        self.assertEqual(metrics.gini([]), 0.0)
        self.assertEqual(metrics.gini([0, 0, 0]), 0.0)

    def test_matches_hand_computed_value(self):
        # sorted [1,2,3,4]: sum=10, weighted=1*1+2*2+3*3+4*4=30
        # G = (2*30 - 5*10) / (4*10) = 10/40 = 0.25
        self.assertAlmostEqual(metrics.gini([4, 3, 2, 1]), 0.25, places=9)

    def test_single_holder_is_zero_not_error(self):
        self.assertEqual(metrics.gini([123]), 0.0)

    def test_scale_invariance(self):
        a = metrics.gini([1, 2, 3, 40])
        b = metrics.gini([1000, 2000, 3000, 40000])
        self.assertAlmostEqual(a, b, places=9)

    def test_bounded(self):
        for case in ([1, 1e9], [0, 0, 1], [5, 5, 5, 5, 5]):
            value = metrics.gini(case)
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)


# ------------------------------------------------------------- thresholds ---
class TestConcentration(unittest.TestCase):
    def test_extreme_by_top1(self):
        verdict, reason = metrics.concentration_verdict(0.51, 0.60, 100)
        self.assertEqual(verdict, "EXTREME")
        self.assertIn("51.0%", reason)

    def test_extreme_by_top10(self):
        self.assertEqual(metrics.concentration_verdict(0.10, 0.91, 100)[0], "EXTREME")

    def test_high(self):
        self.assertEqual(metrics.concentration_verdict(0.26, 0.40, 100)[0], "HIGH")
        self.assertEqual(metrics.concentration_verdict(0.10, 0.71, 100)[0], "HIGH")

    def test_moderate(self):
        self.assertEqual(metrics.concentration_verdict(0.10, 0.55, 100)[0], "MODERATE")

    def test_distributed(self):
        self.assertEqual(metrics.concentration_verdict(0.05, 0.30, 500)[0], "DISTRIBUTED")

    def test_thin_sample_cannot_be_distributed(self):
        verdict, reason = metrics.concentration_verdict(0.05, 0.30, 5)
        self.assertEqual(verdict, "MODERATE")
        self.assertIn("small sample", reason)

    def test_zero_holders_is_unknown(self):
        self.assertEqual(metrics.concentration_verdict(0.0, 0.0, 0)[0], "UNKNOWN")

    def test_boundaries_are_inclusive(self):
        # exactly at the threshold counts as the worse bucket
        self.assertEqual(metrics.concentration_verdict(0.50, 0.50, 100)[0], "EXTREME")
        self.assertEqual(metrics.concentration_verdict(0.25, 0.25, 100)[0], "HIGH")
        self.assertEqual(metrics.concentration_verdict(0.0, 0.50, 100)[0], "MODERATE")

    def test_top_shares(self):
        values = [100, 50, 25, 25]
        shares = metrics.top_shares(values, 200)
        self.assertAlmostEqual(shares["top1"], 0.5)
        self.assertAlmostEqual(shares["top10"], 1.0)

    def test_top_share_empty(self):
        self.assertEqual(metrics.share_of([], 0, 10), 0.0)

    def test_dust_count(self):
        # 0.01% of 1_000_000 = 100
        values = [500000, 499900, 50, 49, 1]
        self.assertEqual(metrics.dust_count(values, 1000000, 0.0001), 3)

    def test_hhi(self):
        self.assertAlmostEqual(metrics.hhi([100], 100), 1.0)
        self.assertAlmostEqual(metrics.hhi([50, 50], 100), 0.5)


# ----------------------------------------------------------- chunk maths ---
class TestChunking(unittest.TestCase):
    def test_even_split(self):
        self.assertEqual(metrics.plan_chunks(0, 9, 5), [(0, 4), (5, 9)])

    def test_remainder_chunk(self):
        self.assertEqual(metrics.plan_chunks(100, 112, 5), [(100, 104), (105, 109), (110, 112)])

    def test_single_block(self):
        self.assertEqual(metrics.plan_chunks(7, 7, 5000), [(7, 7)])

    def test_no_gaps_and_no_overlap(self):
        chunks = metrics.plan_chunks(1000, 12345, 777)
        self.assertEqual(chunks[0][0], 1000)
        self.assertEqual(chunks[-1][1], 12345)
        for (a_start, a_end), (b_start, _b_end) in zip(chunks, chunks[1:]):
            self.assertEqual(b_start, a_end + 1)

    def test_exact_multiple_does_not_add_empty_chunk(self):
        self.assertEqual(metrics.plan_chunks(0, 9, 5), [(0, 4), (5, 9)])
        self.assertEqual(len(metrics.plan_chunks(0, 9, 10)), 1)

    def test_inverted_range_is_empty(self):
        self.assertEqual(metrics.plan_chunks(10, 5, 100), [])

    def test_bad_chunk_size(self):
        with self.assertRaises(ValueError):
            metrics.plan_chunks(0, 10, 0)

    def test_count_matches_plan(self):
        for span, size in ((100000, 5000), (1, 1), (12345, 777)):
            self.assertEqual(metrics.count_chunks(0, span - 1, size),
                             len(metrics.plan_chunks(0, span - 1, size)))


# -------------------------------------------------------------- addresses ---
class TestAddresses(unittest.TestCase):
    def test_lowercases_and_keeps_prefix(self):
        self.assertEqual(
            metrics.normalise_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        )

    def test_accepts_missing_prefix(self):
        self.assertEqual(metrics.normalise_address("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
                         "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")

    def test_topic_word_extracts_last_40(self):
        topic = "0x000000000000000000000000" + "833589fcd6edb6e08f4c7c32d4f71b54bda02913"
        self.assertEqual(metrics.topic_to_address(topic),
                         "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")

    def test_topic_rejects_garbage(self):
        self.assertEqual(metrics.topic_to_address("0xzz"), "")
        self.assertEqual(metrics.topic_to_address(None), "")
        self.assertEqual(metrics.topic_to_address("0x1234"), "")

    def test_non_hex_rejected(self):
        self.assertEqual(metrics.normalise_address("0x" + "g" * 40), "")

    def test_zero_detection(self):
        self.assertTrue(metrics.is_zero_address("0x" + "0" * 40))
        self.assertFalse(metrics.is_zero_address("0x" + "0" * 39 + "1"))

    def test_evm_padding(self):
        padded = evm._pad_address("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        self.assertEqual(len(padded), 64)
        self.assertTrue(padded.endswith("833589fcd6edb6e08f4c7c32d4f71b54bda02913"))

    def test_evm_padding_rejects_garbage(self):
        with self.assertRaises(Exception):
            evm._pad_address("not-an-address")


# ---------------------------------------------------------------- parsing ---
class TestParsing(unittest.TestCase):
    def test_hex_quantity(self):
        self.assertEqual(metrics.parse_uint("0x10"), 16)
        self.assertEqual(metrics.parse_uint("0x"), 0)
        self.assertEqual(metrics.parse_uint(None, 7), 7)
        self.assertEqual(metrics.parse_uint("nonsense", 3), 3)
        self.assertEqual(metrics.parse_uint(42), 42)

    def test_decode_uint256(self):
        word = "0x" + "0" * 61 + "1f4"      # 500, full 32-byte word
        self.assertEqual(metrics.decode_uint256(word), 500)
        self.assertEqual(metrics.decode_uint256("0x"), 0)
        self.assertEqual(metrics.decode_uint256(None), 0)
        self.assertEqual(metrics.decode_uint256("0x1234"), 0)   # short word

    def test_decode_abi_string_dynamic(self):
        # offset 32, length 4, "JIDI"
        blob = ("0x"
                + "0" * 62 + "20"
                + "0" * 63 + "4"
                + "4a494449" + "0" * 56)
        self.assertEqual(metrics.decode_abi_string(blob), "JIDI")

    def test_decode_abi_string_bytes32(self):
        blob = "0x" + "4d4b5254".ljust(64, "0")   # "MKRT" padded
        self.assertEqual(metrics.decode_abi_string(blob), "MKRT")

    def test_decode_abi_string_rejects_junk(self):
        self.assertIsNone(metrics.decode_abi_string(None))
        self.assertIsNone(metrics.decode_abi_string("0x"))
        self.assertIsNone(metrics.decode_abi_string("0xzzzz"))

    def test_format_amount(self):
        self.assertEqual(metrics.format_amount(0, 18), "0")
        self.assertEqual(metrics.format_amount(10 ** 18, 18), "1")
        self.assertEqual(metrics.format_amount(1500 * 10 ** 18, 18), "1,500")
        self.assertEqual(metrics.format_amount(1234 * 10 ** 6, 6), "1,234")
        # 1 wei must never render as "0"
        self.assertNotEqual(metrics.format_amount(1, 18), "0")
        self.assertIn("e-18", metrics.format_amount(1, 18))

    def test_format_usd(self):
        self.assertEqual(metrics.format_usd(1500), "$1.5K")
        self.assertEqual(metrics.format_usd(2_500_000), "$2.50M")
        self.assertEqual(metrics.format_usd(None), "n/a")

    def test_pct(self):
        self.assertEqual(metrics.pct(0.1234), "12.34%")
        self.assertEqual(metrics.pct(None), "n/a")

    def test_safe_div(self):
        self.assertEqual(metrics.safe_div(1, 0), 0.0)
        self.assertEqual(metrics.safe_div(1, 0, -1), -1)
        self.assertEqual(metrics.safe_div(1, 4), 0.25)


# ------------------------------------------------------------------- LP ----
class TestLpBurnMath(unittest.TestCase):
    def test_half_burned(self):
        out = metrics.lp_burn_math(1000, 500, 0)
        self.assertAlmostEqual(out["burned_pct"], 0.5)
        self.assertAlmostEqual(out["floating_pct"], 0.5)
        self.assertTrue(out["known"])

    def test_burned_plus_locked_cannot_exceed_supply(self):
        out = metrics.lp_burn_math(1000, 900, 900)
        self.assertLessEqual(out["burned_pct"] + out["locked_pct"] + out["floating_pct"], 1.0000001)
        self.assertAlmostEqual(out["burned_pct"], 0.9)
        self.assertAlmostEqual(out["locked_pct"], 0.1)
        self.assertEqual(out["floating"], 0)

    def test_zero_supply_is_unknown(self):
        out = metrics.lp_burn_math(0, 5, 5)
        self.assertFalse(out["known"])
        self.assertEqual(out["burned_pct"], 0.0)

    def test_none_inputs(self):
        out = metrics.lp_burn_math(None, None, None)
        self.assertFalse(out["known"])
        self.assertEqual(out["total_supply"], 0)

    def test_negative_clamped(self):
        out = metrics.lp_burn_math(100, -50, -10)
        self.assertEqual(out["burned"], 0)
        self.assertEqual(out["locked_by_pool"], 0)

    def test_full_burn(self):
        out = metrics.lp_burn_math(1_000_000, 1_000_000, 0)
        self.assertAlmostEqual(out["burned_pct"], 1.0)
        self.assertAlmostEqual(out["floating_pct"], 0.0)

    def test_lp_token_resolution_refuses_bytes32_pool_id(self):
        pair = {
            "dex": "uniswap",
            "pair_address": "0x8daaaa183fd6ee98fd4fb47b38e86db0e7cf29f6c2ca282d3114c34c9b8d12c6",
            "is_bytes32_pool_id": True,
            "labels": ["v4"],
        }
        addr, reason = evm.lp_token_address(pair)
        self.assertIsNone(addr)
        self.assertIn("v4", reason)

    def test_lp_token_resolution_v3_nft(self):
        addr, reason = evm.lp_token_address({
            "dex": "uniswap", "pair_address": "0x" + "1" * 40, "labels": ["v3"]})
        self.assertIsNone(addr)
        self.assertIn("NFT", reason)

    def test_lp_token_resolution_v2_pair(self):
        addr, reason = evm.lp_token_address({
            "dex": "uniswap", "pair_address": "0x" + "a" * 40, "labels": ["v2"]})
        self.assertEqual(addr, "0x" + "a" * 40)
        self.assertIsNone(reason)


# ------------------------------------------------------------- RPC parsing --
class TestRpcClassification(unittest.TestCase):
    def setUp(self):
        self.pool = RpcPool("base", endpoints=["https://example.invalid"])
        self.ep = Endpoint("https://example.invalid")

    def test_max_results_error_becomes_range_too_large(self):
        with self.assertRaises(RangeTooLarge) as ctx:
            self.pool._classify(
                self.ep, "eth_getLogs", -32602,
                "query exceeds max results 20000, retry with the range 53149696-53149963")
        self.assertEqual(ctx.exception.suggested_from, 53149696)
        self.assertEqual(ctx.exception.suggested_to, 53149963)

    def test_block_span_limit_becomes_range_limited(self):
        with self.assertRaises(RangeLimited) as ctx:
            self.pool._classify(
                self.ep, "eth_getLogs", -32602,
                "eth_getLogs is limited to 0 - 50 blocks range")
        self.assertEqual(ctx.exception.max_range, 51)

    def test_request_limit_reached_marks_logs_blocked(self):
        from forensics.rpc import EndpointUnsupported
        with self.assertRaises(EndpointUnsupported):
            self.pool._classify(self.ep, "eth_getLogs", -32011, "request limit reached")
        self.assertTrue(self.ep.logs_blocked)

    def test_rate_limit_is_retryable(self):
        with self.assertRaises(RetryableRpcError):
            self.pool._classify(self.ep, "eth_call", -32005, "rate limit exceeded")

    def test_method_not_found_marks_logs_blocked(self):
        from forensics.rpc import EndpointUnsupported
        with self.assertRaises(EndpointUnsupported):
            self.pool._classify(self.ep, "eth_getLogs", -32601, "method not found")
        self.assertTrue(self.ep.logs_blocked)

    def test_revert_is_protocol_error(self):
        with self.assertRaises(RpcProtocolError):
            self.pool._classify(self.ep, "eth_call", 3, "execution reverted")

    def test_blocked_logs_endpoint_is_not_chosen_for_logs(self):
        self.ep.logs_blocked = True
        self.pool.endpoints = [self.ep]
        self.assertEqual(self.pool._candidates(allow_logs=True), [])
        self.assertEqual(len(self.pool._candidates(allow_logs=False)), 1)


# ------------------------------------------------------- report model/html --
def _fake_holders(n=5, tracked=1000):
    rows = []
    remaining = tracked
    for i in range(n):
        raw = remaining if i == n - 1 else int(tracked / (2 ** (i + 1)))
        remaining -= raw
        rows.append({
            "rank": i + 1,
            "address": "0x" + ("%040x" % (i + 1)),
            "balance_raw": raw,
            "balance": metrics.format_amount(raw, 18),
            "share": raw / float(tracked),
            "share_of_supply": raw / float(tracked),
        })
    return {
        "unique_addresses_seen": n + 2,
        "balances_read": n + 2,
        "balances_failed": 0,
        "nonzero_holders": n,
        "zero_balance_holders": 2,
        "excluded_pool_addresses": ["0x" + "9" * 40],
        "tracked_supply_raw": tracked,
        "tracked_supply": "0.000000000000001",
        "total_supply_raw": tracked * 2,
        "total_supply": "0.000000000000002",
        "coverage_of_total_supply": 0.5,
        "top1_share": rows[0]["share"],
        "top5_share": 1.0,
        "top10_share": 1.0,
        "top50_share": 1.0,
        "gini": metrics.gini([r["balance_raw"] for r in rows]),
        "hhi": 0.5,
        "dust_wallets": 1,
        "dust_threshold_pct": 0.01,
        "verdict": "EXTREME",
        "verdict_reason": "top-1 holds 50.0%",
        "rows": rows,
        "burned_total": "0",
        "burned_pct_of_supply": 0.0,
    }


def _fake_model(symbol="TEST"):
    meta = {"address": "0x" + "a" * 40, "symbol": symbol, "name": symbol,
            "decimals": 18, "total_supply_raw": 2000, "warnings": []}
    holders = _fake_holders()
    holders_result = {
        "meta": meta,
        "pairs": [{"dex": "uniswap", "pair_address": "0x" + "b" * 40, "labels": ["v3"],
                   "quote_symbol": "WETH", "liquidity_usd": 12345.0,
                   "volume_24h_usd": 999.0, "fdv": 1000000.0, "base_symbol": symbol}],
        "window": {"from_block": 100, "to_block": 200, "blocks": 101, "chunk_size": 5000},
        "head_endpoint": "https://example.invalid",
        "analysis": {
            "holders": holders,
            "transfers": [],
            "transfer_stats": {"chunks": 1, "raw_logs": 10, "skipped_blocks": []},
        },
    }
    lp_result = {"lp": {
        "pairs": holders_result["pairs"], "pair_count": 1,
        "top_pair": holders_result["pairs"][0], "lp_pair": holders_result["pairs"][0],
        "lp_pair_index": 0,
        "notes": ["note one"],
        "lp": {"determined": True, "known": True, "address": "0x" + "b" * 40,
               "total_supply": 1000, "burned": 500, "locked_by_pool": 0, "floating": 500,
               "burned_pct": 0.5, "locked_pct": 0.0, "floating_pct": 0.5,
               "total_supply_display": "1,000", "burned_display": "500",
               "locked_display": "0", "floating_display": "500"},
    }}
    insiders = {"rows": [{"address": "0x" + "c" * 40, "first_block": 101, "first_tx": "0xdead",
                          "bought_raw": 10, "bought": "10", "current_balance_raw": 10,
                          "current_balance": "10", "still_holds": True, "share_of_supply": 0.01,
                          "share_of_tracked": 0.01}],
                "summary": {"requested": 100, "found": 1, "still_holding": 1, "exited": 0,
                            "combined_share_of_supply": 0.01}}
    ctx = {"command": "forensics report --chain base --token 0x" + "a" * 40,
           "generated_at": "2026-01-01T00:00:00Z", "chain": "base",
           "token": "0x" + "a" * 40, "rpc_endpoint": "https://example.invalid",
           "block_range": "100-200 (101 blocks)", "duration": "1.0s",
           "dexscreener": "https://api.dexscreener.com/latest/dex/tokens/0x" + "a" * 40,
           "rpc_summary": {"chain": "base", "requests": 3}}
    return report.build_model("base", "0x" + "a" * 40, meta, holders_result, lp_result,
                              insiders, ctx, warnings=["a warning"])


class TestReportModel(unittest.TestCase):
    def test_schema_keys_present(self):
        model = _fake_model()
        for key in ("schema", "tool", "version", "generated_at", "chain", "token",
                    "symbol", "decimals", "total_supply_raw", "context", "window",
                    "holders", "transfer_stats", "pairs", "lp", "insiders",
                    "warnings", "rpc"):
            self.assertIn(key, model, "missing key %r" % key)
        self.assertEqual(model["schema"], "forensics.report/1")
        self.assertEqual(model["tool"], "forensics")

    def test_json_round_trip(self):
        model = _fake_model()
        text = report.to_json(model)
        again = json.loads(text)
        self.assertEqual(again["schema"], model["schema"])
        self.assertEqual(again["holders"]["nonzero_holders"],
                         model["holders"]["nonzero_holders"])
        self.assertIsInstance(again["pairs"], list)
        self.assertIsInstance(again["holders"]["rows"], list)

    def test_holder_rows_have_required_fields(self):
        model = _fake_model()
        for row in model["holders"]["rows"]:
            for field in ("rank", "address", "balance_raw", "balance", "share"):
                self.assertIn(field, row)

    def test_context_carries_reproducibility_fields(self):
        ctx = _fake_model()["context"]
        for field in ("command", "generated_at", "rpc_endpoint", "block_range"):
            self.assertTrue(ctx.get(field), "context.%s is empty" % field)

    def test_html_is_self_contained(self):
        html = report.build_report(_fake_model())
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("@import", html)
        self.assertNotIn("fonts.googleapis", html)
        self.assertNotIn("cdn.", html.lower())
        self.assertIn("<style>", html)
        self.assertIn("<svg", html)
        self.assertIn("What this report cannot tell you", html)

    def test_html_has_balanced_tags(self):
        from html.parser import HTMLParser

        class V(HTMLParser):
            VOID = {"meta", "br", "img", "hr", "input", "link", "path", "rect",
                    "text", "circle"}

            def __init__(self):
                HTMLParser.__init__(self)
                self.stack = []
                self.errors = []

            def handle_starttag(self, tag, attrs):
                if tag not in self.VOID:
                    self.stack.append(tag)

            def handle_endtag(self, tag):
                if tag in self.VOID:
                    return
                if self.stack and self.stack[-1] == tag:
                    self.stack.pop()
                else:
                    self.errors.append(tag)

        parser = V()
        parser.feed(report.build_report(_fake_model()))
        self.assertEqual(parser.stack, [])
        self.assertEqual(parser.errors, [])

    def test_numbers_appear_in_html(self):
        html = report.build_report(_fake_model())
        self.assertIn("EXTREME", html)
        self.assertIn("50.00%", html)      # top-10 share rendered

    def test_lp_section_renders_burn_pct(self):
        html = report.build_report(_fake_model())
        self.assertIn("LP token", html)
        self.assertIn("50.00%", html)

    def test_insiders_section_says_early_buyers(self):
        html = report.build_report(_fake_model())
        self.assertIn("early buyers", html.lower())
        self.assertIn("not insiders", html.lower())


class TestHtmlEscaping(unittest.TestCase):
    XSS = '<script>alert("pwn")</script><img src=x onerror=alert(1)>'

    def test_token_symbol_is_escaped(self):
        html = report.build_report(_fake_model(symbol=self.XSS))
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_esc_handles_none_and_quotes(self):
        self.assertEqual(report.esc(None), "")
        self.assertEqual(report.esc('a"b'), "a&quot;b")
        self.assertEqual(report.esc("<b>"), "&lt;b&gt;")

    def test_warning_text_is_escaped(self):
        model = _fake_model()
        model["warnings"] = [self.XSS]
        html = report.build_report(model)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_address_with_quotes_cannot_break_out(self):
        model = _fake_model()
        model["holders"]["rows"][0]["address"] = '"><script>x</script>'
        html = report.build_report(model)
        self.assertNotIn("<script>x</script>", html)

    def test_lp_note_is_escaped(self):
        model = _fake_model()
        model["lp"]["notes"] = [self.XSS]
        html = report.build_report(model)
        self.assertNotIn("<script>alert", html)


class TestSvg(unittest.TestCase):
    def test_bar_chart_has_one_rect_per_row(self):
        rows = [{"address": "0x" + "%040x" % i, "share": 0.1 * (i + 1)} for i in range(5)]
        svg = report.svg_bar_chart(rows)
        self.assertEqual(svg.count("<rect"), 5)
        self.assertTrue(svg.startswith("<svg"))

    def test_bar_chart_empty(self):
        self.assertIn("no holder rows", report.svg_bar_chart([]))

    def test_gauge_clamps(self):
        for value in (-1, 0, 0.5, 1, 2, None):
            svg = report.svg_gauge(value)
            self.assertIn("<svg", svg)
            self.assertIn("</svg>", svg)


class TestVerdictWording(unittest.TestCase):
    """The tool must never claim knowledge it does not have."""

    def test_insiders_are_labelled_early_buyers(self):
        import inspect
        doc = inspect.getdoc(evm.early_buyers)
        self.assertIn("early buyer", doc)
        self.assertIn("not evidence", doc)

    def test_lp_never_invents_address(self):
        addr, reason = evm.lp_token_address({
            "dex": "uniswap", "pair_address": "0xdeadbeef", "labels": []})
        self.assertIsNone(addr)
        self.assertTrue(reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
