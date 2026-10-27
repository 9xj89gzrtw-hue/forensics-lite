"""Pure functions: concentration metrics, LP burn math, parsing helpers.

Everything here is side-effect free and unit-tested offline, so the numbers in a
report can be reproduced without touching the network.
"""

import math

ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"

# Thresholds for the human-readable verdict. Documented in README so users can
# disagree with them on purpose.
THRESHOLDS = {
    "extreme_top1": 0.50,
    "extreme_top10": 0.90,
    "high_top1": 0.25,
    "high_top10": 0.70,
    "moderate_top10": 0.50,
    "thin_holders": 30,
}


# ---------------------------------------------------------------- parsing ---
def normalise_address(value):
    """Lowercase a hex address / topic word, or return '' if it is not one."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.hex()
    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    if not text:
        return ""
    if len(text) < 40:
        return ""
    text = text[-40:]
    if any(c not in "0123456789abcdefABCDEF" for c in text):
        return ""
    return "0x" + text.lower()


def topic_to_address(topic):
    """Extract an address from a 32-byte log topic."""
    if not topic:
        return ""
    text = topic[2:] if topic.startswith("0x") else topic
    if len(text) < 40:
        return ""
    return normalise_address(text[-40:])


def is_zero_address(address):
    return normalise_address(address) == ZERO


def parse_uint(value, default=0):
    """Parse '0x...' or decimal into int. Never raises."""
    if value is None:
        return default
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except (TypeError, ValueError):
        return default


def parse_hex_quantity(value, default=0):
    return parse_uint(value, default)


def decode_uint256(hexdata, default=0):
    """Decode a 32-byte ABI uint from an eth_call return blob."""
    if not hexdata or not isinstance(hexdata, str):
        return default
    body = hexdata[2:] if hexdata.startswith("0x") else hexdata
    if len(body) < 64:
        return default
    try:
        return int(body[:64], 16)
    except ValueError:
        return default


def decode_abi_string(hexdata):
    """Decode symbol()/name() for both ``string`` and ``bytes32`` returns."""
    if not hexdata or not isinstance(hexdata, str) or len(hexdata) < 3:
        return None
    body = hexdata[2:] if hexdata.startswith("0x") else hexdata
    try:
        raw = bytes.fromhex(body)
    except ValueError:
        return None
    if not raw:
        return None
    # bytes32 style: the whole word is the value, right padded with zeros.
    if len(raw) == 32:
        text = raw.split(b"\x00", 1)[0]
        return text.decode("utf-8", "replace").strip() or None
    # dynamic string: offset(32) | length(32) | data
    if len(raw) >= 64:
        try:
            length = int.from_bytes(raw[32:64], "big")
            if 0 < length <= 256 and 64 + length <= len(raw):
                text = raw[64:64 + length].decode("utf-8", "replace")
                cleaned = "".join(ch for ch in text if ch.isprintable()).strip()
                return cleaned or None
        except Exception:
            pass
    text = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
    cleaned = "".join(ch for ch in text if ch.isprintable()).strip()
    return cleaned or None


def format_amount(raw, decimals, precision=4):
    """Human-readable token amount. Returns a string, never raises."""
    try:
        raw = int(raw)
        decimals = int(decimals)
    except (TypeError, ValueError):
        return "0"
    if decimals < 0 or decimals > 36:
        decimals = 18
    if raw == 0:
        return "0"
    value = raw / float(10 ** decimals)
    if value == 0:
        return "<1e-%d" % max(1, decimals - 1)
    if value >= 1e12:
        return "%.2e" % value
    if value >= 1000:
        return "{:,.0f}".format(value)
    if value >= 1:
        return ("{:,.%df}" % precision).format(value).rstrip("0").rstrip(".")
    if value < 1e-6:
        # Never print a nonzero balance as "0": dust is a signal, not noise.
        return "%.2e" % value
    return ("{:.%df}" % max(precision, 6)).format(value).rstrip("0").rstrip(".")


def format_usd(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "n/a"
    if value >= 1e9:
        return "$%.2fB" % (value / 1e9)
    if value >= 1e6:
        return "$%.2fM" % (value / 1e6)
    if value >= 1e3:
        return "$%.1fK" % (value / 1e3)
    return "$%.0f" % value


# ------------------------------------------------------------- chunk math ---
def plan_chunks(from_block, to_block, chunk_size):
    """Inclusive, gap-free, non-overlapping block ranges covering the window.

    >>> plan_chunks(0, 9, 5)
    [(0, 4), (5, 9)]
    """
    from_block = int(from_block)
    to_block = int(to_block)
    chunk_size = int(chunk_size)
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    if to_block < from_block:
        return []
    chunks = []
    cur = from_block
    while cur <= to_block:
        end = min(cur + chunk_size - 1, to_block)
        chunks.append((cur, end))
        cur = end + 1
    return chunks


def count_chunks(from_block, to_block, chunk_size):
    return len(plan_chunks(from_block, to_block, chunk_size))


# ------------------------------------------------------------ concentration --
def gini(values):
    """Gini coefficient of a list of non-negative numbers, 0..1.

    0 = perfectly equal, 1 = one wallet holds everything. Empty list or all-zero
    list returns 0.0 (no inequality can be measured).
    """
    nums = sorted(float(v) for v in values if v is not None)
    n = len(nums)
    if n == 0:
        return 0.0
    total = sum(nums)
    if total <= 0:
        return 0.0
    # Standard discrete formula: G = (2*sum(i*x_i) - (n+1)*sum(x)) / (n*sum(x))
    weighted = sum((i + 1) * x for i, x in enumerate(nums))
    value = (2.0 * weighted - (n + 1) * total) / (n * total)
    return max(0.0, min(1.0, value))


def share_of(values, total, n):
    """Sum of the top ``n`` values divided by ``total`` (0..1)."""
    if total <= 0:
        return 0.0
    top = sorted(values, reverse=True)[:max(0, int(n))]
    return max(0.0, min(1.0, sum(top) / float(total)))


def top_shares(values, total, ns=(1, 10, 50)):
    return dict(("top%d" % n, share_of(values, total, n)) for n in ns)


def dust_count(values, total, threshold=0.0001):
    """How many wallets hold strictly less than ``threshold`` of ``total``."""
    if total <= 0:
        return 0
    cutoff = total * float(threshold)
    return sum(1 for v in values if v < cutoff)


def hhi(values, total):
    """Herfindahl-Hirschman index on shares, 0..1 (1 = one wallet owns all)."""
    if total <= 0:
        return 0.0
    return sum((float(v) / total) ** 2 for v in values)


def concentration_verdict(top1_share, top10_share, holders):
    """Map concentration numbers to a label + short reason.

    Deliberately conservative: a token with fewer than
    ``THRESHOLDS['thin_holders']`` tracked holders can never be called
    "distributed" because the sample is too small to mean anything.
    """
    if holders <= 0:
        return ("UNKNOWN", "no holder balances could be read")
    if top1_share >= THRESHOLDS["extreme_top1"] or top10_share >= THRESHOLDS["extreme_top10"]:
        return ("EXTREME", "top-1 holds %.1f%%, top-10 holds %.1f%%"
                % (top1_share * 100, top10_share * 100))
    if top1_share >= THRESHOLDS["high_top1"] or top10_share >= THRESHOLDS["high_top10"]:
        return ("HIGH", "top-1 holds %.1f%%, top-10 holds %.1f%%"
                % (top1_share * 100, top10_share * 100))
    if holders < THRESHOLDS["thin_holders"]:
        return ("MODERATE", "only %d holders tracked; small sample" % holders)
    if top10_share >= THRESHOLDS["moderate_top10"]:
        return ("MODERATE", "top-10 holds %.1f%%" % (top10_share * 100))
    return ("DISTRIBUTED", "top-10 holds %.1f%% across %d holders"
            % (top10_share * 100, holders))


# ------------------------------------------------------------------- LP math --
def lp_burn_math(total_supply, burned, locked_by_pool):
    """Percentages of LP supply that are burned / pool-held / floating.

    Returns a dict with 0..1 fractions and raw values. Any input that is
    missing or larger than supply is clamped instead of producing nonsense.
    """
    total = max(0, int(total_supply or 0))
    burned = max(0, int(burned or 0))
    locked = max(0, int(locked_by_pool or 0))
    if total == 0:
        return {
            "total_supply": 0,
            "burned": burned,
            "locked_by_pool": locked,
            "floating": 0,
            "burned_pct": 0.0,
            "locked_pct": 0.0,
            "floating_pct": 0.0,
            "known": False,
        }
    burned = min(burned, total)
    locked = min(locked, total - burned)
    floating = max(0, total - burned - locked)
    return {
        "total_supply": total,
        "burned": burned,
        "locked_by_pool": locked,
        "floating": floating,
        "burned_pct": burned / float(total),
        "locked_pct": locked / float(total),
        "floating_pct": floating / float(total),
        "known": True,
    }


def pct(value, digits=2):
    try:
        return ("%." + str(digits) + "f%%") % (float(value) * 100)
    except (TypeError, ValueError):
        return "n/a"


def safe_div(a, b, default=0.0):
    try:
        b = float(b)
        if b == 0:
            return default
        return float(a) / b
    except (TypeError, ValueError):
        return default


def mean(values):
    vals = [float(v) for v in values if v is not None]
    if not vals:
        return 0.0
    return sum(vals) / len(vals)


def stddev(values):
    vals = [float(v) for v in values if v is not None]
    if len(vals) < 2:
        return 0.0
    m = mean(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / (len(vals) - 1))
