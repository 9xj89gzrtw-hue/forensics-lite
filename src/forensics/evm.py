"""EVM side: token metadata, transfer-log holder scan, early buyers, LP analysis.

All contract calls use hand-encoded selectors. We cannot compute keccak256 with
the standard library, so the four-byte selectors we need are constants:

============  ==========  ==================================================
function      selector    notes
============  ==========  ==================================================
transfer      0xddf252ad  event topic, not a selector (keccak of the sig)
balanceOf     0x70a08231
decimals      0x313ce567
symbol        0x95d89b41
name          0x06fdde03
totalSupply   0x18160ddd
============  ==========  ==================================================
"""

import concurrent.futures
import time

from . import metrics
from .metrics import normalise_address
from .rpc import (
    DEXSCREENER_CHAIN,
    INFRA_ADDRESSES,
    ZERO_ADDRESS,
    RpcError,
    http_json,
)

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SEL_BALANCE_OF = "0x70a08231"
SEL_DECIMALS = "0x313ce567"
SEL_SYMBOL = "0x95d89b41"
SEL_NAME = "0x06fdde03"
SEL_TOTAL_SUPPLY = "0x18160ddd"

DEXSCREENER_TOKEN_URL = "https://api.dexscreener.com/latest/dex/tokens/%s"

#: Dex ids whose pair contract *is* the fungible LP token.
LP_IS_PAIR_DEXES = {
    "uniswap", "pancakeswap", "sushiswap", "baseswap", "swapbased", "alien-base",
    "aerodrome", "aero", "velodrome", "velodrome-v2", "solidly", "equalizer",
    "thena", "ramses", "hydrex", "dackieswap", "kimav2",
}

#: Dex ids where liquidity is an NFT position or a singleton pool: no LP token.
NO_LP_TOKEN_LABELS = {"v3", "v4", "CLAMM", "concentrated"}


class TokenError(RpcError):
    pass


# --------------------------------------------------------------- metadata ---
def _pad_address(address):
    addr = normalise_address(address)
    if not addr:
        raise TokenError("invalid address: %r" % (address,))
    return addr[2:].rjust(64, "0")


def get_token_meta(pool, token):
    """Read symbol/name/decimals/totalSupply. Missing pieces degrade to defaults."""
    token = normalise_address(token)
    meta = {
        "address": token,
        "symbol": None,
        "name": None,
        "decimals": 18,
        "total_supply_raw": 0,
        "decimals_source": "default",
        "warnings": [],
    }

    res, _ = pool.eth_call(token, SEL_DECIMALS)
    if res:
        value = metrics.decode_uint256(res, -1)
        if 0 <= value <= 36:
            meta["decimals"] = value
            meta["decimals_source"] = "contract"

    res, _ = pool.eth_call(token, SEL_SYMBOL)
    if res:
        meta["symbol"] = metrics.decode_abi_string(res)

    res, _ = pool.eth_call(token, SEL_NAME)
    if res:
        meta["name"] = metrics.decode_abi_string(res)

    res, _ = pool.eth_call(token, SEL_TOTAL_SUPPLY)
    if res:
        meta["total_supply_raw"] = metrics.decode_uint256(res, 0)

    if not meta["symbol"]:
        meta["symbol"] = "UNKNOWN"
        meta["warnings"].append("symbol() could not be read; using UNKNOWN")
    if not meta["name"]:
        meta["name"] = meta["symbol"]
    if meta["total_supply_raw"] == 0:
        meta["warnings"].append("totalSupply() returned 0 or could not be read")
    return meta


def get_balance(pool, token, holder):
    """balanceOf(holder) -> int raw. Returns None if the call failed."""
    data = SEL_BALANCE_OF + _pad_address(holder)
    try:
        res, _ = pool.eth_call(token, data, attempts=2)
    except RpcError:
        return None
    if not res or res == "0x":
        return None
    return metrics.decode_uint256(res, 0)


def get_balances(pool, token, holders, concurrency=8, progress=None):
    """Read balanceOf for many holders in a thread pool.

    Returns ``(balances, failures)`` where ``balances`` maps address -> raw int.
    A holder whose call fails after retries is simply absent; we never invent a
    zero, because "0" and "unknown" mean different things.
    """
    balances = {}
    failures = []
    total = len(holders)
    done = 0
    if not holders:
        return balances, failures

    def work(addr):
        return addr, get_balance(pool, token, addr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(concurrency))) as ex:
        futures = {ex.submit(work, h): h for h in holders}
        for fut in concurrent.futures.as_completed(futures):
            addr = futures[fut]
            try:
                addr, value = fut.result()
            except Exception as exc:  # defensive: a thread must not kill the scan
                failures.append((addr, str(exc)))
                value = None
            done += 1
            if value is None:
                failures.append((addr, "call failed"))
            else:
                balances[addr] = value
            if progress and (done % 25 == 0 or done == total):
                progress(done, total)
    return balances, failures


# ------------------------------------------------------------ dexscreener ---
def fetch_pairs(chain, token, timeout=25.0):
    """DexScreener pairs for a token, filtered to the requested chain."""
    token = normalise_address(token) or token
    data, endpoint = http_json(DEXSCREENER_TOKEN_URL % token, timeout=timeout)
    wanted = DEXSCREENER_CHAIN.get(chain, chain)
    pairs = []
    for raw in (data.get("pairs") or []):
        if raw.get("chainId") != wanted:
            continue
        pairs.append(_normalise_pair(raw, token))
    pairs.sort(key=lambda p: p.get("liquidity_usd") or 0, reverse=True)
    return pairs, endpoint


def _normalise_pair(raw, token):
    base = raw.get("baseToken") or {}
    quote = raw.get("quoteToken") or {}
    labels = raw.get("labels") or []
    liquidity = raw.get("liquidity") or {}
    volume = raw.get("volume") or {}
    txns = (raw.get("txns") or {}).get("h24") or {}
    created = raw.get("pairCreatedAt")
    pair_raw = raw.get("pairAddress") or ""
    pair_norm = normalise_address(pair_raw)
    # Uniswap v4 identifies a pool by a 32-byte id, not an address. Normalising
    # it to 20 bytes would silently invent a different, unrelated address.
    is_bytes32 = len(str(pair_raw)) == 66
    return {
        "dex": raw.get("dexId") or "unknown",
        "pair_address": (str(pair_raw).lower() if is_bytes32 else (pair_norm or pair_raw)),
        "is_bytes32_pool_id": is_bytes32,
        "labels": labels,
        "base_symbol": base.get("symbol"),
        "base_address": normalise_address(base.get("address")),
        "quote_symbol": quote.get("symbol"),
        "quote_address": normalise_address(quote.get("address")),
        "liquidity_usd": _num(liquidity.get("usd")),
        "volume_24h_usd": _num(volume.get("h24")),
        "price_usd": _num(raw.get("priceUsd")),
        "price_native": _num(raw.get("priceNative")),
        "fdv": _num(raw.get("fdv")),
        "market_cap": _num(raw.get("marketCap")),
        "buys_24h": txns.get("buys"),
        "sells_24h": txns.get("sells"),
        "created_at_ms": created,
        "url": raw.get("url"),
        "is_our_base": normalise_address(base.get("address")) == token,
    }


def _num(value):
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def pool_addresses(pairs):
    """Pair/pool addresses that must never be counted as holders."""
    out = set()
    for pair in pairs:
        addr = normalise_address(pair.get("pair_address"))
        # Uniswap v4 "pairAddress" is a bytes32 pool id, not an address: it will
        # not normalise to a 20-byte address, so it is skipped here on purpose.
        if addr and len(addr) == 42:
            out.add(addr)
    out.update(INFRA_ADDRESSES)
    # 0x...dEaD is a burn sink, not a holder. Counting it as a whale would be
    # technically true and completely misleading.
    out.add(metrics.DEAD)
    return out


# ----------------------------------------------------------- transfer scan ---
def scan_transfers(pool, token, from_block, to_block, chunk_size=5000, progress=None):
    """eth_getLogs Transfer events -> normalised records + fetch stats."""
    token = normalise_address(token)
    logs, stats = pool.get_logs(
        token, [TRANSFER_TOPIC], from_block, to_block,
        chunk_size=chunk_size, progress=progress,
    )
    transfers = []
    skipped = 0
    for entry in logs:
        topics = entry.get("topics") or []
        if len(topics) < 3:
            skipped += 1
            continue
        if normalise_address(entry.get("address")) not in (token, ""):
            # Some nodes ignore the address filter; re-check defensively.
            skipped += 1
            continue
        src = metrics.topic_to_address(topics[1])
        dst = metrics.topic_to_address(topics[2])
        if not src or not dst:
            skipped += 1
            continue
        transfers.append({
            "block": metrics.parse_uint(entry.get("blockNumber")),
            "tx": entry.get("transactionHash"),
            "log_index": metrics.parse_uint(entry.get("logIndex")),
            "from": src,
            "to": dst,
            "value": metrics.parse_uint(entry.get("data")),
        })
    transfers.sort(key=lambda t: (t["block"], t["log_index"]))
    stats["raw_logs"] = len(logs)
    stats["skipped_logs"] = skipped
    return transfers, stats


# ----------------------------------------------------------------- holders ---
def holders_analysis(pool, token, meta, pairs, from_block, to_block,
                     chunk_size=5000, top=50, concurrency=8, progress=None):
    """Full holder scan: logs -> unique addresses -> balances -> metrics."""
    transfers, stats = scan_transfers(
        pool, token, from_block, to_block, chunk_size=chunk_size, progress=progress
    )
    excluded = pool_addresses(pairs)

    seen = {}
    for t in transfers:
        for side in ("from", "to"):
            addr = t[side]
            if addr == ZERO_ADDRESS or addr in excluded:
                continue
            if addr not in seen:
                seen[addr] = t["block"]

    candidates = sorted(seen.keys(), key=lambda a: seen[a])
    balances, failures = get_balances(
        pool, token, candidates, concurrency=concurrency, progress=progress
    )

    decimals = meta["decimals"]
    nonzero = [(addr, raw) for addr, raw in balances.items() if raw > 0]
    nonzero.sort(key=lambda kv: kv[1], reverse=True)

    tracked_raw = sum(raw for _, raw in nonzero)
    values = [raw for _, raw in nonzero]
    total_supply_raw = meta.get("total_supply_raw") or 0

    # Shares are computed against tracked supply (sum of balances we actually
    # read). When totalSupply is available we also report the coverage.
    shares = metrics.top_shares(values, tracked_raw, ns=(1, 5, 10, 50))
    verdict, reason = metrics.concentration_verdict(
        shares["top1"], shares["top10"], len(nonzero)
    )
    coverage = metrics.safe_div(tracked_raw, total_supply_raw)
    if total_supply_raw and coverage < 0.25:
        # Never let a 6% sample look like a verdict on the whole token.
        reason += (" - shares are of the %s we could see (%.1f%% of totalSupply)"
                   % (metrics.format_amount(tracked_raw, decimals), coverage * 100))

    rows = []
    for rank, (addr, raw) in enumerate(nonzero[:max(top, 50)], start=1):
        rows.append({
            "rank": rank,
            "address": addr,
            "balance_raw": raw,
            "balance": metrics.format_amount(raw, decimals),
            "share": (raw / tracked_raw) if tracked_raw else 0.0,
            "share_of_supply": metrics.safe_div(raw, total_supply_raw),
        })

    zero_balance = sum(1 for raw in balances.values() if raw == 0)

    # Burned supply is reported separately: it is real supply, but it is not a
    # holder and it must not inflate concentration.
    burned_dead = get_balance(pool, token, metrics.DEAD) or 0
    burned_zero = get_balance(pool, token, metrics.ZERO) or 0

    return {
        "holders": {
            "burned_dead_raw": burned_dead,
            "burned_zero_raw": burned_zero,
            "burned_total": metrics.format_amount(burned_dead + burned_zero, decimals),
            "burned_pct_of_supply": metrics.safe_div(burned_dead + burned_zero, total_supply_raw),
            "unique_addresses_seen": len(candidates),
            "balances_read": len(balances),
            "balances_failed": len(failures),
            "nonzero_holders": len(nonzero),
            "zero_balance_holders": zero_balance,
            "excluded_pool_addresses": sorted(excluded),
            "tracked_supply_raw": tracked_raw,
            "tracked_supply": metrics.format_amount(tracked_raw, decimals),
            "total_supply_raw": total_supply_raw,
            "total_supply": metrics.format_amount(total_supply_raw, decimals),
            "coverage_of_total_supply": metrics.safe_div(tracked_raw, total_supply_raw),
            "top1_share": shares["top1"],
            "top5_share": shares["top5"],
            "top10_share": shares["top10"],
            "top50_share": shares["top50"],
            "gini": metrics.gini(values),
            "hhi": metrics.hhi(values, tracked_raw),
            "dust_wallets": metrics.dust_count(values, tracked_raw, 0.0001),
            "dust_threshold_pct": 0.01,
            "verdict": verdict,
            "verdict_reason": reason,
            "rows": rows,
        },
        "transfers": transfers,
        "transfer_stats": stats,
        "balances": balances,
        "excluded": sorted(excluded),
        "failures": failures[:20],
    }


# ------------------------------------------------------------ early buyers ---
def early_buyers(transfers, excluded, balances, decimals, total_supply_raw,
                 first_n=100, max_rank=None):
    """First distinct recipients of transfers that came from a pool/router/mint.

    Labelled "early buyer" on purpose: a transfer from a pool is evidence of a
    swap, not evidence of intent or of privileged information.
    """
    limit = int(max_rank if max_rank is not None else first_n)
    excluded = set(excluded) | {ZERO_ADDRESS}
    out = []
    seen = set()
    for t in transfers:
        if len(out) >= first_n:
            break
        if t["from"] not in excluded:
            continue
        if t["to"] in seen:
            continue
        if t["to"] == ZERO_ADDRESS:
            continue
        seen.add(t["to"])
        raw = balances.get(t["to"])
        out.append({
            "address": t["to"],
            "first_block": t["block"],
            "first_tx": t["tx"],
            "bought_raw": t["value"],
            "bought": metrics.format_amount(t["value"], decimals),
            "current_balance_raw": raw,
            "current_balance": (metrics.format_amount(raw, decimals)
                                if raw is not None else "unknown"),
            "still_holds": bool(raw and raw > 0),
            "share_of_supply": metrics.safe_div(raw or 0, total_supply_raw),
            "share_of_tracked": None,
        })
    tracked = sum(balances.values()) if balances else 0
    for row in out:
        row["share_of_tracked"] = metrics.safe_div(row["current_balance_raw"] or 0, tracked)
    return out[:limit]


# -------------------------------------------------------------- LP section ---
def lp_token_address(pair):
    """Best-effort LP token resolution, or ``(None, reason)``.

    Never guesses an address: returns None with an explanation when the pool
    type has no fungible LP token.
    """
    labels = {str(x).lower() for x in (pair.get("labels") or [])}
    dex = (pair.get("dex") or "").lower()
    raw = str(pair.get("pair_address") or "")
    if pair.get("is_bytes32_pool_id") or len(raw) == 66:
        return None, ("Uniswap v4 pool identified by a bytes32 pool id inside the "
                      "PoolManager singleton; there is no LP token")
    addr = normalise_address(raw)
    if not addr or len(addr) != 42:
        return None, "pair address is not a 20-byte address, so it cannot be an LP token"
    if labels & {"v3", "clamm", "concentrated"}:
        return None, ("%s concentrated-liquidity pool: positions are NFTs "
                      "(ERC-721), there is no fungible LP token to burn" % (dex or "this"))
    if labels & {"v4"}:
        return None, "Uniswap v4 pool: liquidity lives in the PoolManager singleton, no LP token"
    if dex in LP_IS_PAIR_DEXES:
        return addr, None
    return addr, "unrecognised dex %r: assuming the pair contract is the LP token (verify)" % dex


def lp_analysis(pool, chain, token, pairs, probe_unknown=True):
    """LP supply / burned / pool-held / floating for the deepest usable pair.

    Walks pairs from deepest liquidity down and uses the first one whose LP
    token can actually be identified. The deepest pair often has no fungible LP
    token (Uniswap v3 NFTs, v4 singleton), so stopping at pair #1 would produce a
    useless "cannot determine" on most real tokens.
    """
    result = {
        "pairs": pairs,
        "pair_count": len(pairs),
        "top_pair": None,
        "lp_pair": None,
        "lp_pair_index": None,
        "lp": None,
        "notes": [],
        "skipped_pairs": [],
    }
    if not pairs:
        result["notes"].append("DexScreener returned no pairs for this token on %s" % chain)
        return result

    result["top_pair"] = pairs[0]
    chosen = None
    chosen_addr = None
    total_raw = 0
    for index, pair in enumerate(pairs):
        addr, reason = lp_token_address(pair)
        if addr is None:
            result["skipped_pairs"].append({
                "index": index, "dex": pair.get("dex"),
                "pair_address": pair.get("pair_address"), "reason": reason,
            })
            continue
        # Verify it really is an ERC-20 LP token: several pool types expose an
        # address that is *not* an LP token (proxies, Slipstream pools, v3
        # wrappers) and simply revert or return empty on totalSupply().
        try:
            res, _ = pool.eth_call(addr, SEL_TOTAL_SUPPLY, attempts=2)
        except RpcError:
            res = None
        supply = metrics.decode_uint256(res, 0) if res else 0
        if supply <= 0:
            result["skipped_pairs"].append({
                "index": index, "dex": pair.get("dex"),
                "pair_address": pair.get("pair_address"),
                "reason": "pair contract does not answer ERC-20 totalSupply() "
                          "(not a fungible LP token)",
            })
            continue
        chosen, chosen_addr, total_raw = pair, addr, supply
        result["lp_pair_index"] = index
        break

    if chosen is None:
        reasons = sorted({s["reason"] for s in result["skipped_pairs"]})
        result["lp"] = {
            "address": None,
            "determined": False,
            "reason": ("no pair on %s exposes a fungible ERC-20 LP token: %s"
                       % (chain, "; ".join(reasons))),
            "total_supply": None,
            "burned": None,
            "locked_by_pool": None,
            "floating": None,
            "burned_pct": None,
            "locked_pct": None,
            "floating_pct": None,
            "known": False,
        }
        result["notes"].append("LP token could not be determined: %s" % result["lp"]["reason"])
        return result

    result["lp_pair"] = chosen
    if result["lp_pair_index"] != 0:
        result["notes"].append(
            "the %d deeper pair(s) have no fungible LP token (v3/v4/concentrated "
            "liquidity or a non-ERC20 pool); LP numbers below are for pair #%d "
            "(%s, %s)" % (result["lp_pair_index"], result["lp_pair_index"] + 1,
                          chosen.get("dex"), chosen.get("pair_address"))
        )

    burned = get_balance(pool, chosen_addr, ZERO_ADDRESS) or 0
    # Dead address is a common burn sink as well.
    dead = get_balance(pool, chosen_addr, "0x000000000000000000000000000000000000dEaD") or 0
    burned_total = burned + dead
    locked = get_balance(pool, chosen_addr, chosen.get("pair_address")) or 0

    maths = metrics.lp_burn_math(total_raw, burned_total, locked)
    lp_decimals = 18
    try:
        res, _ = pool.eth_call(chosen_addr, SEL_DECIMALS, attempts=1)
        dec = metrics.decode_uint256(res, -1) if res else -1
        if 0 <= dec <= 36:
            lp_decimals = dec
    except RpcError:
        pass
    maths["address"] = chosen_addr
    maths["decimals"] = lp_decimals
    maths["total_supply_display"] = metrics.format_amount(total_raw, lp_decimals)
    maths["burned_display"] = metrics.format_amount(burned_total, lp_decimals)
    maths["locked_display"] = metrics.format_amount(locked, lp_decimals)
    maths["floating_display"] = metrics.format_amount(maths["floating"], lp_decimals)
    maths["determined"] = True
    maths["reason"] = None
    maths["burned_zero_address"] = burned
    maths["burned_dead_address"] = dead
    maths["pair_address"] = chosen.get("pair_address")
    maths["dex"] = chosen.get("dex")
    result["lp"] = maths
    result["notes"].append(
        "LP tokens staked in a gauge or farm are indistinguishable from floating "
        "supply with this method; only 0x0 / 0x...dEaD and the pair itself are counted."
    )
    return result


def run_holders(pool, chain, token, blocks, from_block, top, chunk_size,
                concurrency, progress=None):
    """Convenience wrapper used by the CLI and the report command."""
    latest, endpoint = pool.block_number()
    start = int(from_block) if from_block is not None else max(0, latest - int(blocks))
    if start > latest:
        raise TokenError("--from-block %d is ahead of the chain head %d" % (start, latest))
    meta = get_token_meta(pool, token)
    try:
        pairs, ds_endpoint = fetch_pairs(chain, token)
    except RpcError:
        pairs, ds_endpoint = [], None
    analysis = holders_analysis(
        pool, token, meta, pairs, start, latest,
        chunk_size=chunk_size, top=top, concurrency=concurrency, progress=progress,
    )
    return {
        "meta": meta,
        "pairs": pairs,
        "dexscreener_endpoint": ds_endpoint,
        "window": {
            "from_block": start,
            "to_block": latest,
            "blocks": latest - start + 1,
            "chunk_size": chunk_size,
        },
        "head_endpoint": endpoint.url if endpoint else None,
        "analysis": analysis,
    }


def run_lp(pool, chain, token, progress=None):
    meta = get_token_meta(pool, token)
    pairs, ds_endpoint = fetch_pairs(chain, token)
    lp = lp_analysis(pool, chain, token, pairs)
    return {"meta": meta, "dexscreener_endpoint": ds_endpoint, "lp": lp}


def run_insiders(pool, chain, token, first_n=100, blocks=50000, from_block=None,
                 chunk_size=5000, concurrency=8, progress=None):
    latest, endpoint = pool.block_number()
    start = int(from_block) if from_block is not None else max(0, latest - int(blocks))
    meta = get_token_meta(pool, token)
    try:
        pairs, _ = fetch_pairs(chain, token)
    except RpcError:
        pairs = []
    transfers, stats = scan_transfers(pool, token, start, latest,
                                      chunk_size=chunk_size, progress=progress)
    excluded = pool_addresses(pairs)
    addrs = []
    seen = set()
    for t in transfers:
        if t["from"] in excluded and t["to"] not in seen and t["to"] != ZERO_ADDRESS:
            seen.add(t["to"])
            addrs.append(t["to"])
        if len(addrs) >= max(first_n * 3, 150):
            break
    balances, failures = get_balances(pool, token, addrs, concurrency=concurrency)
    rows = early_buyers(transfers, excluded, balances, meta["decimals"],
                        meta.get("total_supply_raw") or 0, first_n=first_n)
    still = sum(1 for r in rows if r["still_holds"])
    return {
        "meta": meta,
        "window": {"from_block": start, "to_block": latest,
                   "blocks": latest - start + 1, "chunk_size": chunk_size},
        "head_endpoint": endpoint.url if endpoint else None,
        "excluded": sorted(excluded),
        "stats": stats,
        "rows": rows,
        "summary": {
            "requested": first_n,
            "found": len(rows),
            "still_holding": still,
            "exited": len(rows) - still,
            "combined_share_of_supply": sum(r["share_of_supply"] for r in rows),
            "balances_failed": len(failures),
        },
    }
