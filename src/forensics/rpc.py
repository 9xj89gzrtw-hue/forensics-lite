"""JSON-RPC transport with multi-endpoint rotation, failover and adaptive log chunking.

Design notes (these are real constraints observed on the public endpoints):

* ``https://mainnet.base.org`` answers ``eth_blockNumber``/``eth_call`` but rejects
  ``eth_getLogs`` with ``-32011 request limit reached``. It is still useful for
  balance reads, so it stays in the pool with a "no logs" mark instead of being
  dropped.
* ``https://base-rpc.publicnode.com`` serves ``eth_getLogs`` but caps a single
  response at 20000 results and *tells you the range it would accept*:
  ``query exceeds max results 20000, retry with the range 53149696-53149963``.
  We parse that hint and re-chunk instead of guessing.
* ``https://1rpc.io/base`` serves ``eth_getLogs`` but only for a ~50 block span.
  We learn the cap once and shrink the chunk size for that endpoint.
* ``https://base.llamarpc.com`` was returning HTTP 525 during development; the
  failover path exists exactly for this.

Every HTTP request sends a ``User-Agent``: some public gateways answer 403 to the
default ``Python-urllib/3.x`` agent.
"""

import json
import random
import re
import socket
import time
import urllib.error
import urllib.request

USER_AGENT = "forensics/0.1 (+https://github.com/) python-stdlib"

#: Public, key-less endpoints. Order matters: the first one is tried first.
CHAINS = {
    "base": [
        "https://mainnet.base.org",
        "https://base-rpc.publicnode.com",
        "https://base.llamarpc.com",
        "https://1rpc.io/base",
    ],
    "ethereum": [
        "https://ethereum-rpc.publicnode.com",
        "https://eth.llamarpc.com",
        "https://1rpc.io/eth",
    ],
    "arbitrum": [
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
    ],
    "optimism": [
        "https://optimism-rpc.publicnode.com",
        "https://mainnet.optimism.io",
    ],
}

#: DexScreener uses these ids; our chain ids mostly match already.
DEXSCREENER_CHAIN = {
    "base": "base",
    "ethereum": "ethereum",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
}

#: Addresses that are never "holders": routers, permit2, v4 pool manager.
INFRA_ADDRESSES = {
    # Uniswap Universal Router (Base)
    "0x4752ba5dbc23f44d87826276bf6f6b1c372ad24",
    # Uniswap SwapRouter02 (Base)
    "0x2626664c2603336e57b271c5c0b26f421741e481",
    # Uniswap V4 PoolManager (same address on Base and most chains)
    "0x498581ff718922c3f8e6a244956af099b2652b2b",
    # Permit2
    "0x000000000022d473030f116ddee9f6b43ac78ba3",
    # Multicall3
    "0xca11bde05977b3631167028862be2a173976ca11",
}

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_RANGE_HINT_RE = re.compile(r"range\s+(\d+)\s*-\s*(\d+)", re.I)
_BLOCK_LIMIT_RE = re.compile(r"limited to\s+(\d+)\s*-\s*(\d+)\s*blocks", re.I)


class RpcError(Exception):
    """Base class for transport/protocol problems."""


class RpcUnavailable(RpcError):
    """Every endpoint failed for this call."""


class RpcProtocolError(RpcError):
    """The node answered with a JSON-RPC error we cannot work around."""

    def __init__(self, message, code=None, endpoint=None):
        super().__init__(message)
        self.code = code
        self.endpoint = endpoint


class RetryableRpcError(RpcError):
    """Transient: rate limit, 5xx, network drop. Try another endpoint."""


class RangeTooLarge(RpcError):
    """The node refuses the block range because it returns too many results."""

    def __init__(self, suggested_from, suggested_to, message=""):
        super().__init__(message or "range too large")
        self.suggested_from = suggested_from
        self.suggested_to = suggested_to


class RangeLimited(RpcError):
    """The node has a hard per-request block span limit."""

    def __init__(self, max_range, message=""):
        super().__init__(message or "range limited")
        self.max_range = max_range


class EndpointUnsupported(RpcError):
    """The node does not serve this method at all."""


class Endpoint(object):
    def __init__(self, url, name=None):
        self.url = url
        self.name = name or url.split("//", 1)[-1].split("/")[0]
        self.ok = 0
        self.fail = 0
        self.cooldown_until = 0.0
        self.max_block_range = None   # learned per-endpoint span cap
        self.logs_blocked = False     # endpoint refuses eth_getLogs outright
        self.last_error = None
        self.total_requests = 0

    # -- scoring -------------------------------------------------------
    @property
    def score(self):
        return (self.ok + 1.0) / (self.ok + self.fail + 2.0)

    def healthy(self, now=None):
        now = time.time() if now is None else now
        return self.cooldown_until <= now

    def penalise(self, seconds, err=None):
        self.fail += 1
        self.cooldown_until = max(self.cooldown_until, time.time() + seconds)
        if err:
            self.last_error = str(err)

    def reward(self):
        self.ok += 1

    def __repr__(self):
        return "<Endpoint %s ok=%d fail=%d>" % (self.name, self.ok, self.fail)


class RpcPool(object):
    """Rotating JSON-RPC client.

    ``call`` returns ``(result, endpoint)`` so callers can report which node
    actually served the request (the HTML report prints it).
    """

    def __init__(self, chain="base", endpoints=None, timeout=30.0, verbose=False,
                 max_attempts=None, backoff_base=0.6, time_budget=600.0):
        urls = list(endpoints or CHAINS.get(chain) or [])
        if not urls:
            raise RpcError("no RPC endpoints configured for chain %r" % (chain,))
        self.chain = chain
        self.endpoints = [Endpoint(u) for u in urls]
        self.timeout = timeout
        self.verbose = verbose
        self.max_attempts = max_attempts or max(3, len(self.endpoints))
        self.backoff_base = backoff_base
        self.time_budget = time_budget
        self.request_count = 0
        self.failover_count = 0
        self._last_used = None

    # -- low level -----------------------------------------------------
    def log(self, msg):
        if self.verbose:
            import sys
            sys.stderr.write("[rpc] %s\n" % msg)

    def _post(self, ep, method, params):
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            ep.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        self.request_count += 1
        ep.total_requests += 1
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read()[:200].decode("utf-8", "replace")
            except Exception:
                pass
            if exc.code in (408, 425, 429, 500, 502, 503, 504):
                raise RetryableRpcError("HTTP %s from %s %s" % (exc.code, ep.name, detail))
            if exc.code in (401, 403):
                raise RetryableRpcError("HTTP %s (blocked) from %s %s" % (exc.code, ep.name, detail))
            raise RpcProtocolError("HTTP %s from %s: %s" % (exc.code, ep.name, detail),
                                   code=exc.code, endpoint=ep.name)
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as exc:
            raise RetryableRpcError("network error from %s: %s" % (ep.name, exc))

        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            raise RetryableRpcError("non-JSON response from %s: %r" % (ep.name, raw[:120]))

        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            code = err.get("code")
            message = str(err.get("message") or err)
            self._classify(ep, method, code, message)
        if "result" not in data:
            raise RpcProtocolError("malformed response from %s: %r" % (ep.name, raw[:160]),
                                   endpoint=ep.name)
        return data["result"]

    def _classify(self, ep, method, code, message):
        """Turn a JSON-RPC error into the right exception type."""
        low = message.lower()

        m = _RANGE_HINT_RE.search(message)
        if m and ("exceed" in low or "max results" in low or "too many" in low
                  or "limit" in low or "range" in low):
            raise RangeTooLarge(int(m.group(1)), int(m.group(2)), message)

        m = _BLOCK_LIMIT_RE.search(message)
        if m:
            raise RangeLimited(int(m.group(2)) - int(m.group(1)) + 1, message)

        # -32011 "request limit reached" on base.org is how the public gateway
        # says "no eth_getLogs for you". It is permanent for logs, transient-ish
        # for everything else.
        if code == -32011 or "request limit reached" in low:
            if method == "eth_getLogs":
                ep.logs_blocked = True
                raise EndpointUnsupported("%s does not serve eth_getLogs (%s)" % (ep.name, message))
            raise RetryableRpcError("rate limited by %s: %s" % (ep.name, message))

        if code == -32601 or "method not found" in low or "not supported" in low \
                or "unsupported" in low or "does not exist" in low:
            if method == "eth_getLogs":
                ep.logs_blocked = True
            raise EndpointUnsupported("%s: %s" % (ep.name, message))

        if code == -32005 or "rate limit" in low or "too many requests" in low \
                or "capacity" in low or "busy" in low:
            raise RetryableRpcError("rate limited by %s: %s" % (ep.name, message))

        # eth_call reverts and similar are legitimate answers, not transport
        # failures: let the caller decide.
        raise RpcProtocolError(message, code=code, endpoint=ep.name)

    # -- endpoint selection --------------------------------------------
    def _candidates(self, allow_logs=False, healthy_only=True):
        now = time.time()
        pool = list(self.endpoints)
        if allow_logs:
            # logs_blocked is permanent: never fall back to it for logs.
            pool = [e for e in pool if not e.logs_blocked]
        if healthy_only:
            pool = [e for e in pool if e.healthy(now)]
        return pool

    def _pick(self, allow_logs=False, tried=()):
        cands = self._candidates(allow_logs=allow_logs)
        if not cands:
            return None
        fresh = [e for e in cands if e.name not in tried]
        return max(fresh or cands, key=lambda e: e.score)

    def _wait_for_cooldown(self, allow_logs=False):
        """Sleep only if some endpoint could actually come back."""
        recoverable = [e for e in self._candidates(allow_logs=allow_logs, healthy_only=False)]
        if not recoverable:
            return False
        now = time.time()
        wait = min(e.cooldown_until for e in recoverable) - now
        wait = max(0.0, min(wait, 25.0))
        if wait > 0:
            self.log("all endpoints cooling down, sleeping %.1fs" % wait)
            time.sleep(wait)
        return True

    def call(self, method, params=None, allow_logs=False, attempts=None, raise_on_error=True):
        """Run one JSON-RPC call with rotation + exponential backoff."""
        attempts = attempts or self.max_attempts
        tried = []
        last_exc = None
        for attempt in range(attempts):
            ep = self._pick(allow_logs=allow_logs, tried=tried)
            if ep is None:
                if not self._wait_for_cooldown(allow_logs=allow_logs):
                    break
                ep = self._pick(allow_logs=allow_logs, tried=tried)
            if ep is None:
                break
            tried.append(ep.name)
            try:
                result = self._post(ep, method, params)
            except EndpointUnsupported as exc:
                ep.penalise(120.0, exc)
                last_exc = exc
                self.log("endpoint %s unsupported for %s: %s" % (ep.name, method, exc))
                continue
            except RetryableRpcError as exc:
                delay = self.backoff_base * (2 ** attempt) + random.uniform(0, 0.3)
                ep.penalise(min(delay * 2, 30.0), exc)
                last_exc = exc
                self.failover_count += 1
                self.log("failover from %s (%s), backoff %.1fs" % (ep.name, exc, delay))
                time.sleep(min(delay, 8.0))
                continue
            except (RangeTooLarge, RangeLimited):
                raise
            except RpcProtocolError:
                raise
            ep.reward()
            self._last_used = ep
            return result, ep
        if not raise_on_error:
            return None, None
        raise RpcUnavailable(
            "%s failed on every endpoint (%s). Last error: %s"
            % (method, ", ".join(tried) or "none", last_exc)
        )

    # -- conveniences ---------------------------------------------------
    def block_number(self):
        res, ep = self.call("eth_blockNumber")
        return int(res, 16), ep

    def eth_call(self, to, data, block="latest", attempts=None):
        try:
            res, ep = self.call("eth_call", [{"to": to, "data": data}, block], attempts=attempts)
            return res, ep
        except RpcProtocolError as exc:
            # A revert is a normal answer for "this contract has no symbol()".
            if "revert" in str(exc).lower() or "invalid" in str(exc).lower():
                return None, None
            raise

    def get_logs(self, address, topics, from_block, to_block, chunk_size=5000,
                 progress=None, max_chunks=100000, time_budget=None):
        """Fetch logs in adaptive chunks.

        Returns ``(logs, stats)``. ``stats`` records what actually happened:
        chunk count, how many times we had to shrink, failovers, skipped blocks
        and the set of endpoints that served data.

        An endpoint that keeps failing is banned for the rest of the scan instead
        of being retried forever: a public node that rate-limits logs will keep
        rate-limiting them, and a scan that hangs is worse than one that fails
        with a clear message.
        """
        stats = {
            "requests": 0,
            "chunks": 0,
            "shrinks": 0,
            "failovers": 0,
            "skipped_blocks": [],
            "endpoints": {},
            "banned": {},
            "chunk_size_start": chunk_size,
        }
        budget = self.time_budget if time_budget is None else time_budget
        deadline = time.time() + budget if budget else None
        logs = []
        cur = int(from_block)
        to_block = int(to_block)
        size = max(1, int(chunk_size))
        guard = 0
        stall = 0
        last_cur = cur
        strikes = {}
        banned = set()

        def available():
            return [e for e in self._candidates(allow_logs=True) if e.name not in banned]

        while cur <= to_block:
            guard += 1
            if guard > max_chunks:
                raise RpcError("log scan aborted after %d chunks (raise --chunk-size)" % guard)
            if deadline and time.time() > deadline:
                raise RpcUnavailable(
                    "log scan exceeded its %.0fs time budget after %d/%d blocks; "
                    "narrow the window with --blocks or use --rpc with a dedicated node"
                    % (budget, cur - int(from_block), to_block - int(from_block) + 1)
                )
            if cur != last_cur:
                stall = 0
                last_cur = cur
            stall += 1
            if stall > 8:
                raise RpcUnavailable(
                    "eth_getLogs made no progress after %d attempts at block %d (%s). "
                    "Try --chunk-size 1000 or --rpc <your node>."
                    % (stall, cur, "; ".join("%s: %s" % kv for kv in stats["banned"].items())
                       or "no detail")
                )

            ep = None
            cands = available()
            if cands:
                ep = max(cands, key=lambda e: e.score)
            else:
                if not self._wait_for_cooldown(allow_logs=True):
                    raise RpcUnavailable(
                        "no configured endpoint can serve eth_getLogs (%s). "
                        "Pass --rpc with an endpoint that does, e.g. "
                        "https://base-rpc.publicnode.com"
                        % ", ".join("%s (%s)" % (e.name, stats["banned"].get(e.name, "no logs"))
                                    for e in self.endpoints)
                    )
                cands = available()
                ep = max(cands, key=lambda e: e.score) if cands else None
            if ep is None:
                raise RpcUnavailable(
                    "no endpoint available for eth_getLogs (%s)"
                    % ("; ".join("%s: %s" % kv for kv in stats["banned"].items())
                       or "all endpoints cooling down")
                )

            span = size
            if ep.max_block_range:
                span = min(span, ep.max_block_range)
            end = min(cur + span - 1, to_block)
            flt = {
                "fromBlock": hex(cur),
                "toBlock": hex(end),
                "address": address,
                "topics": topics,
            }
            try:
                result = self._post(ep, "eth_getLogs", [flt])
            except RangeLimited as exc:
                ep.max_block_range = max(1, exc.max_range)
                stats["shrinks"] += 1
                self.log("%s caps logs at %d blocks/request" % (ep.name, ep.max_block_range))
                size = min(size, ep.max_block_range)
                continue
            except RangeTooLarge as exc:
                new_end = min(end, exc.suggested_to)
                new_span = max(1, new_end - cur + 1)
                if new_span >= span and span == 1:
                    # A single block overflows the node's result cap: record and
                    # move on rather than looping forever.
                    stats["skipped_blocks"].append(cur)
                    self.log("block %d has too many logs for %s, skipped" % (cur, ep.name))
                    cur = end + 1
                    continue
                size = min(size, new_span)
                stats["shrinks"] += 1
                self.log("shrinking chunk to %d blocks (%s)" % (size, ep.name))
                continue
            except EndpointUnsupported as exc:
                ep.penalise(600.0, exc)
                banned.add(ep.name)
                stats["banned"][ep.name] = "no eth_getLogs"
                stats["failovers"] += 1
                self.log("endpoint %s cannot serve logs: %s" % (ep.name, exc))
                continue
            except RetryableRpcError as exc:
                strikes[ep.name] = strikes.get(ep.name, 0) + 1
                stats["failovers"] += 1
                self.failover_count += 1
                if strikes[ep.name] >= 3:
                    banned.add(ep.name)
                    ep.penalise(300.0, exc)
                    stats["banned"][ep.name] = "rate limited / unreachable"
                    self.log("banning %s for this scan: %s" % (ep.name, exc))
                    continue
                ep.penalise(3.0, exc)
                delay = min(self.backoff_base * (2 ** (strikes[ep.name] - 1)), 4.0)
                self.log("log fetch retry on %s in %.1fs: %s" % (ep.name, delay, exc))
                time.sleep(delay)
                continue
            except RpcProtocolError as exc:
                # e.g. "block range too wide" worded differently: shrink once, then give up.
                if stats["shrinks"] < 12 and span > 1:
                    size = max(1, span // 2)
                    stats["shrinks"] += 1
                    continue
                raise

            strikes[ep.name] = 0
            ep.reward()
            stats["requests"] += 1
            stats["chunks"] += 1
            stats["endpoints"][ep.name] = stats["endpoints"].get(ep.name, 0) + 1
            if isinstance(result, list):
                logs.extend(result)
            if progress:
                progress(cur, end, len(logs))
            cur = end + 1

        stats["chunk_size_end"] = size
        return logs, stats

    def summary(self):
        return {
            "chain": self.chain,
            "requests": self.request_count,
            "failovers": self.failover_count,
            "endpoints": [
                {
                    "name": e.name,
                    "url": e.url,
                    "ok": e.ok,
                    "fail": e.fail,
                    "logs_blocked": e.logs_blocked,
                    "max_block_range": e.max_block_range,
                    "last_error": e.last_error,
                }
                for e in self.endpoints
            ],
        }


def http_json(url, timeout=25.0, retries=3, backoff_base=0.8):
    """GET a JSON document with retry/backoff. Returns ``(data, endpoint)``.

    Used for DexScreener, which is a plain REST API with no key.
    """
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            return json.loads(raw.decode("utf-8", "replace")), url
        except urllib.error.HTTPError as exc:
            last = "HTTP %s" % exc.code
            if exc.code in (429, 500, 502, 503, 504):
                time.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.2))
                continue
            raise RpcProtocolError("DexScreener returned %s for %s" % (last, url),
                                   code=exc.code)
        except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
            last = str(exc)
            time.sleep(backoff_base * (2 ** attempt) + random.uniform(0, 0.2))
    raise RpcUnavailable("could not fetch %s after %d attempts (%s)" % (url, retries, last))


def probe(chain="base", timeout=15.0):
    """Check every configured endpoint; used by ``forensics doctor``."""
    out = []
    for url in CHAINS.get(chain, []):
        row = {"endpoint": url, "block_number": None, "logs": None, "error": None}
        pool = RpcPool(chain, endpoints=[url], timeout=timeout, max_attempts=1,
                       time_budget=40.0)
        try:
            bn, _ = pool.block_number()
            row["block_number"] = bn
        except RpcError as exc:
            row["error"] = str(exc)
            out.append(row)
            continue
        try:
            logs, st = pool.get_logs(
                "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
                bn - 50, bn, chunk_size=50, time_budget=40.0,
            )
            row["logs"] = len(logs)
        except RpcError as exc:
            row["logs"] = "unavailable: %s" % exc
        out.append(row)
    return out
