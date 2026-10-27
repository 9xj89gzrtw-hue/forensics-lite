# forensics-lite — token holder concentration from raw chain logs

A single-file CLI that answers one question without asking anyone's API for permission:
**who actually holds this token, and how concentrated is it?**

It reads `Transfer` logs straight from a public Base RPC, collects every address that ever
touched the token inside a block window, reads each balance with `balanceOf`, and prints a
concentration table plus a self-contained HTML report.

No API key. No account. No `pip install`. Python 3.9+ and the standard library.

```
$ ./forensics holders --chain base --token 0x532f27101965dd16442E59d40670FaF5eBB142E4 --blocks 3000 --top 5
metric                              value
--------------------------  -------------
unique addresses in window            186
balances read                         186
balances failed                         0
holders (balance > 0)                 139
tracked supply                 52,385,188
total supply                9,999,997,544
coverage of totalSupply             0.52%
top 1 share                        31.39%
top 5 share                        94.41%
top 10 share                       98.16%
gini                               0.9698
verdict: EXTREME - top-1 holds 31.4%, top-10 holds 98.2%
         - shares are of the 52,385,188 we could see (0.5% of totalSupply)
```

That output is real, captured on 27 Oct 2026 at Base block 53,174,736. It also shows the thing
most holder tools hide: **0.5% coverage**. The window was 3,000 blocks; the token is older than
that, so the census sees a slice, not the whole. The tool prints coverage on every run and folds
it into the verdict, because a concentration number without its denominator is a lie.

## Why raw logs instead of an explorer API

Explorer APIs (Basescan, Blockscout, Moralis) answer faster and cost a key, a quota, and trust.
Raw `eth_getLogs` costs neither, and it lets you prove the number: the command prints the block
range, the endpoint that answered, and the exact filter it used. If someone disputes the result,
they re-run the command.

The trade-off is real and documented: public RPCs cap log ranges (Base's `mainnet.base.org`
refuses `eth_getLogs` entirely; `publicnode` caps results at 20,000 per query), so the tool
learns each endpoint's limits, splits the range, and tells you which chunks it had to skip.

## Install

```bash
git clone https://github.com/9xj89gzrtw-hue/forensics-lite
cd forensics-lite
./forensics --help          # nothing to install
python3 -m unittest discover -s tests    # 80 tests, offline
```

The `forensics` shim inserts `src/` into `sys.path` itself, so it works from a fresh clone on a
machine with nothing but Python.

## Three things you can run right now

**1. Concentration on a Base token, last 24h of activity**

```bash
./forensics holders --chain base --token 0xTOKEN --blocks 50000
```

`--blocks` is how far back to scan. For a token launched hours ago, `--blocks 5000` is enough and
takes seconds. For an old token, pass the deployment block instead:

```bash
./forensics holders --chain base --token 0xTOKEN --from-block 12000000
```

**2. A shareable report**

```bash
./forensics report --chain base --token 0xTOKEN --blocks 3000 \
  --out report.html --json-alongside
```

Writes one HTML file with inline CSS and inline SVG — open it from disk, email it, commit it. No
CDN, no fonts, no JavaScript. `--json-alongside` also writes the model as JSON so you can diff two
runs or feed a dashboard.

A real example is committed: [`examples/example-report.html`](examples/example-report.html).

**3. A different chain**

`--chain` accepts every chain in the built-in pool (Base, Ethereum, Arbitrum, Optimism, Polygon,
BSC). Or point it anywhere:

```bash
./forensics holders --chain base --token 0xTOKEN --rpc https://your-endpoint.example
```

## Reading the numbers

| Field | What it means | Where it lies |
|---|---|---|
| `coverage of totalSupply` | tracked balance ÷ `totalSupply()` | low coverage = you are looking at a slice; the verdict says so |
| `top N share` | share of the **tracked** supply, not of total supply | a whale that never moved in the window is invisible |
| `gini` | inequality across tracked holders | meaningless when there are 5 holders |
| `hhi` | Herfindahl index, 0–1 | a single 51% wallet pushes it near 0.25 even with thousands of dust wallets |
| `dust wallets` | holders below 0.01% | airdrop spam inflates the count |

Verdict thresholds: `EXTREME` ≥ 50% top-10 or ≥ 25% top-1, `HIGH` ≥ 30% top-10, `MODERATE`
≥ 15%, otherwise `DISTRIBUTED`. They are heuristics, printed with the numbers that produced them.

## What this cannot tell you

- **A CEX omnibus wallet looks exactly like a whale.** This tool does not label addresses.
- **`balanceOf` is current state.** A wallet that held 5% yesterday and dumped shows 0 today.
- **The window is a window.** Holders who received tokens before `--from-block` are not discovered.
- **Public RPCs rate-limit.** The pool fails over across four endpoints and reports failovers; a
  chunk that could not be fetched is counted, never silently dropped.

All four caveats are printed inside the HTML report, not just here.

## Lite vs Pro

This repository is the Lite edition: `holders` and `report`, EVM chains, MIT licence, no strings.

The Pro pack (paid, USDC on Base) adds the commands that need more than one sweep:

| | Lite | Pro |
|---|---|---|
| Holder census + concentration + Gini | ✓ | ✓ |
| Self-contained HTML + JSON report | ✓ | ✓ |
| LP pools, burned vs floating LP share | — | ✓ |
| Early-buyer list (first transfers from a pool) with current balance | — | ✓ |
| Solana path (supply, largest accounts, DexScreener pairs) | — | ✓ |
| Endpoint triage (`doctor`) for all four RPCs | — | ✓ |
| Reference report on a live token, both formats | — | ✓ |

The engine modules (`rpc`, `evm`, `metrics`, `report`) are the same code in both editions and are
covered by the same 80 tests — the Lite edition is not a crippled demo, it is a smaller CLI.

## Licence

MIT. Use it, fork it, ship it inside your product.
