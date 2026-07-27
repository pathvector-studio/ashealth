# ashealth — a health checkup for your AS

English | [日本語](README.ja.md)

**Real-time hijack detection is the ER. `ashealth` is the annual physical.**

The routing-hygiene data an AS operator depends on lives in four separate registries, each with a different owner and a different update cadence — so the longer you operate, the more they drift apart. `ashealth` takes a single AS number and cross-checks all four, then prints a scored health report with concrete, ready-to-submit fix actions.

It is a single Rust binary aimed at small AS operators (regional ISPs, hosting providers, university networks) who want a preventive routing-hygiene check rather than an incident alarm.

## The four sources (and why they drift)

| # | Source | What it is | Why it drifts |
|---|--------|------------|---------------|
| 1 | **BGP announcements** | routes actually in the DFZ right now | new prefixes announced, transfers/returns, announcements withdrawn |
| 2 | **RPKI ROAs** | signed "this AS may originate this prefix" statements at the RIR | ROA never created after announcing; stale after an origin change or re-split |
| 3 | **IRR route objects** | routing-policy records in RADB / JPIRR / etc. | left behind by a former operator; proxy registrations from an old transit; origin mismatches between DBs |
| 4 | **PeeringDB** | directory of peering contacts and IX presence | never registered, or not updated after IX/policy changes |

The cost of drift is quiet: no ROA (or an invalid one) gets your route **dropped by every ROV network**; a missing IRR object gets you **filtered by IRR-based peers**; stale IRR/ROA leftovers invite abuse; an empty PeeringDB means peering requests have nowhere to land.

> ⚠️ **Prototype.** Results are derived from public-API snapshots (RIPEstat's validator, whois.radb.net, PeeringDB). Treat them as advisory — verify before you change any real registration.

## Install

### From source

Requires Rust (build-time only).

```
cargo build --release
# binary: target/release/ashealth
```

Static Linux (x86_64/aarch64, musl) and macOS (Intel/Apple Silicon) binaries are published on [Releases](https://github.com/pathvector-studio/ashealth/releases).

## The five subcommands

```bash
ashealth check <ASN>     # run the health checkup and print a scored report
ashealth fix <ASN>       # generate the artifacts you submit to fix the findings
ashealth serve           # embedded web UI (form → report), offline-capable
ashealth watch <ASN>     # periodic re-check, diff vs. last run, webhook on change
ashealth report          # periodic digest across your ASes (score trend + top findings)
```

`<ASN>` accepts `64496`, `AS64496`, or `as64496`.

### `check` — the diagnosis

```bash
ashealth check AS64496                # live (RIPEstat / PeeringDB / whois.radb.net)
ashealth check AS64496 --json         # full structured output
ashealth check AS64496 --limit 100    # cap prefixes sent for RPKI validation (default 50)
```

It queries the four sources, runs seven checks, and prints a report ending in a **score out of 100** and a letter grade (**A** 90+ / **B** 75+ / **C** 60+ / **D** 40+ / **E** below 40).

| # | Check | Verdict |
|---|-------|---------|
| 1 | announced prefix has no covering ROA | **FAIL** |
| 2 | announcement is RPKI-invalid (origin / maxLength) | **FAIL** — dropped by ROV networks |
| 3 | ROA exists for a prefix you no longer announce | WARN |
| 4 | announced prefix has no IRR route/route6 object | WARN |
| 5 | IRR route object with no matching announcement | WARN |
| 6 | origin disagrees between IRR databases | WARN |
| 7 | PeeringDB record missing / incomplete | WARN / INFO |

To protect the live APIs, RPKI validation is capped at the first `--limit` prefixes (default 50). When announcements exceed that cap the score is an **estimate over the sampled range**: the terminal output flags incomplete coverage and annotates the grade, and JSON adds a `coverage: {announced, checked, complete}` object. `--limit 0` is **rejected** — it would silently skip all RPKI validation and inflate the score.

### `fix` — the remedy

Where `check` says *what* is wrong, `fix` produces the actual artifacts you submit to fix it — ROA request parameters, paste-ready RPSL route/route6 objects (create and delete), and where to submit each.

```bash
ashealth fix AS64496                 # human-readable report (default)
ashealth fix AS64496 --format rpsl   # paste-ready RPSL objects only (> objects.txt)
ashealth fix AS64496 --format json   # structured [{finding, artifact_type, artifact, submission_hint}]
```

Recommended ROA `maxLength` is pinned to the **currently announced prefix length** (a wider maxLength opens the door to forged-origin subprefix hijacks of unannounced more-specifics). RPKI-invalid findings show the announcement-vs-ROA mismatch and offer both paths — **fix the ROA** or **fix the announcement**. Stale IRR / origin-conflict findings emit delete objects with a `delete:` line.

### `serve` — web UI

```bash
ashealth serve --port 8080
ashealth serve --port 8080 --rate-limit 10 --cache-ttl 600
```

An embedded single-page UI (plain JS, no build step): enter an ASN, get the report. `--rate-limit` caps `/api/check` requests per IP per minute (default 10; 0 = unlimited); `--cache-ttl` is the result-cache lifetime in seconds (default 600; 0 = off). `AS64500` and `AS64501` always answer from bundled fixtures, so the UI is demoable without any live traffic.

### `watch` — change detection

```bash
ashealth watch AS64496 --interval 21600 --webhook https://discord.com/api/webhooks/...
ashealth watch AS64496 --once      # run one cycle and exit (cron / systemd timer)
```

Re-runs `check` on a schedule (default every 21600s = 6h) and POSTs JSON to `--webhook` on any change (new/resolved findings, score delta). The payload includes a Japanese one-line `content` field, so a **Discord webhook URL works out of the box**. State persists to `~/.local/state/ashealth/asXXXX.json` (score history included); `--state` overrides the location.

### `report` — periodic digest

```bash
ashealth report --config ~/.config/ashealth/config.toml
ashealth report --config --webhook https://discord.com/api/webhooks/... --json
```

An operator-facing weekly/monthly digest per AS: current score/grade, **delta since the last `report` run**, the last-four score trend, and the top findings by severity — with a header giving the AS count, average score, and single most severe action across all ASes. Requires `--config`. Shares the `watch` state file, so its diff baseline advances independently of `watch`.

## Managing multiple ASes (`--config`)

`check`, `watch`, `report`, and `serve` all accept `--config <path>` (default `~/.config/ashealth/config.toml`) to operate on a list of ASes in one command. See [examples/config.example.toml](examples/config.example.toml).

```toml
[defaults]
interval = 21600
webhook = "https://discord.com/api/webhooks/xxxx/yyyy"   # optional
limit = 50

[[as]]
asn = 64500
name = "prod AS"
webhook = "https://discord.com/api/webhooks/xxxx/prod"   # per-AS override

[[as]]
asn = 64501
name = "staging AS"
```

Precedence is **per-AS > defaults > built-in default**. `check --config` prints a worst-first summary table; `watch --config` monitors every AS each cycle; `serve --config` turns the top page into a multi-AS dashboard (auto-refreshing, plus a `GET /api/summary` endpoint). Multi-AS runs are serialized with a 1-second pause between ASes to be gentle on the upstream APIs.

## Offline demo (`--demo`)

Every subcommand takes `--demo`, which runs entirely against bundled fixtures — no network access.

```bash
ashealth check --demo      # diagnose the unhealthy fixture AS64500 (score 28 / grade E)
ashealth fix --demo        # generate its fix artifacts
ashealth serve --demo      # fully offline: every ASN answers from the AS64500 fixture
ashealth report --config --demo   # digest over both fixtures (AS64500 unhealthy, AS64501 healthy)
```

`--config --demo` uses your real config if one exists, otherwise synthesizes an in-memory two-AS config (AS64500 + AS64501) so multi-AS commands demo with zero setup. `--demo` skips the reserved-ASN validation, since the fixtures live in the RFC 5398 documentation range.

## ASN validation

Live runs pre-screen the ASN. `AS0` (RFC 7607) and `AS23456` (AS_TRANS, RFC 6793) are **rejected** — they can never be a real operating AS. Documentation / private-use / reserved ranges (RFC 5398 / 6996 / 7300) emit a warning but still run.

## Design notes

- **Fetch and check are separated.** `collect()` assembles the input; `run_checks()` and `fix::remediations()` are pure functions, unit-tested without a network (`cargo test`, 100+ tests).
- **One `DataSource` trait.** Swapping `LiveSource` for `FixtureSource` routes CLI, web, and tests through the same code path.
- **Degrade gracefully.** If IRR or PeeringDB fetches fail, the affected check is skipped with a note and the rest of the diagnosis continues.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License / disclaimer

MIT. Diagnoses are advisory, based on public-API snapshots — verify before making any real routing or registration change.
