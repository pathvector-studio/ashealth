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
ashealth fix AS64496 --limit 100     # same prefix cap as `check` (default 50)
```

Recommended ROA `maxLength` is pinned to the **currently announced prefix length** (a wider maxLength opens the door to forged-origin subprefix hijacks of unannounced more-specifics). RPKI-invalid findings show the announcement-vs-ROA mismatch and offer both paths — **fix the ROA** or **fix the announcement**. Stale IRR / origin-conflict findings emit delete objects with a `delete:` line.

### `serve` — web UI

```bash
ashealth serve --port 8080
ashealth serve --port 8080 --rate-limit 10 --cache-ttl 600
```

An embedded single-page UI (plain JS, no build step): enter an ASN, get the report. `--port` is the listen port (default 8080); `--rate-limit` caps `/api/check` requests per IP per minute (default 10; 0 = unlimited); `--cache-ttl` is the result-cache lifetime in seconds (default 600; 0 = off). `AS64500` and `AS64501` always answer from bundled fixtures, so the UI is demoable without any live traffic.

### `watch` — change detection

```bash
ashealth watch AS64496 --interval 21600 --webhook https://discord.com/api/webhooks/...
ashealth watch AS64496 --once      # run one cycle and exit (cron / systemd timer)
```

Re-runs `check` on a schedule (default every 21600s = 6h) and POSTs JSON to `--webhook` on any change (new/resolved findings, score delta). The payload includes a Japanese one-line `content` field, so a **Discord webhook URL works out of the box**. State persists to `asXXXX.json` (score history included), under `$XDG_STATE_HOME/ashealth/` if that variable is set, otherwise `~/.local/state/ashealth/`. `--state <path>` overrides the location: it is the state file itself for `watch <ASN>`, or a directory (holding `asXXXX.json`) with `--config`. `--limit` (default 50) caps the prefixes sent for RPKI validation, as in `check`. With `--config`, the interval and limit come from the config file (`--interval` / `--limit` are not used).

### `report` — periodic digest

```bash
ashealth report --config ~/.config/ashealth/config.toml
ashealth report --config --webhook https://discord.com/api/webhooks/... --json
```

An operator-facing weekly/monthly digest per AS: current score/grade, **delta since the last `report` run**, the score trend (up to four earlier runs), and the top findings by severity — with a header giving the AS count, average score, and single most severe action across all ASes. Requires `--config`.

The state file is shared with `watch` (`asXXXX.json`, under `$XDG_STATE_HOME/ashealth/` if that variable is set, otherwise `~/.local/state/ashealth/`; `--state <dir>` overrides the directory). It keeps the score history (the most recent 90 entries, oldest dropped first) and `last_report_at`, the time of the previous `report` run. Every `report` run appends to the history and updates `last_report_at`, which is what moves the delta baseline; `watch` runs append to the history but leave `last_report_at` as it was, so the diff baseline advances independently of `watch`.

`--webhook <URL>` POSTs one JSON payload after the run. It has a Japanese one-line summary in `content` (so a Discord webhook URL works as-is), plus `as_count`, `avg_score`, `top_action` (`null` if there is no finding), and `blocks` (the full per-AS blocks: `asn`, `label`, `score`, `grade`, `fail_count`, `warn_count`, `delta`, `trend`, `top_findings`). `--json` prints the same fields, without `content`, to stdout. The webhook client is shared with `watch`.

Example cron entry, sending a weekly report every Sunday at 03:00:

```cron
0 3 * * 0 /usr/local/bin/ashealth report --config --webhook https://discord.com/api/webhooks/... >> /var/log/ashealth-report.log 2>&1
```

#### Sample output (`ashealth report --config --demo`)

Output from running `--demo` twice in a row against the bundled fixtures (AS64500 unhealthy, AS64501 healthy). The first run shows `初回` ("first run") instead of a delta; the second run, shown here, has only one history entry, so the trend is a single value and the delta is `±0`. The report output is currently Japanese only (there is no language switch).

```
  ashealth ─ 定期サマリレポート
  ────────────────────────────────────────────────────────────────
  対象AS数: 2件   平均スコア: 64点
  最重要アクション: AS64500: [FAIL] 203.0.113.0/24 — RPKI invalid (invalid_asn) — ROV実施ネットワークからこの経路は破棄されます【最優先】
  ────────────────────────────────────────────────────────────────

  本番AS (AS64500)  スコア 28点 グレードE  前回比 ±0
    FAIL 3件 / WARN 5件
    トレンド: 28
    上位所見:
      - [FAIL] 198.51.100.0/24 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません
      - [FAIL] 2001:db8::/32 — ROA未作成 — このプレフィックスをカバーするROAが存在せず、RPKI的に保護されていません
      - [FAIL] 203.0.113.0/24 — RPKI invalid (invalid_asn) — ROV実施ネットワークからこの経路は破棄されます【最優先】

  検証AS (AS64501)  スコア 100点 グレードA  前回比 ±0
    FAIL 0件 / WARN 0件
    トレンド: 100
```

Header: AS count (`対象AS数`), average score (`平均スコア`), and the single most severe action across all ASes (`最重要アクション`). Per AS: score/grade, delta vs. the last `report` (`前回比`), FAIL/WARN counts, the score trend (`トレンド`, e.g. `28 → 35 → 45 → 79` once history accumulates), and the top three findings by severity (`上位所見`).

Notes on reading the output:

- The trend is built from the history shared with `watch`, **excluding the current run**: up to the four most recent earlier entries, oldest first. So the trend is empty only when there is no history yet in the state file; if `watch` has already recorded history, even the first `report` run shows a trend. `watch` runs also feed it.
- The delta is `初回` until `last_report_at` exists, i.e. only on the very first `report` run for an AS. Running `watch` first does not remove it.
- `--demo` keeps its own state in a `demo/` subdirectory of the default state directory (`~/.local/state/ashealth/demo/asXXXX.json` when `$XDG_STATE_HOME` is unset; with `--state <dir>` the files go directly in that directory). If those files are left over from earlier runs, even your first `--demo` run will not show `初回` and will already have a trend. Delete them to reproduce the sample above.

## Managing multiple ASes (`--config`)

`check`, `watch`, `report`, and `serve` all accept `--config <path>` (default `$XDG_CONFIG_HOME/ashealth/config.toml` if that variable is set, otherwise `~/.config/ashealth/config.toml`; omit the path to use the default) to operate on a list of ASes in one command. See [examples/config.example.toml](examples/config.example.toml).

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

`--config --demo` uses your real config if one exists, otherwise synthesizes an in-memory two-AS config (AS64500 + AS64501) so multi-AS commands demo with zero setup. On the CLI, `--demo` skips the ASN validation described below, since the fixtures live in the RFC 5398 documentation range (`serve --demo` follows its own rules, described below).

## ASN validation

Live single-AS runs pre-screen the ASN: `check` / `fix` / `watch` with an ASN given as an argument (not `--config`), and `serve`'s `/api/check/{asn}`. The multi-AS paths (`check --config`, `watch --config`, `report`) do not run this validation on the ASNs in the config file; as for the ASN value, the config loader only rejects `asn = 0` (it also rejects duplicate entries). The `serve --config` dashboard list (and `/api/summary`) shows the configured ASNs without validating them, but each row's check link goes through `/api/check/{asn}`, so the `serve` rules below apply there. `AS0` (RFC 7607) and `AS23456` (AS_TRANS, RFC 6793) are **rejected** — they can never be a real operating AS. Documentation / private-use / reserved ranges (RFC 5398 / 6996 / 7300) emit a warning but still run on the CLI (`check` / `fix` / `watch`). `serve` is stricter: outside `--demo`, `/api/check/{asn}` rejects those ranges as well (HTTP 400, the warning text is the error message), except the bundled fixtures AS64500 / AS64501, which are always allowed. With `serve --demo`, reserved ranges are allowed, but `AS0` / `AS23456` are still rejected.

## Design notes

- **Fetch and check are separated.** `collect()` assembles the input; `run_checks()` and `fix::remediations()` are pure functions, unit-tested without a network (`cargo test`, 100+ tests).
- **One `DataSource` trait.** Swapping `LiveSource` for `FixtureSource` routes CLI, web, and tests through the same code path.
- **Degrade gracefully.** If IRR or PeeringDB fetches fail, the affected check is skipped with a note and the rest of the diagnosis continues.

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License / disclaimer

MIT. Diagnoses are advisory, based on public-API snapshots — verify before making any real routing or registration change.
