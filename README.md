# Pathlookup Analysis Tool

Analyze IP Fabric path lookups from the command line — one flow at a time, or a
whole CSV of them.

## Introduction

Two commands, sharing one graph walker and one intent vocabulary:

| Command | What it does | Writes to IP Fabric? |
| --- | --- | --- |
| `single` | One flow, rendered as a tree (or table) with the security verdict. Optional pivot to find where the source is attached. | No |
| `bulk` | A CSV of flows, each simulated and scored against its stated intent. | Only with `--create-path-verifications` |

`bulk --create-path-verifications` is the **one thing in this repo that writes**:
it saves each flow into IP Fabric's **Path Verifications** table, so the flow is
re-evaluated on every snapshot instead of being a one-off simulation.

> ⚠️ Path lookup results are a **simulation**. Treat the output as draft validation
> evidence and have a network engineer review it before it feeds any audit or
> compliance deliverable.

## Prerequisites

- Python 3.10 or above is required to run this script. Please make sure you have the appropriate version of Python installed on your system.

## Dependencies

The following dependencies are required to run the script, including a python version 3.10+

See [`requirements.txt`](requirements.txt).

- `ipfabric` **8.0.1+** — the script consumes the typed `PathLookupResult` model.
  Not 8.0.0: its decision-trace event union lacks IP Fabric's cloud event types, and
  because that union is discriminated, pydantic rejects the entire result — any path
  crossing the Cloud, when using the New Cloud Model, fails to parse.
- `dotenv`
- `typer`
- `rich`
- `pandas` — **only** for `modules/pathdiff.py` (the Jupyter snapshot-diff helpers).
  Neither CLI command imports it. The `style_*` helpers additionally need `jinja2`
  (pandas' Styler dependency) — already present in any Jupyter install, so this only
  bites outside a notebook.

Please make sure to install these dependencies before running the script.

## Installation

To install the required dependencies, run the following command:

```shell
pip install -r requirements.txt
pip install pandas          # optional: only for modules/pathdiff.py
```

## Usage

```shell
python e2e_analysis.py single -s 192.168.1.10 -d 8.8.8.8 -p icmp
python e2e_analysis.py bulk --input flows.csv
python e2e_analysis.py bulk --input flows.csv --create-path-verifications
```

Running `e2e_analysis.py` with no arguments lists the commands.

### `single` — one flow

The available options:

- --source_ip or -s: Enter the source IPv4 address or subnet.
- --destination_ip or-d: Enter the destination IPv4 address or subnet.
- --protocol or -p: Enter the protocol (tcp, udp, icmp).
- --destination_port or -dp: Enter the destination ports (udp, tcp).
- --source_port or -sp: Enter the source ports (udp, tcp).
- --ttl or -ttl: Enter the Time To Live (TTL).
- --fragment_offset or -fo: Enter the Fragment Offset.
- --secure_path or -sec: Secure the path: stop the flow when hitting security rules.
- --l2_exclusion or -l2: Remove L2 from the displayed path.
- --pivot or -pivot: Enter the Pivot IPv4 address.
- --auto-pivot: If the source has `DEFAULT_GW_NOT_FOUND`, reverse source and destination, find where that path leaves to the transit, and re-run from that device and interface (opt-in).
- --table or -t: Display result in a table format (see *The table* below).
- --first-path or -fp: Follow one branch at each fork (tree and table).
- --verbose or -v: Enable verbose mode, and add the raw edge dump (section `x`).
- --file or -f: JSON file containing Pathlookup output \*testing purposes only\*

To run it:

```shell
python e2e_analysis.py single --source_ip 192.168.1.10 --destination_ip 8.8.8.8 --protocol icmp
```

```shell
python e2e_analysis.py single --source_ip 192.168.1.10 --destination_ip 10.48.115.12 --protocol tcp --source_port 1024 --destination_port 443 --secure_path --table
```

Replace the IP addresses and protocol with your desired values.

### `bulk` — a CSV of flows

```shell
python e2e_analysis.py bulk --input flows.csv [--output results.csv] [--limit 10]
```

| Option | Default | Description |
| --- | --- | --- |
| `--input` / `-i` | _(required)_ | Input CSV of flows |
| `--output` / `-o` | `results.csv` | Output CSV path |
| `--snapshot` | _(from `.env`)_ | Snapshot ID |
| `--delay` | `0.2` | Seconds between API calls |
| `--limit` | `0` | Only process the first N rows |
| `--create-path-verifications` | off | **Also create each flow in IP Fabric** |
| `--force-create` | off | Create even if an identical verification exists |
| `--auto-pivot` | off | On `DEFAULT_GW_NOT_FOUND`, reverse src/dst, find the source's entry point and retry. Adds an `auto_pivot` output column. Single-IP sources only; saved verifications don't carry the entry point |
| `--report-dir` | _(none)_ | Write each flow's files into this folder (see below). Adds a `report` output column |
| `--png` | off | With `--report-dir`: also save each flow's diagram as a PNG |
| `--parallel` | `1` | Run this many flows at once (max 10). `--delay` is then ignored. The CSV stays in input order; console lines appear as flows finish |
| `--resume` | off | With `--report-dir`: reuse flows finished by an earlier run instead of looking them up again |

`--create-path-verifications` is additive: `bulk` still simulates every row, so one
pass gives you the outcome **and** the saved verification. That costs 3 API calls
per row instead of 1 (lookup + exists + create).

Without `--force-create`, a row whose parameters already exist is reported
`SKIPPED existing` and nothing is sent — so rerunning the same CSV is a no-op.
With it, the create is sent anyway; observed behaviour is that IP Fabric returns
the **same check id** rather than adding a second copy.

#### Input CSV

| Column | Required | Default | Notes |
| --- | --- | --- | --- |
| `srcIP` | yes | — | Single IP or subnet up to `/16` |
| `dstIP` | yes | — | Same as `srcIP` |
| `srcPort` | no | `1024-65535` | Integer, range, or list |
| `dstPort` | no | `443` | Integer, range, or name |
| `protocol` | no | `tcp` | `tcp`, `udp`, or `icmp` |
| `application` | no | _(empty)_ | NGFW app name, e.g. `ssh`, `https` |
| `security` | no | `drop` | `drop` stops at denies; `continue` simulates past them |
| `expected` | no | _(empty)_ | The intent — see below |
| `comment` | no | _(empty)_ | Free text, copied through |

Any other column is copied through unchanged. See
[`flows_sample.csv`](flows_sample.csv) and [`results_sample.csv`](results_sample.csv).

Appended to the output: `status`, `verdict` (when `expected` is present),
`blocked_at`, `rule`, `branches`, `details`. With `--create-path-verifications`,
also `create_status`, `exists`, `check_id`, `job_id`, `expectedPassingTraffic`.

#### Per-flow reports (`--report-dir`)

The CSV is the overview, one line per flow. `--report-dir DIR` (also on `single`) adds the
detail, one set of files per flow:

| File | Contents |
| --- | --- |
| `<flow>.md` | Every branch, hop by hop: interfaces, VRF, zone, security events, blocked hops, and the intent / verdict / pivot for the flow |
| `<flow>_summary.md` | The verdict and the first path on one line |
| `<flow>.json` | The raw IP Fabric response (can be used as a golden fixture) |
| `<flow>.png` | The diagram, with `--png` (one extra API call per flow) |

`<flow>` is `<src>_to_<dst>_<proto>-<dstPort>`, with `/` and `,` made filename-safe, `_sp<port>`
added for a non-default source port, and `_2`, `_3`... when two rows would get the same name.
The `.md` is written last. A report that fails to write is noted in the `report` column and
never stops the run. With `--auto-pivot`, the JSON and PNG are those of the pivoted lookup.

`--resume` skips a flow when its `.md` and `.json` (and `.png`, if `--png`) already exist
in the report folder **and** were made for the same parameters. The `.md` starts with a
`<!-- flow: ... -->` line recording the source, destination, ports, protocol, security
mode, application, snapshot ID and `--auto-pivot`; if any of them differ, the flow is
looked up again. Resumed rows are scored from the saved JSON, so the CSV is complete
(verdict, intent and the `auto_pivot` column included) and the console line ends with
`[resumed]`. `--create-path-verifications` still runs for every row; it already skips
verifications that exist.

| `status` | Meaning |
| --- | --- |
| `REACHED` | All requested traffic reaches the destination |
| `PARTIAL` | Some destination hosts/ports reach, others are denied |
| `BLOCKED` | A security policy denies the traffic; nothing reaches |
| `NO-PATH` | No route / unreachable, with no security deny recorded |
| `ERROR` | Bad input row or unexpected response |

#### Intent (`expected`)

An intent is satisfied only by a **full** outcome — `PARTIAL` matches neither.

| `expected` | Also accepted | REACHED | PARTIAL | BLOCKED | NO-PATH | Creates as |
| --- | --- | --- | --- | --- | --- | --- |
| `allow` | `allowed` `pass` `permit` `permitted` `reach` `reached` `yes` `ok` `all` | MATCH | MISMATCH | MISMATCH | MISMATCH | `all` |
| `block` | `blocked` `deny` `denied` `no` `none` | MISMATCH | MISMATCH | MATCH | MATCH | `none` |
| `part` | `partial` `some` | MISMATCH | MATCH | MISMATCH | MISMATCH | `part` |
| `assess` | `check` `info` `fyi` `review` `observe` `report` | ASSESS | ASSESS | ASSESS | ASSESS | _not created_ |
| _(empty)_ | — | — | — | — | — | _not created_ |

The synonym sets are defined in
[`modules/verdict.py`](modules/verdict.py) as `EXPECTED_ALLOW`, `EXPECTED_BLOCK`,
`EXPECTED_PART` and `EXPECTED_ASSESS` — that file is the single source of truth for
both the verdict and the create mapping. Matching is case-insensitive and trims
whitespace. An unrecognised value scores `?` rather than falling back to a default.

Use `assess` to **observe** a flow without a pass/fail judgment — it surfaces the
status but stays out of the MATCH/MISMATCH tally.

The security-critical case is **expected `block` but `REACHED`/`PARTIAL`**: traffic
you meant to deny is getting through.

> An empty `expected` is **not** created as `all`. Turning "nobody said" into a
> permanent assertion that the flow must fully pass produces failing verifications
> months later that no one can account for. State the intent, or it is skipped.

## Output

Three sections: the event summary, the path itself, and the security verdict.
The path is printed as a tree — where the traffic forks (ECMP, redundant firewall
legs, a load-balancer hairpin) **every** leg is shown as a labelled branch, and `⑃ rejoin`
marks where they merge again. `--first-path` (`-fp`) shows one branch per fork instead:

```text
 2. Path (all branches)
• host: 172.16.22.20 host     [- → -]  n/a
• s2xsw01            switch   [1/1/3 → 1/1/1]  l2
• s2xgw1             l3switch [1/1/2 → 1/1/1]  ip  vrf=default
• d2xfw01            fw       [ge-0/0/2.0 → ge-0/0/0.0,ge-0/0/1.0]  ip  vrf=master  zone=CORE
     🔒 ✅ zoneFw 'SITE2@CORE' rule=[1, 0, 0] → ZONEFW_PERMIT (ignored)
⑂ 2 branches
├─ branch 1/2
│  • d2xr01             router   [Gi0/3 → Gi0/5]  ip
└─ branch 2/2
   • d2xr01             router   [Gi0/4 → Gi0/5]  ip
⑃ rejoin
...
• lb3x02             lb       [Vl1 → Vl100]  ip  vrf=0
...
• d3xfw02            fw       [port3 → port2]  ip  zone=any  ⛔ BLOCKED
     🔒 ❌ zoneFw 'main' rule=[0, 2] → ZONEFW_DENY
...
⑂ 2 branches
├─ branch 1/2
│  • s4xlf03            l3switch [Et1 → Et5]  vxlan  vrf=s4tenant
│  • host: 172.16.42.60 host     [- → -]  n/a
└─ branch 2/2
   • s4xlf05            l3switch [Et2 → Et5]  vxlan  vrf=s4tenant
   • host: 172.16.42.61 host     [- → -]  n/a

 3. Security verdict
⛔ Traffic blocked at d3xfw02 (fw)
     rule: zoneFw policy 'main'  rule=[0, 2]  → ZONEFW_DENY
```

### The table (`--table`)

`--table` flattens the path into one numbered row per hop (`#`). Flattening loses the
tree shape, so forks and merges get a note row instead of a marker column:

```text
6   ge-0/0/2.0  d1xfw01      ge-0/0/0.0,ge-0/0/1.0  ip  master  OK SITE1@CORE
                ⑂ 2 branches
                  branch 1/2
7   Et0/2         d1xr01     Et1/1                  ip
...
                  branch 2/2
12  Et0/2         d1xr02     Et1/1                  ip
...
                ⑃ rejoin
15  Gi0/4       d3xr02       Gi0/2                  ip
```

- Hops inside a fork are indented under their `branch n/N` note; nested forks indent
  further.
- `⑃ rejoin` means the path continues past the fork, so everything below is shared.
  A fork at the very end (e.g. several destination hosts) has no rejoin.
- Columns that are empty for the whole path (VRF, Security) are left out.

`--first-path` (`-fp`) works the same way in the tree: it follows one branch at each fork instead of all of them: the
first branch that reaches the destination, else the first. The fork note says how many
branches were left out (`⑂ 3 branches, showing branch 1`). The security verdict below
the table still covers all branches, so a blocked leg is not hidden by the shorter view.

The `Security` column shows the deciding verdict as a coloured word — `OK`, `INFO`, `WARN`,
`BLOCK` — rather than the emoji used in the tree. Emoji are double-width in most
terminals but rich measures some of them as one cell, which shifts every column border
below them.

Additional Information

- When using the ICMP protocol, the --destination_port and --source_port options will not be used.
- The --secure_path option can be used to secure the path and stop the flow when hitting security rules.
- The --l2_exclusion option collapses runs of pure L2/FabricPath hops into a single
  `... l2/fp skipped ...` line. A hop carrying a security verdict or a drop is always kept.
- The --pivot option is used to find where the source IP is connected using a pivot IP.
- The --verbose option adds the raw edge dump (section `x`) that the tree is built from.

![Example1: script output](img/result01.png)
![Example2: script output](img/result02.png)

Feel free to explore different options and customize the analysis based on your needs.

## Modules

| File | Purpose | Needs |
| --- | --- | --- |
| `modules/bulk.py` | One CSV row end to end for `bulk` (lookup or resume, verdict, create, report), plus the output columns and console lines. No printing, thread-safe. | `lookup`, `report`, `checks`, `verdict` |
| `modules/report.py` | Writes one flow's files (JSON, PNG, markdown) into the report folder; file naming. | `markdown`, `pathgraph` |
| `modules/markdown.py` | The detailed and summary markdown for one flow. Text only, no I/O. | `pathgraph`, `utilis` |
| `modules/pathgraph.py` | Walks the graph and enriches each hop (ingress/egress, protocol, VRF, security verdict, ZoneFW, drop reason, delivered packet). Keyed on **edge** id, so a device traversed twice gets one entry per visit. No pandas. | `utilis` |
| `modules/verdict.py` | One lookup → `REACHED`/`PARTIAL`/`BLOCKED`/`NO-PATH` plus details, and the intent vocabulary (`MATCH`/`MISMATCH`/`ASSESS`, and the `expectedPassingTraffic` mapping used when creating verifications). | `pathgraph` |
| `modules/utilis.py` | Severity → icon / coloured word. | — |
| `modules/pathdiff.py` | Compare two path lookups, locally (`diff_paths`) or via IP Fabric's server-side compare overlay (`compare_snapshots`, `overlay_diff`, `divergence_point`). Returns DataFrames; intended for Jupyter. | `pathgraph`, **pandas** |
| `modules/pivot.py` | Entry point of the source, from a pivot lookup's `--transit` edge. | `pathgraph` |
| `modules/lookup.py` | Client, the one `Unicast` builder, CSV-row parsing, `run_lookup()` with manual and auto pivot. | `pivot`, `verdict` |
| `modules/display.py` | Event summary, pivot message, raw edge dump, table rendering. | `pathgraph`, `utilis` |
| `modules/checks.py` | Saved path verifications (the only writes to IP Fabric). | `lookup`, `verdict` |

### Using it from Jupyter

Nothing in `modules/` imports typer or touches the CLI, so copy the folder as-is.
The minimum set is **`pathgraph.py` + `utilis.py`**; add `pathdiff.py` for the diff
side. `pivot.py` and `lookup.py` are optional — take them if you want
`run_lookup()`, which wraps the lookup including the two-stage pivot.

```python
from modules.pathgraph import enrich, show, show_blocked, blocked_hops, flatten
from modules.pathdiff import (
    diff_paths, style_diff, compare_snapshots, overlay_diff, style_overlay_diff,
    overlay_hops, show_overlay, divergence_point, path_devices, overlay_path_devices,
)

result = Diagram(ipf=ipf).model(uni)
show(enrich(result))                 # tree, all branches
show(enrich(result, zonefw))         # …with the ZoneFW column
```

Import `pathgraph` on its own if you don't want pandas — keeping that split is the
reason the diff helpers live in a separate file.

## Tests

Three scripts, no pytest, no server needed for any. Run them all:

```shell
python tests/test_pathgraph.py    # is the logic correct?
python tests/test_golden.py       # is the output still what it was?
python tests/test_report.py       # are the report file names right?
```

### `test_pathgraph.py` — is the logic correct?

Offline assert-based self-check on a **synthetic** path lookup we build by hand.
Covers the fork, the per-visit attribution, multiple traces on one ingress edge, the
L2 collapse, a lookup that found no path at all, and the pivot entry point — plus
the `verdict` layer: the delivered packet, which hops count as destinations, the
branch count, the status mapping, and the full `expected` truth table above.

Every case runs against **both** endpoint shapes: straight off the wire
(`PathLookupResult(**json)`, i.e. the `--file` replay) an edge's `source`/`target`
are node-id strings, but `Diagram.model()` swaps in the `Node` object. Use
`pathgraph.node_id()` rather than touching `.source`/`.target` directly.

Because the data is synthetic, this can never notice that IP Fabric started
returning something new. That is the other script's job.

### `test_golden.py` — is the output still what it was?

Runs the same functions over **recorded real responses** and compares the result to
a saved copy. If they differ, either you changed the code or something underneath
changed — and the diff says exactly what.

#### The two kinds of file in `tests/fixtures/`

This is the bit worth getting straight before anything else:

| File | What it holds | Think of it as | Written by |
| --- | --- | --- | --- |
| `<name>.json` | what IP Fabric returned (20–210 KB) | the **question** (input) | `--record` |
| `<name>.expected.txt` | what our code made of it (1–8 KB) | the **answer** (output) | `--update` |

Both are committed to git. That is what makes any change reviewable.

#### The three commands

| Command | Reads | **Writes** | Needs a server? |
| --- | --- | --- | --- |
| `python tests/test_golden.py` | both | **nothing** | No |
| `python tests/test_golden.py --record` | — | the **`.json`** (inputs) | **Yes** |
| `python tests/test_golden.py --update` | `.json` | the **`.expected.txt`** (outputs) | No |

- **No flags — the actual check.** Loads each `.json`, runs the code over it,
  compares to `.expected.txt`. Prints `OK` per scenario or a unified diff. Exits 1 if
  anything changed. Writes nothing, so it is always safe to run.
- **`--record` replaces the questions.** Calls your live IP Fabric and overwrites the
  `.json` files. Read-only against IP Fabric — path lookups only, nothing is created.
  It deliberately does **not** touch `.expected.txt`, so the plain run straight
  afterwards tells you whether the new responses still produce the old output.
- **`--update` replaces the answers.** Re-runs the code on the existing `.json` and
  overwrites `.expected.txt` with whatever comes out. It asserts nothing — it just
  says "today's output is the new reference".

> ⚠️ `--update` is unconditional: it never asks whether the new output is *correct*.
> Running it reflexively when something fails erases the evidence that something
> broke. **Read the diff first, then decide.**

#### Upgrading the SDK

```shell
pip install -U ipfabric
python tests/test_golden.py          # same inputs, same code, new SDK
```

All `OK` → the upgrade changed nothing you depend on. A diff → the SDK changed your
output; read it, and if the new output is right, `--update` and commit. The diff in
review is then the permanent record of what that upgrade did.

#### Upgrading IP Fabric

Re-fetch first, because the responses themselves change:

```shell
python tests/test_golden.py --record   # refresh the inputs (read-only)
git diff tests/fixtures/               # what IP Fabric now RETURNS
python tests/test_golden.py            # what that did to OUR OUTPUT
```

Keeping those two steps apart is the whole point: `git diff` on the `.json` shows
what *they* changed, the failing comparison shows what it did to *us*.

#### What is recorded, and why

| Fixture | Why it is there |
| --- | --- |
| `site2-to-aws-ping` | long path, L2 runs, ECMP forks |
| `rdp-blocked-zonefw` | BLOCKED by a zone firewall; `droppedPackets` + deciding rule |
| `rdp-partial-subnet` | PARTIAL — one host of the subnet reached, the rest denied |
| `aws-cloud-path` | cloud node types (`transit`/`awsTgw`/`awsSubnet`/`awsEni`), which set no interface name |
| `workshop-day1` | the workshop flow before the Paris fix |
| `workshop-day4` | the same flow after the fix + SD-WAN migration |
| `workshop-day1-vs-day4-overlay` | IP Fabric's **server-side** compare overlay |
| `workshop-day1-vs-day4-local` | the same two snapshots diffed **locally** (no `.json` of its own — built from the two above) |

The last three are the only coverage `modules/pathdiff.py` has: `diff_paths`,
`overlay_hops`, `overlay_diff`, `divergence_point` and `show_overlay` are exercised
nowhere else. Recording Day 1 and Day 4 separately *and* the overlay is deliberate —
one checks our local difflib alignment, the other checks how we read IP Fabric's own
comparison.

The workshop scenarios need `SNAP_DAY1` / `SNAP_DAY4` in `.env`. Without them
`--record` skips those three with a note and still records the rest, so the check
works against any instance.

## Limitations / Future development

- Multiple ports or IPs as part of the input may not be correctly represented. For example, if you want to see the flow opening result for destination port 80,443 the output will not differentiate which one is allowed/denied.
- The source hop merges the egress of every start edge onto one line, so a source with
  two uplinks shows both there rather than one per branch.
- When two legs of a fork share the *same* downstream edges but do not yet merge onto a
  single one (two edge routers both reaching one WAN router over an mpls/internet pair),
  that shared sub-fork is rendered under each leg. Faithful — the graph really does hold
  that many combinations — but more rows than the distinct edge count suggests.
