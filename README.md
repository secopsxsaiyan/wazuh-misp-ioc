# MISP IOC Matching Rules for Wazuh

Match live Wazuh telemetry against **MISP threat-intel indicators** held in Wazuh CDB lists,
and (optionally) tier the alerts by whether the traffic was already blocked.

These rules consult six CDB lists (`etc/lists/misp-ip`, `misp-domains`, `misp-hashes`,
`misp-urls`, `misp-ja3`, `misp-files`) that the **included loader** (`loader/`) refreshes from
MISP. They cover **IP** indicators (src/dst), **file-hash** indicators (SHA256 / SHA1 / MD5 on
FIM events), **URL** indicators (web access logs), **filename** indicators, and **domain** /
**JA3** indicators (pre-staged for DNS and TLS-fingerprint sources).

> **Note** — these rules **match indicators against your existing event stream**
> (firewall/CEF/FIM/auth). They are independent of, and do not require, any MISP *enrichment*
> integration that queries MISP per alert.

## Rules

| ID | Level | Fires on | Notes |
|----|-------|----------|-------|
| 100210 | 12 | any event whose **source IP** matches a MISP indicator | **universal** — no firewall field required |
| 100211 | 12 | any event whose **destination IP** matches a MISP indicator | **universal** |
| 100216 | 9  | *(optional)* malicious source IP in a firewall **DROP** | child of 100210 — de-escalates an already-blocked hit |
| 100217 | 9  | *(optional)* malicious destination IP in a firewall **DROP** | child of 100211 |
| 100218 | **11** | *(optional)* **internal (RFC1918)** source IP that was blocked | child of 100216 — compromised LAN host beaconing (T1071) |
| 100212 | 12 | a monitored file's **SHA256** matched a malicious hash | FIM `sha256_after` (rules 550/554) |
| 100213 | 12 | a monitored file's **MD5** matched a malicious hash | FIM `md5_after` |
| 100215 | 12 | a monitored file's **SHA1** matched a malicious hash | FIM `sha1_after` |
| 100214 | 12 | a DNS query matched a malicious **domain** | activates once a DNS source populates `dns.rrname` |
| 100227 | 12 | a web request **URL** matched a malicious indicator | `url` (stock web-accesslog decoders) |
| 100228 | 12 | a JSON log's **`data.url`** matched a malicious indicator | JSON-decoded web/proxy logs |
| 100229 | 12 | a **JA3** TLS fingerprint matched (`tls.ja3.hash`) | forward-looking — Suricata `eve.json` |
| 100230 | 12 | a **JA3** TLS fingerprint matched (`ja3.hash`) | forward-looking — other JSON TLS sources |
| 100231 | 12 | a Sysmon **JA3** matched (`win.eventdata.ja3`) | forward-looking — Sysmon with JA3 |
| 100232 | 12 | a **filename** matched a known-malicious sample | any decoder that sets `filename` |
| 100233 | 12 | a FIM **file path** matched a known-malicious filename | FIM 550/554 — opportunistic (`file` is a full path) |

### Design notes
- **Universal base detection.** `100210/100211` fire on *any* event carrying a matching src/dst
  IP — no firewall/decoder-specific fields required, so they work in any Wazuh deployment out of
  the box.
- **Optional block-state tiering.** `100216/100217` are *child rules* (`if_sid`) that fire only
  when the event also carries a firewall "drop/deny" action, de-escalating an already-blocked hit
  to **L9** (below the L10 triage gate) so blocked scans don't page. They key on `unifi.fw_action=D`
  by default — **change that field name / value to match your firewall's decoder** (e.g.
  `action=deny`, `fw_action=DROP`). If your events have no such field these simply never fire and
  the base **L12** alert stands — nothing to remove or break.
- **Internal-source escalation.** `100218` (child of `100216`) re-escalates a *blocked* hit back to
  **L11** when the source is RFC1918 — a LAN host beaconing to known-bad infra is worth paging even
  if the packet was dropped. Set the CIDR to your own RFC1918 range.
- **Forward-looking.** `100214` (domains) activates once you onboard a DNS log source
  (Suricata/Zeek `eve.json`, sysmon-for-linux DNS) that sets `dns.rrname`; `100229–100231`
  (JA3) activate once a source emits JA3 fingerprints.
- **CDB-safe keys.** CDB keys cannot contain `:`, so the loader stores URLs scheme-, port- and
  userinfo-stripped and lower-cased (`evil.example/path`), and filenames as lower-cased
  basenames.
- **URL rules — known limitation.** `match_key` is an exact lookup, so `100227/100228` fire only
  when the event field holds the same scheme-less `host/path` form. A field carrying
  `https://…`, or a bare path (stock web access logs log `/path` only), will not match. Treat the
  URL rules as forward-looking until you normalise `url` at the decoder.

## How the CDB lists are populated

The rules are inert until the six CDB lists exist and are non-empty. This repo ships a loader
(`loader/`) that builds and refreshes them. The field/`lookup` idioms the rules rely on:

| List | Field | `lookup` |
|------|-------|----------|
| `etc/lists/misp-ip` | `srcip` / `dstip` | `address_match_key` |
| `etc/lists/misp-hashes` | `sha256_after` / `sha1_after` / `md5_after` | `match_key` |
| `etc/lists/misp-domains` | `dns.rrname` | `match_key` |
| `etc/lists/misp-urls` | `url` / `data.url` | `match_key` |
| `etc/lists/misp-ja3` | `tls.ja3.hash` / `ja3.hash` / `win.eventdata.ja3` | `match_key` |
| `etc/lists/misp-files` | `filename` / `file` | `match_key` |

Declare the lists in `ossec.conf` under `<ruleset>`:

```xml
<ruleset>
  <list>etc/lists/misp-ip</list>
  <list>etc/lists/misp-domains</list>
  <list>etc/lists/misp-hashes</list>
  <list>etc/lists/misp-urls</list>
  <list>etc/lists/misp-ja3</list>
  <list>etc/lists/misp-files</list>
</ruleset>
```

Every declared list file must exist before the manager starts. The loader never pushes an
empty list (so it can't wipe a good one), which means a list whose MISP types you hold no
indicators for — often `misp-ja3` — is never created. Create placeholders once:

```bash
for l in misp-ip misp-domains misp-hashes misp-urls misp-ja3 misp-files; do
  f=/var/ossec/etc/lists/$l; [ -e "$f" ] || { touch "$f"; chown wazuh:wazuh "$f"; }
done
```

(You can populate the lists any other way too, as long as the file names and `key:value` CDB
format match. The included loader is the turnkey option.)

## Loader (`loader/`)

`loader/misp_to_wazuh.py` is a small Python pipeline. Each cycle it:

1. **Exports `to_ids` IOCs** (`ip-src/ip-dst`, `domain/hostname`, `md5/sha1/sha256`, `url/uri`,
   `ja3-fingerprint-md5/ja3s-fingerprint-md5`, `filename/malware-sample/filename|<hash>`). Two modes:
   - **`MISP_EXPORT_MODE=api`** (default, portable) — pulls indicators via the MISP REST API
     (`/attributes/restSearch`). Needs only `MISP_URL` + `ADMIN_KEY`; **no database access**.
   - **`MISP_EXPORT_MODE=db`** — reads MISP's MySQL directly (faster for very large instances;
     needs the `MISP_DB_*` vars and the `pymysql` package).
   Either mode then filters: non-public/RFC1918 IPs, a built-in public-DNS allowlist, and anything
   matching an **enabled MISP warninglist** (with a recall-protective skip-list so datacenter/VPN/
   dyn-DNS ranges that host real C2 are kept) for the IP, domain and URL lists. Warninglist
   checking is **fail-closed**: if MISP can't answer, that list is skipped and the last-known-good
   CDB stays in place. Each list is pushed to Wazuh via `PUT /lists/files/<name>`; an empty push
   is refused and an expired API token is refreshed once.
2. **Reloads the manager** — **`WAZUH_RELOAD=docker`** (default) runs `wazuh-control restart` in the
   manager container over the docker socket; **`WAZUH_RELOAD=api`** calls the REST restart endpoint
   for non-docker deployments. Skipped when nothing was pushed.
3. **Staggered feed refresh** — re-fetches enabled MISP feeds in small batches, draining between
   batches (avoids the all-at-once fetch spike that can corrupt the MISP DB); the next cycle exports
   the fresh data. Skip with `DO_REFRESH=0`, or set `CRON_PULLALL` > 0 if MISP's own scheduled
   workers already fetch feeds.

Run modes: `once` (default), `export` (skip the feed refresh), `loop` (service mode, sleeps
`REFRESH_SECONDS` between cycles).

| File | Purpose |
|------|---------|
| `misp_to_wazuh.py` | the pipeline |
| `docker-compose.yml` | runs it as a long-lived `intel-loader` service in `loop` mode |
| `docker-compose.override.yml` | memory limit (256m) |
| `.env.example` | **required** config template — MISP/Wazuh URLs + credentials, mode toggles, tuning |
| `.secrets.example` | **optional** keyed-feed API keys (OTX / abuse.ch / AbuseIPDB / GreyNoise) |

### Configure & run

```bash
cd loader
cp .env.example .env            # fill in MISP + Wazuh URLs and credentials
cp .secrets.example .secrets    # OPTIONAL — only if you use keyed feeds; otherwise skip it
# edit docker-compose.yml: set the external network names for wazuh-net and misp-net
#   (docker network ls | grep -E 'wazuh|misp')

# Minimum to run (portable defaults — api export, docker reload):
#   MISP_URL, ADMIN_KEY, WAZUH_API, WAZUH_USER, WAZUH_PASS, WAZUH_MGR_CONTAINER
# For MISP_EXPORT_MODE=db also set MISP_DB_HOST/USER/NAME/PASS.
# For a non-docker manager set WAZUH_RELOAD=api.

docker compose up -d            # runs every REFRESH_SECONDS (default 86400 = daily)
docker compose logs -f intel-loader

# one-off run without the long-lived service:
#   docker compose run --rm intel-loader python misp_to_wazuh.py export
```

> In the default **api** mode the loader needs only network access to the MISP REST API and the
> Wazuh API — no MISP database access. `.env` and `.secrets` hold live credentials and are
> git-ignored (see `.gitignore`) — never commit them.

### Tuning (env vars, defaults shown)

| Var | Default | Meaning |
|-----|---------|---------|
| `MISP_EXPORT_MODE` | `api` | `api` (REST, no DB) or `db` (direct MySQL, faster at scale) |
| `WAZUH_RELOAD` | `docker` | `docker` (exec in container) or `api` (REST restart) |
| `PER_LIST_CAP` | `200000` | max IOCs per list (most-recent kept) |
| `MAX_IOC_AGE_DAYS` | `180` | exclude indicators older than this |
| `REFRESH_SECONDS` | `86400` | loop interval |
| `REFRESH_BATCH` | `6` | feeds fetched per batch during the staggered refresh |
| `DO_REFRESH` | `1` | set `0` to export only, skipping the MISP feed re-fetch |
| `WL_ENFORCE` | `1` | set `0` to disable MISP warninglist filtering |
| `WL_SKIP_LISTS` | datacenter/VPN/cloud/dyn-DNS/LOTS | `;`-separated warninglist names whose hits are **kept** |
| `WL_BATCH` | `5000` | values per warninglist `checkValue` request |
| `WL_WARMUP_TRIES` / `WL_WARMUP_SLEEP` | `4` / `5` | 1-value probes (and seconds between them) that absorb MISP's cold-cache warninglist rebuild before the real batches |
| `CRON_PULLALL` | `0` | set > 0 when MISP's scheduled workers already fetch feeds — skips the loader's own refresh |

## Install the rules

```bash
cp custom_rules/misp_ioc_rules.xml /var/ossec/etc/rules/
chmod 0644 /var/ossec/etc/rules/misp_ioc_rules.xml

# confirm the 100210-100218 and 100227-100233 ranges are free (expect empty):
grep -rhoE 'rule id="(10021[0-8]|10022[7-9]|10023[0-3])"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/

/var/ossec/bin/wazuh-control reload   # or `up -d --force-recreate` for single-file bind mounts
```

## ID range / collisions

Uses **100210-100218** and **100227-100233** — clear of the stock Wazuh ruleset. Community
rulesets also use the 100000+ custom range, so verify it is free on your manager before installing.
