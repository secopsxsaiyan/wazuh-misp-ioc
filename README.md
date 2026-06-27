# MISP IOC Matching Rules for Wazuh

Match live Wazuh telemetry against **MISP threat-intel indicators** held in Wazuh CDB lists,
and (optionally) tier the alerts by whether the traffic was already blocked.

These rules consult three CDB lists (`etc/lists/misp-ip`, `etc/lists/misp-domains`,
`etc/lists/misp-hashes`) that the **included loader** (`loader/`) refreshes from MISP. They
cover **IP** indicators (src/dst), **file-hash** indicators (SHA256 / SHA1 / MD5 on FIM events),
and **domain** indicators (pre-staged for a future DNS source).

> **Note** — distinct from the SOCFortress `MISP` integration (`100620-misp.xml`), which
> decodes the MISP module's own enrichment output. These rules instead **match indicators
> against your existing event stream** (firewall/CEF/FIM/auth). No ID overlap with SOCFortress.

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
  (Suricata/Zeek `eve.json`, sysmon-for-linux DNS) that sets `dns.rrname`.

## How the CDB lists are populated

The rules are inert until the three CDB lists exist and are non-empty. This repo ships a loader
(`loader/`) that builds and refreshes them. The field/`lookup` idioms the rules rely on:

| List | Field | `lookup` |
|------|-------|----------|
| `etc/lists/misp-ip` | `srcip` / `dstip` | `address_match_key` |
| `etc/lists/misp-hashes` | `sha256_after` / `sha1_after` / `md5_after` | `match_key` |
| `etc/lists/misp-domains` | `dns.rrname` | `match_key` |

Declare the lists in `ossec.conf` under `<ruleset>`:

```xml
<ruleset>
  <list>etc/lists/misp-ip</list>
  <list>etc/lists/misp-domains</list>
  <list>etc/lists/misp-hashes</list>
</ruleset>
```

(You can populate the lists any other way too — e.g. the SOCFortress `custom-misp` integration —
as long as the file names and `key:value` CDB format match. The included loader is the turnkey option.)

## Loader (`loader/`)

`loader/misp_to_wazuh.py` is a small Python pipeline. Each cycle it:

1. **Staggered feed refresh** — re-fetches enabled MISP feeds in small batches, draining between
   batches (avoids the all-at-once fetch spike that can corrupt the MISP DB). Skip with `DO_REFRESH=0`.
2. **Exports `to_ids` IOCs** (`ip-src/ip-dst`, `domain/hostname`, `md5/sha1/sha256`). Two modes:
   - **`MISP_EXPORT_MODE=api`** (default, portable) — pulls indicators via the MISP REST API
     (`/attributes/restSearch`). Needs only `MISP_URL` + `ADMIN_KEY`; **no database access**.
   - **`MISP_EXPORT_MODE=db`** — reads MISP's MySQL directly (faster for very large instances;
     needs the `MISP_DB_*` vars and the `pymysql` package).
   Either mode then filters: non-public/RFC1918 IPs, a built-in public-DNS allowlist, and anything
   matching an **enabled MISP warninglist** (with a recall-protective skip-list so datacenter/VPN/
   dyn-DNS ranges that host real C2 are kept). Warninglist checking is **fail-open**. Each list is
   pushed to Wazuh via `PUT /lists/files/<name>`.
3. **Reloads the manager** — **`WAZUH_RELOAD=docker`** (default) runs `wazuh-control restart` in the
   manager container over the docker socket; **`WAZUH_RELOAD=api`** calls the REST restart endpoint
   for non-docker deployments.

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

## Install the rules

```bash
cp custom_rules/misp_ioc_rules.xml /var/ossec/etc/rules/
chmod 0644 /var/ossec/etc/rules/misp_ioc_rules.xml

# confirm the 100210-100218 range is free (expect empty):
grep -rhoE 'rule id="10021[0-8]"' /var/ossec/etc/rules/ /var/ossec/ruleset/rules/

/var/ossec/bin/wazuh-control reload   # or `up -d --force-recreate` for single-file bind mounts
```

## ID range / collisions

Uses **100210-100218** — verified clear against the full SOCFortress ruleset (no renumbering
needed). Verify it is also free on your manager before installing.
