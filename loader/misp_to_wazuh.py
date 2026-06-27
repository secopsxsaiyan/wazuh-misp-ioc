#!/usr/bin/env python3
"""
misp_to_wazuh.py — daily MISP threat-intel pipeline:
  1) STAGGERED feed re-fetch in MISP (small batches, draining between) — avoids the
     all-at-once fetch spike that corrupted the DB.
  2) Export to_ids IOCs into Wazuh CDB lists (via the Wazuh API). MISP_EXPORT_MODE=api
     reads them over the MISP REST API (no DB); =db reads MISP's MySQL directly. Values
     matching an ENABLED MISP warninglist (benign infra: public DNS/cloud/CDN, top-N
     domains, TLDs, reserved ranges) are dropped before upload.
  3) Manager reload: WAZUH_RELOAD=docker runs `wazuh-control restart` in the manager
     container over the docker socket (the API `manager/restart` proved unreliable);
     =api calls the REST restart endpoint for non-docker deployments.
Env: MISP_URL, ADMIN_KEY, WAZUH_API/USER/PASS, MISP_EXPORT_MODE (api|db),
     WAZUH_RELOAD (docker|api), MISP_DB_* (db mode), WAZUH_MGR_CONTAINER (docker reload),
     PER_LIST_CAP, MAX_IOC_AGE_DAYS, REFRESH_SECONDS, REFRESH_BATCH, DO_REFRESH, WL_ENFORCE.
"""
import os, sys, time, ipaddress
import urllib3
urllib3.disable_warnings()
import requests
# pymysql is imported lazily in db_conn() — only required for MISP_EXPORT_MODE=db

# ---------- IOC allowlist (benign IPs that must NEVER reach the CDB) ----------
# These are well-known public resolvers and infrastructure IPs that appear in MISP
# feeds as false positives (confirmed present in MISP DB as to_ids=1).
# Add IPs here to permanently suppress them regardless of feed changes.
# RFC1918/loopback/link-local are already filtered by public_ip(); this list covers
# public IPs that are benign by definition (DNS resolvers, CDN, etc.).
KNOWN_BENIGN_IPS = frozenset({
    # Google Public DNS
    "8.8.8.8", "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1", "1.0.0.1",
    # Quad9
    "9.9.9.9", "149.112.112.112",
    # OpenDNS / Cisco Umbrella
    "208.67.222.222", "208.67.220.220",
    # Level3 / CenturyLink public DNS
    "4.2.2.1", "4.2.2.2",
    # Verisign public DNS
    "64.6.64.6", "64.6.65.6",
    # Comodo Secure DNS
    "8.26.56.26", "8.20.247.20",
    # CleanBrowsing DNS
    "185.228.168.9", "185.228.169.9",
})

MISP    = os.environ.get("MISP_URL", "https://misp-core").rstrip("/")
MKEY    = os.environ.get("ADMIN_KEY", "")
# Export mode: "api" (portable — MISP REST /attributes/restSearch, no DB access) or
# "db" (direct MySQL read — faster for very large instances, needs MISP_DB_* + pymysql).
EXPORT_MODE = os.environ.get("MISP_EXPORT_MODE", "api").strip().lower()
DB_HOST = os.environ.get("MISP_DB_HOST", "db"); DB_USER = os.environ.get("MISP_DB_USER", "misp")
DB_PASS = os.environ.get("MISP_DB_PASS", ""); DB_NAME = os.environ.get("MISP_DB_NAME", "misp")
WZ_API  = os.environ.get("WAZUH_API", "https://wazuh.manager:55000").rstrip("/")
WZ_USER = os.environ.get("WAZUH_USER", "wazuh-wui"); WZ_PASS = os.environ["WAZUH_PASS"]
CAP     = int(os.environ.get("PER_LIST_CAP", "200000"))
# Manager reload: "docker" (exec wazuh-control restart in the container) or "api" (REST restart).
RELOAD_MODE = os.environ.get("WAZUH_RELOAD", "docker").strip().lower()
MGR_CONT = os.environ.get("WAZUH_MGR_CONTAINER", "wazuh.manager-1")
REFRESH_BATCH = int(os.environ.get("REFRESH_BATCH", "6"))
DO_REFRESH = os.environ.get("DO_REFRESH", "1") == "1"
# Max age of IOCs to include in CDB export (days). Older attributes are excluded so the
# candidate pool stays bounded and ORDER BY timestamp DESC is cheap. Default 180 days.
MAX_IOC_AGE_DAYS = int(os.environ.get("MAX_IOC_AGE_DAYS", "180"))
# Warninglist enforcement: drop exported IOCs that match an ENABLED MISP warninglist
# (benign infra — public DNS resolvers, cloud/CDN ranges, top-N popular domains, TLDs,
# reserved/documentation ranges). Leverages MISP's /warninglists/checkValue, which the
# raw DB export otherwise bypasses entirely. FAIL-OPEN: any error keeps the unfiltered set
# so a transient MISP hiccup never silently drops real IOCs. Toggle WL_ENFORCE=0; tune the
# per-request value count with WL_BATCH.
WL_ENFORCE = os.environ.get("WL_ENFORCE", "1") == "1"
WL_BATCH   = int(os.environ.get("WL_BATCH", "5000"))
# Recall protection: warninglists whose matches must NOT trigger suppression. Broad
# datacenter/VPN and cloud-provider IP ranges, plus dynamic-DNS and trusted-site-abuse
# domains, all routinely host real C2 — a feed hit there is still worth alerting on, so we
# keep those IOCs. Without this, the "vpn-ipv4 ... datacenters" list alone drops ~28% of
# the IP CDB. Substring-matched (case-insensitive) against the warninglist NAME;
# ';'-separated because names contain commas (e.g. "Top 1,000,000"). Set WL_SKIP_LISTS=""
# for the aggressive mode (suppress on every enabled warninglist).
WL_SKIP_DEFAULT = ("vpn-ipv4;amazon aws ip;gcp (google cloud;azure datacenter;"
                   "github ip ranges;dynamic dns;living off trusted")
WL_SKIP = [s.strip().lower() for s in
           os.environ.get("WL_SKIP_LISTS", WL_SKIP_DEFAULT).split(";") if s.strip()]

GROUPS = {"misp-ip": ["ip-src", "ip-dst"], "misp-domains": ["domain", "hostname"],
          "misp-hashes": ["md5", "sha1", "sha256"]}
MH = {"Authorization": MKEY, "Accept": "application/json", "Content-Type": "application/json"}
def log(m): print(f"[intel] {m}", flush=True)

def db_conn():
    import pymysql                                 # lazy — only needed for MISP_EXPORT_MODE=db
    return pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME,
                           connect_timeout=30, read_timeout=300)
def db_scalar(sql):
    c = db_conn()
    try:
        with c.cursor() as cur:
            cur.execute(sql); return cur.fetchone()[0]
    finally:
        c.close()

# ---------- 1. staggered feed refresh ----------
def running_fetches():
    if EXPORT_MODE != "db":
        return -1                                  # no DB visibility (api mode) -> fixed inter-batch pause
    try: return db_scalar("SELECT COUNT(*) FROM jobs WHERE worker=0x64656661756c74 AND progress<100")
    except Exception: return -1

def staggered_refresh():
    if not (DO_REFRESH and MKEY):
        log("refresh skipped (DO_REFRESH off or no ADMIN_KEY)"); return
    try:
        feeds = requests.get(f"{MISP}/feeds/index", headers=MH, verify=False, timeout=60).json()
    except Exception as e:
        log(f"refresh: feeds/index failed ({type(e).__name__}); skipping"); return
    enabled = [f["Feed"] for f in feeds if isinstance(f, dict) and f.get("Feed", {}).get("enabled")]
    log(f"staggered refresh: {len(enabled)} feeds, batches of {REFRESH_BATCH}")
    for i in range(0, len(enabled), REFRESH_BATCH):
        for fd in enabled[i:i + REFRESH_BATCH]:
            try: requests.post(f"{MISP}/feeds/fetchFromFeed/{fd['id']}", headers=MH, verify=False, timeout=60)
            except Exception: pass
        for _ in range(40):                      # drain this batch (cap ~10 min) before the next
            rf = running_fetches()
            if rf == 0: break
            if rf < 0:                            # no queue visibility (api mode): fixed pause
                time.sleep(20); break
            time.sleep(15)
    log("staggered refresh done")

# ---------- 2. export IOCs ----------
def db_values(types):
    """Return a deterministic, bounded set of recent IOCs from the MISP attributes table.

    Changes vs original:
    - WHERE timestamp >= age_cutoff: prunes stale IOCs (>MAX_IOC_AGE_DAYS old), reducing
      the candidate pool so the LIMIT is no longer a lottery over 800k+ rows.
    - ORDER BY timestamp DESC: most-recently-updated indicators are prioritised, making
      consecutive runs produce the same set (deterministic given the same DB state).
    - age_cutoff is computed from MAX_IOC_AGE_DAYS env var (default 180 days).
    """
    age_cutoff = int(time.time()) - MAX_IOC_AGE_DAYS * 86400
    c = db_conn()
    try:
        with c.cursor() as cur:
            ph = ",".join(["%s"] * len(types))
            # Count the full eligible pool for diagnostic logging
            cur.execute(
                f"SELECT COUNT(DISTINCT value1) FROM attributes WHERE deleted=0 AND to_ids=1 "
                f"AND type IN ({ph}) AND value1<>'' AND timestamp >= %s",
                (*types, age_cutoff))
            pool_size = cur.fetchone()[0]
            # Deterministic: ORDER BY timestamp DESC so the same recent IOCs win each run
            cur.execute(
                f"SELECT DISTINCT value1 FROM attributes WHERE deleted=0 AND to_ids=1 "
                f"AND type IN ({ph}) AND value1<>'' AND timestamp >= %s "
                f"ORDER BY timestamp DESC LIMIT %s",
                (*types, age_cutoff, CAP))
            vals = {r[0].strip() for r in cur.fetchall() if r and r[0]}
            if pool_size > CAP:
                log(f"  pool={pool_size} eligible IOCs (age<={MAX_IOC_AGE_DAYS}d), cap={CAP} "
                    f"— {pool_size - CAP} lower-priority IOCs trimmed (ORDER BY timestamp DESC)")
            return vals, pool_size
    finally:
        c.close()

def api_values(types):
    """Portable export via MISP REST /attributes/restSearch — no DB access required.
    Pages through to_ids indicators of the given types, bounded by MAX_IOC_AGE_DAYS.
    Returns (values, pool_size)."""
    vals, page, page_size = set(), 1, 10000
    while True:
        body = {"returnFormat": "json", "type": types, "to_ids": 1, "deleted": 0,
                "enforceWarninglist": 0, "includeEventTags": 0, "includeContext": 0,
                "timestamp": f"{MAX_IOC_AGE_DAYS}d", "limit": page_size, "page": page}
        r = requests.post(f"{MISP}/attributes/restSearch", headers=MH, json=body,
                          verify=False, timeout=300)
        r.raise_for_status()
        attrs = ((r.json() or {}).get("response", {}) or {}).get("Attribute", []) or []
        for a in attrs:
            v = (a.get("value") or "").strip()
            if v: vals.add(v)
        if len(attrs) < page_size or len(vals) >= CAP:
            break
        page += 1
    pool_size = len(vals)
    if len(vals) > CAP:
        log(f"  pool={pool_size} eligible IOCs (age<={MAX_IOC_AGE_DAYS}d), cap={CAP} "
            f"— {pool_size - CAP} IOCs trimmed")
        vals = set(sorted(vals)[:CAP])
    return vals, pool_size

def get_values(types):
    """Dispatch to the configured export mode."""
    return db_values(types) if EXPORT_MODE == "db" else api_values(types)

def public_ip(v):
    try:
        ip = ipaddress.ip_address(v)
        if ip.version != 4: return False         # IPv6 colons break the CDB key:value format
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast
                    or ip.is_link_local or ip.is_unspecified)
    except ValueError:
        return False

def _wl_benign(matches):
    """A value is benign (drop it) only if at least one matched warninglist is NOT in the
    recall-protective skip set. Values matched solely by skipped lists (datacenter/cloud/
    dyndns/trusted-site) are kept so those IOCs still alert."""
    for mm in matches:
        nm = (mm.get("name") or "").lower()
        if not any(sk in nm for sk in WL_SKIP):
            return True
    return False

def warninglist_filter(values, label):
    """Remove values matching any ENABLED MISP warninglist via /warninglists/checkValue,
    EXCEPT matches that come only from recall-protective skipped lists (see WL_SKIP).
    Returns (kept_set, removed_count). checkValue returns ONLY matched values as response
    keys (non-matches omitted), each with the matched warninglist names.
    FAIL-OPEN: on any non-200 / exception, returns the input unchanged (removed=0) so the
    SIEM feed never loses real IOCs to a transient MISP problem."""
    if not WL_ENFORCE or not values:
        return set(values), 0
    vals = list(values)
    benign = set()
    try:
        for i in range(0, len(vals), WL_BATCH):
            batch = vals[i:i + WL_BATCH]
            r = requests.post(f"{MISP}/warninglists/checkValue.json", headers=MH,
                              json=batch, verify=False, timeout=180)
            if r.status_code != 200:
                log(f"{label}: warninglist check HTTP {r.status_code} (batch {i // WL_BATCH}) "
                    f"— FAIL-OPEN, keeping {len(vals)} unfiltered")
                return set(vals), 0
            benign.update(v for v, matches in r.json().items() if _wl_benign(matches))
    except Exception as e:
        log(f"{label}: warninglist check failed ({type(e).__name__}: {str(e)[:80]}) — FAIL-OPEN")
        return set(vals), 0
    kept = {v for v in vals if v not in benign}
    return kept, len(vals) - len(kept)

def wz_token():
    last = None
    for _ in range(15):                          # manager auth 500s for ~1-2 min after a restart
        try:
            r = requests.post(f"{WZ_API}/security/user/authenticate", auth=(WZ_USER, WZ_PASS),
                              verify=False, timeout=30)
            if r.status_code == 200: return r.json()["data"]["token"]
            last = f"HTTP {r.status_code}"
        except Exception as e:
            last = type(e).__name__
        time.sleep(10)
    raise RuntimeError(f"Wazuh auth failed: {last}")

def wz_put_list(token, name, values):
    body = "".join(f"{v}:\n" for v in sorted(values))
    r = requests.put(f"{WZ_API}/lists/files/{name}", params={"overwrite": "true"},
                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"},
                     data=body.encode(), verify=False, timeout=180)
    return r.status_code

def export_iocs():
    token = wz_token(); total = 0
    for name, types in GROUPS.items():
        try:
            vals, pool_size = get_values(types)
        except Exception as e:
            log(f"{name}: IOC read FAILED ({type(e).__name__}: {str(e)[:80]}); skipping"); continue
        if name == "misp-ip":
            before = len(vals)
            # Filter 1: reject non-public / RFC1918 / loopback / link-local / multicast IPs
            vals = {v for v in vals if public_ip(v)}
            # Filter 2: reject known-benign public IPs (DNS resolvers, CDN infra etc.)
            #            that appear in feeds as false positives (confirmed in MISP DB)
            benign_hits = vals & KNOWN_BENIGN_IPS
            if benign_hits:
                log(f"{name}: suppressing {len(benign_hits)} known-benign IPs: {sorted(benign_hits)}")
            vals = vals - KNOWN_BENIGN_IPS
            # Filter 3: drop IPs matching an enabled MISP warninglist (cloud/CDN/DNS/reserved)
            vals, wl_removed = warninglist_filter(vals, name)
            log(f"{name}: {before} raw -> {len(vals)} after public+benign+warninglist "
                f"(warninglist dropped {wl_removed}, pool={pool_size}) "
                f"-> Wazuh API {wz_put_list(token, name, vals)}")
        elif name == "misp-domains":
            before = len(vals)
            # drop domains matching an enabled MISP warninglist (top-N popular, TLDs, LOTS)
            vals, wl_removed = warninglist_filter(vals, name)
            log(f"{name}: {before} -> {len(vals)} after warninglist "
                f"(dropped {wl_removed}, pool={pool_size}) -> Wazuh API {wz_put_list(token, name, vals)}")
        else:
            log(f"{name}: {len(vals)} IOCs (pool={pool_size}) -> Wazuh API {wz_put_list(token, name, vals)}")
        total += len(vals)
    return total

# ---------- 3. manager reload ----------
def reload_manager():
    # WAZUH_RELOAD=docker (default): exec wazuh-control restart in the manager container.
    if RELOAD_MODE != "api":
        try:
            import docker
            mgr = docker.from_env().containers.get(MGR_CONT)
            rc, out = mgr.exec_run("/var/ossec/bin/wazuh-control restart", user="root")
            log(f"wazuh-control restart (docker exec) rc={rc}")
            return
        except Exception as e:
            log(f"docker reload FAILED ({type(e).__name__}: {str(e)[:90]}); trying API restart")
    # WAZUH_RELOAD=api, or docker reload unavailable: call the Wazuh REST restart endpoint.
    try:
        t = wz_token()
        requests.put(f"{WZ_API}/manager/restart", headers={"Authorization": f"Bearer {t}"},
                     verify=False, timeout=60)
        log("manager restart requested via Wazuh API")
    except Exception as e2:
        log(f"API restart failed: {type(e2).__name__}")

def run_once():
    staggered_refresh()
    total = export_iocs()
    if total > 0:
        reload_manager()
    else:
        log("0 IOCs exported (MISP unreachable or empty) — "
            "skipping manager reload to avoid a needless restart")
    log(f"cycle complete: {total} IOCs pushed")

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "once"
    if mode == "export":                          # export only, no refresh
        if export_iocs() > 0:
            reload_manager()
        else:
            log("0 IOCs exported — skipping manager reload")
    elif mode == "loop":
        interval = int(os.environ.get("REFRESH_SECONDS", "86400"))
        while True:
            try: run_once()
            except Exception as e: log(f"cycle failed: {type(e).__name__}: {str(e)[:160]}")
            log(f"sleeping {interval}s"); time.sleep(interval)
    else:
        run_once()
