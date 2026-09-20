# ingest_leadita_shopify.py — fetches Leadita's daily Shopify sample and loads into shopify_warehouse
import os
import requests
from datetime import datetime, timezone

LEADITA_URL = (
    "https://raw.githubusercontent.com/leadita/tech-stack-datasets/"
    "main/leads/companies-using-shopify/sample.csv"
)
SOURCE_TAG = "leadita-shopify-daily"
DATABASE_URL = os.environ.get("DATABASE_URL")


def fetch_leadita_csv():
    r = requests.get(LEADITA_URL, timeout=30, headers={"User-Agent": "shopify-warehouse/1.0"})
    r.raise_for_status()
    return r.text


def parse_csv(text):
    """Parse Leadita's CSV. Columns: domain,title"""
    lines = [l for l in text.split("\n") if l.strip()]
    if not lines: return []
    header = lines[0].lower()
    start = 1 if "domain" in header else 0
    records = []
    for line in lines[start:]:
        # Handle simple CSV. Title may have commas → use split with maxsplit=1
        parts = line.split(",", 1)
        if len(parts) < 1: continue
        domain = parts[0].strip().strip('"').lower()
        title = parts[1].strip().strip('"') if len(parts) > 1 else ""
        if not domain or "." not in domain: continue
        records.append({"domain": domain, "title": title})
    return records


def normalize_domain(d):
    if not d or not isinstance(d, str): return None
    d = d.strip().lower()
    if d.startswith(("http://", "https://")):
        d = d.split("://", 1)[1]
    d = d.rstrip("/").split("/", 1)[0]
    d = d.split("?", 1)[0].split("#", 1)[0]
    if not d or "." not in d or " " in d: return None
    return d


def ingest(records, get_db, release_db):
    """Insert new Shopify domains into shopify_warehouse. Dedup via UNIQUE(url)."""
    queued = skipped = invalid = 0
    conn = get_db()
    if not conn: return 0, 0, 0
    try:
        cur = conn.cursor()
        for rec in records:
            domain = normalize_domain(rec.get("domain"))
            if not domain:
                invalid += 1
                continue
            url = f"https://{domain}"
            try:
                cur.execute(
                    """INSERT INTO shopify_warehouse
                        (url, domain, source, title, status)
                    VALUES (%s, %s, %s, %s, 'pending')
                    ON CONFLICT (url) DO NOTHING
                    RETURNING id""",
                    (url, domain, SOURCE_TAG, rec.get("title") or ""),
                )
                row = cur.fetchone()
                if row: queued += 1
                else: skipped += 1
            except Exception as e:
                print(f"insert err for {domain}: {e}")
                invalid += 1
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"ingest error: {e}")
    finally:
        release_db(conn)
    return queued, skipped, invalid


def run(get_db, release_db):
    print(f"[{datetime.now(timezone.utc).isoformat()}] Shopify ingest starting...")
    try:
        text = fetch_leadita_csv()
    except Exception as e:
        print(f"FETCH FAILED: {e}")
        return {"status": "error", "error": str(e)[:300]}
    records = parse_csv(text)
    queued, skipped, invalid = ingest(records, get_db, release_db)
    summary = {"status": "ok", "new": queued, "duplicates_skipped": skipped, "invalid": invalid}
    print(f"[{datetime.now(timezone.utc).isoformat()}] {summary}")
    return summary
