# ingest_leadita.py
import os
import requests
from datetime import datetime, timezone

LEADITA_URL = (
    "https://raw.githubusercontent.com/leadita/tech-stack-datasets/"
    "main/leads/companies-using-wix/sample.json"
)
SOURCE_TAG = "leadita-wix-daily"


def fetch_leadita_sample():
    r = requests.get(
        LEADITA_URL,
        timeout=30,
        headers={"User-Agent": "wix-warehouse/1.0"},
    )
    r.raise_for_status()
    return r.json()


def normalize_domain(d):
    if not d or not isinstance(d, str):
        return None
    d = d.strip().lower()
    if d.startswith(("http://", "https://")):
        d = d.split("://", 1)[1]
    d = d.rstrip("/").split("/", 1)[0]
    d = d.split("?", 1)[0].split("#", 1)[0]
    if not d or "." not in d or " " in d:
        return None
    return d


def ingest(json_data, get_db, release_db):
    records = json_data if isinstance(json_data, list) else json_data.get("data", [])
    queued = skipped = invalid = not_wix = 0

    conn = get_db()
    if not conn:
        return 0, 0, 0, 0

    try:
        cur = conn.cursor()
        for rec in records:
            if not isinstance(rec, dict):
                invalid += 1
                continue

            techs = rec.get("technologies", []) or []
            if not any("wix" in str(t).lower() for t in techs):
                not_wix += 1
                continue

            domain = normalize_domain(rec.get("domain"))
            if not domain:
                invalid += 1
                continue

            url = f"https://{domain}"

            cur.execute(
                """
                INSERT INTO wix_warehouse
                    (url, domain, source, title, country, seo_score, tech_spend, crawled_at, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pending')
                ON CONFLICT (url) DO NOTHING
                RETURNING id
                """,
                (
                    url,
                    domain,
                    SOURCE_TAG,
                    rec.get("title") or "",
                    rec.get("country") or None,
                    rec.get("seo_score"),
                    rec.get("tech_spend"),
                    rec.get("crawled_at"),
                ),
            )
            row = cur.fetchone()
            if row:
                queued += 1
            else:
                skipped += 1

        conn.commit()
        cur.close()
    except Exception as e:
        print(f"ingest error: {e}")
    finally:
        release_db(conn)

    return queued, skipped, invalid, not_wix


def run(get_db, release_db):
    print(f"[{datetime.now(timezone.utc).isoformat()}] Leadita ingest starting...")
    try:
        data = fetch_leadita_sample()
    except Exception as e:
        print(f"FETCH FAILED: {e}")
        return {"status": "error", "error": str(e)[:300]}

    queued, skipped, invalid, not_wix = ingest(data, get_db, release_db)
    summary = {
        "status": "ok",
        "new": queued,
        "duplicates_skipped": skipped,
        "invalid": invalid,
        "non_wix": not_wix,
    }
    print(f"[{datetime.now(timezone.utc).isoformat()}] {summary}")
    return summary
