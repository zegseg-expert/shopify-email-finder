from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import requests
import re
import os
import time
import json
import hashlib
import threading
import random
import dns.resolver
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import psycopg2
from psycopg2 import pool
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345_change_this'
DATABASE_URL = os.environ.get('DATABASE_URL')
SHODAN_API_KEY = 'W5LL903l5aFfMROHmpBQGNm7mMkCimWq'
HF_DATASET = "snncn/shopify-websites"

SHOPIFY_IPS = ["23.227.38.32","23.227.38.36","23.227.38.65","23.227.38.66","23.227.38.67","23.227.38.68","23.227.38.69","23.227.38.70","23.227.38.71","23.227.38.72","23.227.38.73","23.227.38.74","23.227.39.20"]

# ==========================================
# DB POOL
# ==========================================
_db_pool = None

def init_pool():
    global _db_pool
    if not DATABASE_URL: return
    try:
        _db_pool = pool.SimpleConnectionPool(1, 10, DATABASE_URL, sslmode='require')
        print("✅ Pool ready")
    except Exception as e:
        print(f"⚠️ Pool: {e}")

def get_db():
    global _db_pool
    if not DATABASE_URL: return None
    if _db_pool is None: init_pool()
    if _db_pool is None:
        try: return psycopg2.connect(DATABASE_URL, sslmode='require')
        except: return None
    try: return _db_pool.getconn()
    except: return None

def release_db(conn):
    global _db_pool
    if conn and _db_pool:
        try: _db_pool.putconn(conn)
        except: pass

_dns_cache = {}
def resolve_mx(domain):
    if domain in _dns_cache: return _dns_cache[domain]
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result = [str(r.exchange) for r in mx]
        _dns_cache[domain] = result
        return result
    except:
        _dns_cache[domain] = None
        return None

def init_db():
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            sender_name VARCHAR(255) DEFAULT '',
            hf_offset INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        try: cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS sender_name VARCHAR(255) DEFAULT ''")
        except: pass
        try: cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS hf_offset INTEGER DEFAULT 0")
        except: pass
        cur.execute("""CREATE TABLE IF NOT EXISTS scraped_stores (
            id SERIAL PRIMARY KEY, domain VARCHAR(255) UNIQUE NOT NULL,
            emails TEXT, scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS user_state (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) UNIQUE NOT NULL,
            found_emails TEXT, verified_emails TEXT, scout_recipients TEXT,
            scout_subject TEXT, scout_message TEXT, scout_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS verify_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            job_name VARCHAR(255), total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            valid_emails TEXT, invalid_emails TEXT, remaining_emails TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS discovered_stores (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL, source VARCHAR(50),
            has_email BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, domain))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS email_scans (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            results JSONB, emails TEXT, email_count INTEGER DEFAULT 0, store_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_history (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL, report JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_queue (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL, domain VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            report JSONB, subject TEXT, message TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, email))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS sent_log (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, email))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS hf_imports (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            requested INTEGER DEFAULT 0,
            added INTEGER DEFAULT 0,
            skipped INTEGER DEFAULT 0,
            offset_before INTEGER DEFAULT 0,
            offset_after INTEGER DEFAULT 0,
            domains TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.commit(); cur.close()
        print("✅ DB ready")
    except Exception as e: print(f"❌ DB: {e}")
    finally: release_db(conn)

try:
    init_pool(); init_db()
except: pass

def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def generate_case_id():
    return "ESS" + str(random.randint(10000, 99999))

def root_domain(hostname):
    hostname = hostname.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    parts = hostname.split('.')
    if len(parts) <= 2: return hostname
    if parts[-2] in ['co','com','net','org','ac','gov'] and len(parts) >= 3:
        if parts[-1] in ['uk','au','nz','in','za','br','mx']:
            return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def domain_from_email(email):
    try: return email.split('@')[1].strip().lower()
    except: return ''

def get_user_sender_name(user_email):
    conn = get_db()
    if not conn: return ''
    try:
        cur = conn.cursor()
        cur.execute("SELECT sender_name FROM users WHERE email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        return row[0] if row and row[0] else ''
    except: return ''
    finally: release_db(conn)

def set_user_sender_name(user_email, name):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET sender_name = %s WHERE email = %s", (name, user_email))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def get_hf_offset(user_email):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT hf_offset FROM users WHERE email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        return row[0] if row and row[0] else 0
    except: return 0
    finally: release_db(conn)

def set_hf_offset(user_email, offset):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET hf_offset = %s WHERE email = %s", (offset, user_email))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def get_cached_emails(domain):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT emails FROM scraped_stores WHERE domain = %s AND scraped_at > NOW() - INTERVAL '7 days'", (domain,))
        row = cur.fetchone(); cur.close()
        return row[0].split(',') if row and row[0] else None
    except: return None
    finally: release_db(conn)

def cache_emails(domain, emails):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO scraped_stores (domain, emails) VALUES (%s, %s)
            ON CONFLICT (domain) DO UPDATE SET emails = %s, scraped_at = NOW()""",
            (domain, ','.join(emails), ','.join(emails)))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def save_user_state(user_email, **kwargs):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_state (user_email) VALUES (%s)", (user_email,))
        for k, v in kwargs.items():
            if v is not None:
                cur.execute(f"UPDATE user_state SET {k}=%s, updated_at=NOW() WHERE user_email=%s", (v, user_email))
        conn.commit(); cur.close()
    except Exception as e: print(f"save: {e}")
    finally: release_db(conn)

def load_user_state(user_email):
    conn = get_db()
    if not conn: return {}
    try:
        cur = conn.cursor()
        cur.execute("SELECT found_emails, verified_emails, scout_recipients, scout_subject, scout_message, scout_count FROM user_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        if row:
            return {
                'found_emails': row[0].split('|||') if row[0] else [],
                'verified_emails': row[1].split('|||') if row[1] else [],
                'scout_recipients': row[2].split('|||') if row[2] else [],
                'scout_subject': row[3] or '',
                'scout_message': row[4] or '',
                'scout_count': row[5] or 0
            }
        return {}
    except: return {}
    finally: release_db(conn)

# ==========================================
# HUGGING FACE IMPORT
# ==========================================
def fetch_hf_batch(offset, length):
    try:
        url = f"https://datasets-server.huggingface.co/rows?dataset={requests.utils.quote(HF_DATASET)}&config=default&split=train&offset={offset}&length={length}"
        r = requests.get(url, timeout=20)
        if r.status_code == 200:
            data = r.json()
            return data.get('rows', []), data.get('num_rows_total', 0)
        return [], 0
    except Exception as e:
        print(f"HF fetch error: {e}")
        return [], 0

def do_hf_import(user_email, requested):
    offset = get_hf_offset(user_email)
    all_rows = []
    total_available = 0
    fetched = 0
    MAX_PER_CALL = 100
    while fetched < requested:
        batch_size = min(MAX_PER_CALL, requested - fetched)
        rows, total = fetch_hf_batch(offset + fetched, batch_size)
        if total > 0: total_available = total
        if not rows: break
        all_rows.extend(rows)
        fetched += len(rows)
        if len(rows) < batch_size: break
        time.sleep(0.3)
    if not all_rows:
        return {'success': False, 'error': 'No rows fetched', 'added': 0, 'skipped': 0, 'offset_after': offset}
    conn = get_db()
    if not conn: return {'success': False, 'error': 'No DB', 'added': 0, 'skipped': 0, 'offset_after': offset}
    added = 0; skipped = 0; added_domains = []; seen = set()
    try:
        cur = conn.cursor()
        for item in all_rows:
            row_data = item.get('row', {})
            store_url = row_data.get('url', '')
            if not store_url: continue
            clean = store_url.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0].strip().lower()
            if not clean or '.' not in clean: continue
            if clean in seen: skipped += 1; continue
            seen.add(clean)
            cur.execute("SELECT id FROM discovered_stores WHERE user_email = %s AND domain = %s", (user_email, clean))
            if cur.fetchone(): skipped += 1; continue
            try:
                cur.execute("""INSERT INTO discovered_stores (user_email, domain, source)
                    VALUES (%s, %s, 'huggingface') ON CONFLICT (user_email, domain) DO NOTHING""",
                    (user_email, clean))
                if cur.rowcount > 0: added += 1; added_domains.append(clean)
            except: pass
        conn.commit(); cur.close()
    except Exception as e:
        return {'success': False, 'error': str(e), 'added': 0, 'skipped': 0, 'offset_after': offset}
    finally: release_db(conn)
    new_offset = offset + len(all_rows)
    if total_available > 0 and new_offset >= total_available: new_offset = 0
    set_hf_offset(user_email, new_offset)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("""INSERT INTO hf_imports (user_email, requested, added, skipped, offset_before, offset_after, domains)
                VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                (user_email, requested, added, skipped, offset, new_offset, '|||'.join(added_domains)))
            cur.execute("""DELETE FROM hf_imports WHERE user_email = %s
                AND id NOT IN (SELECT id FROM hf_imports WHERE user_email = %s ORDER BY created_at DESC LIMIT 3)""", (user_email, user_email))
            conn.commit(); cur.close()
        except Exception as e: print(f"save hf history: {e}")
        finally: release_db(conn)
    return {'success': True, 'added': added, 'skipped': skipped, 'offset_before': offset, 'offset_after': new_offset, 'total_available': total_available}

def get_hf_history(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, requested, added, skipped, offset_after, created_at FROM hf_imports WHERE user_email = %s ORDER BY created_at DESC LIMIT 3", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'requested': r[1], 'added': r[2], 'skipped': r[3], 'offset': r[4], 'created_at': str(r[5])[:16]} for r in rows]
    except: return []
    finally: release_db(conn)

def get_hf_import_detail(import_id, user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT domains FROM hf_imports WHERE id = %s AND user_email = %s", (import_id, user_email))
        row = cur.fetchone(); cur.close()
        return row[0].split('|||') if row and row[0] else []
    except: return []
    finally: release_db(conn)

# ==========================================
# QUEUE
# ==========================================
def add_to_queue(user_email, emails):
    conn = get_db()
    if not conn: return 0, 0
    added = 0; skipped = 0
    try:
        cur = conn.cursor()
        for email in emails:
            email = email.strip().lower()
            if not email or '@' not in email: continue
            domain = domain_from_email(email)
            if not domain: continue
            cur.execute("SELECT id FROM sent_log WHERE user_email = %s AND email = %s", (user_email, email))
            if cur.fetchone(): skipped += 1; continue
            try:
                cur.execute("""INSERT INTO audit_queue (user_email, email, domain, status)
                    VALUES (%s, %s, %s, 'pending') ON CONFLICT (user_email, email) DO NOTHING""",
                    (user_email, email, domain))
                if cur.rowcount > 0: added += 1
            except: pass
        conn.commit(); cur.close()
    except Exception as e: print(f"add_to_queue: {e}")
    finally: release_db(conn)
    return added, skipped

def get_queue(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, email, domain, status, report, subject, message FROM audit_queue WHERE user_email = %s
            ORDER BY CASE status WHEN 'pending' THEN 1 WHEN 'current' THEN 2 WHEN 'done' THEN 3 WHEN 'skipped' THEN 4 ELSE 5 END, added_at ASC""", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'email': r[1], 'domain': r[2], 'status': r[3], 'has_report': bool(r[4]), 'subject': r[5] or '', 'message': r[6] or ''} for r in rows]
    except: return []
    finally: release_db(conn)

def update_queue_item(item_id, user_email, **kwargs):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        for k, v in kwargs.items():
            if v is not None:
                if k == 'report':
                    cur.execute(f"UPDATE audit_queue SET {k}=%s, updated_at=NOW() WHERE id=%s AND user_email=%s", (json.dumps(v), item_id, user_email))
                else:
                    cur.execute(f"UPDATE audit_queue SET {k}=%s, updated_at=NOW() WHERE id=%s AND user_email=%s", (v, item_id, user_email))
        conn.commit(); cur.close()
    except Exception as e: print(f"update_queue: {e}")
    finally: release_db(conn)

def get_queue_item(item_id, user_email):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain, status, report, subject, message FROM audit_queue WHERE id=%s AND user_email=%s", (item_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return None
        report = None
        if row[4]:
            try: report = json.loads(row[4]) if isinstance(row[4], str) else row[4]
            except: report = None
        return {'id': row[0], 'email': row[1], 'domain': row[2], 'status': row[3], 'report': report, 'subject': row[5] or '', 'message': row[6] or ''}
    except: return None
    finally: release_db(conn)

def clear_queue(user_email, only_pending=False):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        if only_pending:
            cur.execute("DELETE FROM audit_queue WHERE user_email = %s AND status IN ('pending','current')", (user_email,))
        else:
            cur.execute("DELETE FROM audit_queue WHERE user_email = %s", (user_email,))
        n = cur.rowcount
        conn.commit(); cur.close()
        return n
    except: return 0
    finally: release_db(conn)

def mark_sent(user_email, email):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO sent_log (user_email, email) VALUES (%s, %s) ON CONFLICT DO NOTHING", (user_email, email))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def get_next_pending_item(user_email):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain, status, report, subject, message FROM audit_queue WHERE user_email = %s AND status = 'pending' ORDER BY added_at ASC LIMIT 1", (user_email,))
        row = cur.fetchone(); cur.close()
        if not row: return None
        report = None
        if row[4]:
            try: report = json.loads(row[4]) if isinstance(row[4], str) else row[4]
            except: report = None
        return {'id': row[0], 'email': row[1], 'domain': row[2], 'status': row[3], 'report': report, 'subject': row[5] or '', 'message': row[6] or ''}
    except: return None
    finally: release_db(conn)

# ==========================================
# EMAIL SCAN HISTORY
# ==========================================
def save_email_scan(user_email, results, store_count):
    conn = get_db()
    if not conn: return
    try:
        total_emails = sum(len(r.get('emails', [])) for r in results)
        flat_emails = []
        for r in results: flat_emails.extend(r.get('emails', []))
        cur = conn.cursor()
        cur.execute("""INSERT INTO email_scans (user_email, results, emails, email_count, store_count)
            VALUES (%s, %s, %s, %s, %s)""", (user_email, json.dumps(results), ','.join(flat_emails), total_emails, store_count))
        cur.execute("""DELETE FROM email_scans WHERE user_email = %s
            AND id NOT IN (SELECT id FROM email_scans WHERE user_email = %s ORDER BY created_at DESC LIMIT 3)""", (user_email, user_email))
        conn.commit(); cur.close()
    except Exception as e: print(f"save_email_scan: {e}")
    finally: release_db(conn)

def get_email_scans(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email_count, store_count, created_at FROM email_scans WHERE user_email = %s ORDER BY created_at DESC LIMIT 3", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'count': r[1], 'stores': r[2], 'created_at': str(r[3])[:16]} for r in rows]
    except: return []
    finally: release_db(conn)

def get_email_scan_detail(scan_id, user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT results, emails FROM email_scans WHERE id = %s AND user_email = %s", (scan_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return []
        if row[0]:
            try:
                parsed = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                if parsed and len(parsed) > 0: return parsed
            except: pass
        if row[1]:
            flat = row[1].split(',') if isinstance(row[1], str) else row[1]
            return [{'store': '(old format)', 'emails': [e for e in flat if e.strip()]}]
        return []
    except: return []
    finally: release_db(conn)

# ==========================================
# AUDIT HISTORY
# ==========================================
def save_audit_history(user_email, domain, report):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO audit_history (user_email, domain, report) VALUES (%s, %s, %s)", (user_email, domain, json.dumps(report)))
        cur.execute("""DELETE FROM audit_history WHERE user_email = %s
            AND id NOT IN (SELECT id FROM audit_history WHERE user_email = %s ORDER BY created_at DESC LIMIT 3)""", (user_email, user_email))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

# ==========================================
# VERIFY
# ==========================================
def verify_email(email):
    try:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return email, False, "Invalid syntax"
        domain = email.split('@')[1]
        mx = resolve_mx(domain)
        if mx is None: return email, False, "No mail server"
        try:
            server = smtplib.SMTP(mx[0], timeout=3)
            server.ehlo()
            resp = server.verify(email)
            server.quit()
            return (email, True, "Valid") if resp[0] == 250 else (email, False, "May not exist")
        except:
            return email, True, "Valid (domain)"
    except:
        return email, False, "Unknown"

def background_verify_worker(job_id):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_emails, valid_emails, invalid_emails, user_email FROM verify_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        valid = row[1].split('|||') if row[1] else []
        invalid = row[2].split('|||') if row[2] else []
        user_email = row[3]
    finally: release_db(conn)
    CHUNK_SIZE = 100
    while remaining:
        conn = get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            cur.execute("SELECT status FROM verify_jobs WHERE id = %s", (job_id,))
            sr = cur.fetchone(); cur.close()
            if not sr or sr[0] == 'cancelled': return
        finally: release_db(conn)
        chunk = remaining[:CHUNK_SIZE]
        remaining = remaining[CHUNK_SIZE:]
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(verify_email, e): e for e in chunk}
            for f in as_completed(futures):
                email, ok, reason = f.result()
                if ok: valid.append(email)
                else: invalid.append(email + " - " + reason)
        conn = get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            new_status = 'completed' if not remaining else 'running'
            cur.execute("""UPDATE verify_jobs SET processed=%s, valid_emails=%s, invalid_emails=%s,
                remaining_emails=%s, status=%s, updated_at=NOW() WHERE id=%s""",
                (len(valid) + len(invalid), '|||'.join(valid), '|||'.join(invalid),
                 '|||'.join(remaining), new_status, job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    if user_email and valid:
        save_user_state(user_email, verified_emails='|||'.join(valid))

def find_emails(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    if not domain or '.' not in domain: return []
    cached = get_cached_emails(domain)
    if cached is not None: return cached
    emails = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for url in [f"https://{domain}/pages/contact", f"https://{domain}/contact", f"https://{domain}"]:
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                clean = re.sub(r'<script[^>]*>.*?</script>', ' ', r.text, flags=re.DOTALL)
                clean = re.sub(r'<[^>]+>', ' ', clean)
                for e in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean):
                    emails.append(e.lower())
                for cf in re.findall(r'data-cfemail="([a-f0-9]+)"', r.text):
                    try:
                        k = int(cf[:2], 16)
                        d = ''.join([chr(int(cf[i:i+2], 16) ^ k) for i in range(2, len(cf), 2)])
                        if '@' in d and '.' in d: emails.append(d.lower())
                    except: pass
                for e in re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text):
                    emails.append(e.lower())
                if len(set(emails)) >= 3: break
        except: continue
    skip = ['.jpg','.png','.jpeg','.gif','.svg','2x','3x','wix','sentry','godaddy','namecheap',
            'markmonitor','tucows','domainabuse','abuse@','whoisproxy','whoisrequest','contactprivacy',
            'withheldforprivacy','example.com','example.org','wixpress','cloudflare','xinnet','wildwest',
            'dnai','web.com','domainmarket','no-reply@registrar','protect@','shopify.com','myshopify.com',
            'you@email.com','your@email.com','email@email.com','test@test.com','user@email.com',
            'name@email.com','service@domainmarket','interested@','sentry.io','facebook.com',
            'instagram.com','twitter.com','pinterest.com','@2x','@3x']
    final = [e for e in set(emails) if len(e) > 5 and '.' in e and not any(x in e for x in skip)]
    cache_emails(domain, final)
    return final

# ==========================================
# AUDIT
# ==========================================
def audit_store(domain, case_id):
    raw = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    report = {"domain": raw, "case_id": case_id, "audited_at": datetime.now().isoformat(), "checks": {}, "scores": {}, "issues": [], "positives": []}
    if not raw or '.' not in raw:
        report['error'] = "Invalid domain"; return report
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept-Language": "en-US,en;q=0.5"}
    base_url = f"https://{raw}"
    try:
        start = time.time()
        r = requests.get(base_url, headers=headers, timeout=10, allow_redirects=True)
        lt = round(time.time() - start, 2)
        report["checks"]["https"] = True; report["checks"]["http_status"] = r.status_code
        report["checks"]["load_time_seconds"] = lt; report["checks"]["final_url"] = r.url
        html = r.text
        if lt < 1.5: report["positives"].append(f"Fast load time ({lt}s)")
        elif lt > 3: report["issues"].append({"title": "Slow Load Time", "description": f"Store took {lt}s to load.", "recommendation": "Optimize images, remove unused apps.", "severity": "medium"})
    except Exception as e:
        report["checks"]["https"] = False
        report["error"] = f"Could not reach store: {str(e)[:100]}"; return report
    is_shop = any(x in html.lower() for x in ['cdn.shopify.com', 'shopify.theme', 'shopify-section', 'myshopify.com'])
    report["checks"]["is_shopify"] = is_shop
    if is_shop: report["positives"].append("Confirmed Shopify store")
    try:
        r2 = requests.get(f"{base_url}/products.json?limit=250", headers=headers, timeout=10)
        if r2.status_code == 200:
            products_data = r2.json().get('products', [])
            pc = len(products_data)
            report["checks"]["product_count"] = pc; report["checks"]["product_count_capped"] = (pc == 250)
            if pc == 0: report["issues"].append({"title": "No Products Visible", "description": "No products.", "recommendation": "Add products.", "severity": "high"})
            elif pc < 10: report["issues"].append({"title": f"Only {pc} Products", "description": "Few products.", "recommendation": "Aim for 20+.", "severity": "medium"})
            else: report["positives"].append(f"{pc}+ products")
            max_img_kb = 0
            for p in products_data[:10]:
                for img in p.get('images', [])[:3]:
                    src = img.get('src', '')
                    if src:
                        try:
                            hr = requests.head(src, headers=headers, timeout=5, allow_redirects=True)
                            cl = hr.headers.get('content-length')
                            if cl:
                                kb = int(cl) / 1024
                                if kb > max_img_kb: max_img_kb = kb
                        except: pass
            if max_img_kb > 0:
                report["checks"]["max_image_kb"] = round(max_img_kb, 1)
                if max_img_kb > 1000: report["issues"].append({"title": "Images Too Large", "description": f"Largest image {round(max_img_kb)}KB.", "recommendation": "Compress to under 300KB.", "severity": "medium"})
                else: report["positives"].append("Images optimized")
    except: report["checks"]["product_count"] = None
    tm = re.search(r'"theme_name"\s*:\s*"([^"]+)"', html)
    report["checks"]["theme"] = tm.group(1) if tm else "Unknown"
    hv = 'name="viewport"' in html.lower()
    report["checks"]["mobile_responsive"] = hv
    if hv: report["positives"].append("Mobile responsive")
    else: report["issues"].append({"title": "Not Mobile Responsive", "description": "Missing viewport.", "recommendation": "Use mobile theme.", "severity": "high"})
    he = bool(re.search(r'mailto:[^"\']+', html)); hp = bool(re.search(r'tel:[^"\']+', html))
    report["checks"]["has_email_link"] = he; report["checks"]["has_phone_link"] = hp
    report["checks"]["has_contact_page"] = 'contact' in html.lower()
    if he or hp: report["positives"].append("Contact info present")
    else: report["issues"].append({"title": "No Contact Info", "description": "No email/phone.", "recommendation": "Add Contact page.", "severity": "high"})
    socials = [p.split('.')[0] for p in ['facebook.com','instagram.com','twitter.com','tiktok.com','youtube.com','pinterest.com'] if p in html.lower()]
    report["checks"]["social_links"] = socials
    if len(socials) >= 2: report["positives"].append(f"{len(socials)} socials")
    elif len(socials) == 0: report["issues"].append({"title": "No Social Media", "description": "None found.", "recommendation": "Add social profiles.", "severity": "medium"})
    pols = ['/policies/refund-policy','/policies/privacy-policy','/policies/terms-of-service','/policies/shipping-policy']
    pf = [0]
    def cp(p):
        try:
            r3 = requests.get(f"{base_url}{p}", headers=headers, timeout=5)
            if r3.status_code == 200: pf[0] += 1
        except: pass
    with ThreadPoolExecutor(max_workers=4) as ex: list(ex.map(cp, pols))
    report["checks"]["policy_pages_found"] = f"{pf[0]}/4"
    if pf[0] == 4: report["positives"].append("All policies present")
    elif pf[0] < 2: report["issues"].append({"title": f"Missing {4-pf[0]} Policies", "description": f"Only {pf[0]}/4.", "recommendation": "Add in Settings.", "severity": "high"})
    cm = re.search(r'"currency"\s*:\s*"([A-Z]{3})"', html)
    report["checks"]["currency"] = cm.group(1) if cm else "Unknown"
    apps = []
    for name, sigs in {"Klaviyo":["klaviyo"],"Judge.me":["judge.me"],"Yotpo":["yotpo"],"Loox":["loox.io"],"ReConvert":["reconvert"],"Recharge":["rechargepayments"],"Tidio":["tidio"],"Gorgias":["gorgias"],"Facebook Pixel":["connect.facebook.net","fbq("],"Google Analytics":["google-analytics.com","gtag("],"TikTok Pixel":["analytics.tiktok.com"]}.items():
        for s in sigs:
            if s in html.lower(): apps.append(name); break
    report["checks"]["detected_apps"] = apps
    ha = any('Pixel' in a or 'Analytics' in a for a in apps)
    if not ha: report["issues"].append({"title": "No Tracking Pixel", "description": "No pixel.", "recommendation": "Install tracking.", "severity": "high"})
    payments = []
    html_low = html.lower()
    payment_sigs = {"PayPal": ["paypal.com/sdk", "paypal-button", "paypalobjects"],"Stripe": ["js.stripe.com", "stripe.com/v3"],"Klarna": ["klarna.com", "klarna-checkout"],"Afterpay": ["afterpay.com", "afterpay"],"Apple Pay": ["apple-pay", "applepay"],"Google Pay": ["google-pay", "googlepay"],"Shop Pay": ["shop-pay", "shop_pay", "shoppay"],"Amazon Pay": ["amazonpay", "amazon-pay"],"Affirm": ["affirm.com", "affirm-"],"Zip": ["zip.co", "zip-payments"]}
    for name, sigs in payment_sigs.items():
        for s in sigs:
            if s in html_low: payments.append(name); break
    report["checks"]["payment_methods"] = payments
    if len(payments) >= 2: report["positives"].append(f"{len(payments)} payment options")
    elif len(payments) <= 1: report["issues"].append({"title": "Limited Payment Options", "description": f"Only {len(payments)} method(s).", "recommendation": "Add PayPal, Shop Pay, Apple Pay.", "severity": "medium"})
    review_apps = []
    for name, sigs in {"Judge.me":["judge.me","judgeme"],"Loox":["loox.io"],"Yotpo":["yotpo"],"Okendo":["okendo"],"Stamped":["stamped.io"],"Reviews.io":["reviews.io"],"Trustpilot":["trustpilot"]}.items():
        for s in sigs:
            if s in html_low: review_apps.append(name); break
    report["checks"]["review_apps"] = review_apps
    if review_apps: report["positives"].append(f"Reviews: {', '.join(review_apps)}")
    else: report["issues"].append({"title": "No Reviews App", "description": "No review system.", "recommendation": "Install Judge.me (free) or Loox.", "severity": "high"})
    has_free_shipping_banner = any(x in html_low for x in ['free shipping', 'free delivery', 'shipping on us'])
    report["checks"]["free_shipping_advertised"] = has_free_shipping_banner
    if has_free_shipping_banner: report["positives"].append("Free shipping advertised")
    else: report["issues"].append({"title": "No Free Shipping Banner", "description": "Top buyer priority.", "recommendation": "Add $50+ free shipping threshold.", "severity": "medium"})
    is_drawer_cart = any(x in html_low for x in ['cart-drawer', 'cart__drawer', 'drawer__cart', 'cart-notification'])
    is_page_cart = '/cart' in html_low and not is_drawer_cart
    report["checks"]["cart_type"] = "drawer" if is_drawer_cart else ("page" if is_page_cart else "unknown")
    if is_drawer_cart: report["positives"].append("Modern drawer cart")
    elif is_page_cart: report["issues"].append({"title": "Page-Based Cart", "description": "Cart opens as page.", "recommendation": "Switch to drawer cart.", "severity": "medium"})
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', html, re.IGNORECASE | re.DOTALL)
    page_title = title_match.group(1).strip() if title_match else ""
    page_desc = desc_match.group(1).strip() if desc_match else ""
    report["checks"]["meta_title_length"] = len(page_title)
    report["checks"]["meta_description_length"] = len(page_desc)
    if len(page_title) == 0: report["issues"].append({"title": "Missing Page Title", "description": "No title tag.", "recommendation": "Add SEO title.", "severity": "high"})
    elif len(page_title) > 70: report["issues"].append({"title": "Meta Title Too Long", "description": f"{len(page_title)} chars.", "recommendation": "50-60 chars.", "severity": "low"})
    if len(page_desc) == 0: report["issues"].append({"title": "Missing Meta Description", "description": "No description.", "recommendation": "Add 150-160 chars.", "severity": "medium"})
    elif len(page_desc) > 170: report["issues"].append({"title": "Meta Description Too Long", "description": f"{len(page_desc)} chars.", "recommendation": "Under 160 chars.", "severity": "low"})
    age_months = None
    try:
        import whois
        w = whois.whois(raw)
        cd = w.creation_date
        if isinstance(cd, list): cd = cd[0]
        if cd:
            delta = datetime.now() - cd
            age_months = int(delta.days / 30)
    except: pass
    report["checks"]["store_age_months"] = age_months
    if age_months is not None:
        if age_months < 6: report["checks"]["store_age_label"] = f"{age_months} months (new)"
        elif age_months < 12: report["checks"]["store_age_label"] = f"{age_months} months"
        else:
            years = age_months // 12
            report["checks"]["store_age_label"] = f"{years} year{'s' if years > 1 else ''}"
    trust = 0
    if he or hp: trust += 20
    trust += int((pf[0]/4)*30)
    if len(socials) >= 2: trust += 15
    elif len(socials) == 1: trust += 8
    if is_shop: trust += 10
    if review_apps: trust += 15
    if len(payments) >= 2: trust += 10
    report["scores"]["trust_score"] = min(trust, 100)
    tech = 0
    if report["checks"].get("https"): tech += 25
    if report["checks"].get("http_status") == 200: tech += 15
    if hv: tech += 20
    lt = report["checks"].get("load_time_seconds", 5)
    if lt < 1.5: tech += 20
    elif lt < 3: tech += 12
    elif lt < 5: tech += 5
    if is_drawer_cart: tech += 10
    if report["checks"].get("max_image_kb") and report["checks"]["max_image_kb"] < 500: tech += 10
    report["scores"]["technical_score"] = min(tech, 100)
    mkt = 0
    mkt += min(len(apps)*6, 30)
    if len(socials) >= 3: mkt += 20
    elif len(socials) >= 1: mkt += 10
    pc = report["checks"].get("product_count") or 0
    if pc >= 10: mkt += 15
    elif pc >= 5: mkt += 8
    if ha: mkt += 15
    if has_free_shipping_banner: mkt += 10
    if len(payments) >= 3: mkt += 10
    report["scores"]["marketing_score"] = min(mkt, 100)
    report["scores"]["overall_score"] = int((report["scores"]["trust_score"] + report["scores"]["technical_score"] + report["scores"]["marketing_score"]) / 3)
    return report

# ==========================================
# EMAIL GENERATOR
# ==========================================
def generate_outreach_email(report, tone='friendly', sender_name=''):
    domain = report.get('domain', '')
    brand = domain.split('.')[0].title() if domain else 'there'
    issues = report.get('issues', [])
    scores = report.get('scores', {})
    checks = report.get('checks', {})
    overall = scores.get('overall_score', 0)
    priority = {'high': 0, 'medium': 1, 'low': 2}
    sorted_issues = sorted(issues, key=lambda x: priority.get(x.get('severity', 'low'), 3))
    top_issues = sorted_issues[:3]
    issue_bullets = []
    for i in top_issues:
        title = i.get('title', '')
        if 'Product' in title and checks.get('product_count'):
            title = f"Only {checks['product_count']} products listed"
        elif 'Load Time' in title and checks.get('load_time_seconds'):
            title = f"Slow load time ({checks['load_time_seconds']}s)"
        issue_bullets.append(title)
    if overall < 50: subject = f"Found {len(issues)} issues on {domain}"
    elif overall < 75: subject = f"Quick idea for {domain}"
    else: subject = f"Nice store! One thing I noticed on {domain}"
    if tone == 'friendly':
        greeting = f"Hi {brand} team,"
        opener = f"I was looking at {domain} today and noticed a few things that could be costing you sales."
        closer = "Want me to send over a quick 2-min video showing how to fix these?"
        signoff = "No pitch — just thought it was worth sharing."
    elif tone == 'professional':
        greeting = f"Hello {brand} team,"
        opener = f"I recently analyzed {domain} and identified {len(issues)} optimization opportunities."
        closer = "Would it be worth a 15-minute call this week to discuss?"
        signoff = "I help Shopify stores improve conversion. Happy to walk you through it."
    else:
        greeting = f"Hey {brand},"
        opener = f"Took a look at {domain} — cool store! Noticed a few things though."
        closer = "Want me to send a quick checklist of fixes?"
        signoff = "No pressure either way!"
    body = f"""{greeting}

{opener}

Top 3 issues I found:

"""
    for b in issue_bullets:
        body += f"• {b}\n"
    signature = sender_name.strip() if sender_name and sender_name.strip() else "[Your name]"
    body += f"\nOverall score: {overall}/100. Most are fixable in a day or two.\n\n{closer}\n\n{signoff}\n\nBest regards,\n{signature}"
    return {'subject': subject, 'body': body, 'tone': tone}

# ==========================================
# NAVBAR
# ==========================================
NAVBAR = '''
<style>
.navbar{position:fixed;top:0;left:0;right:0;height:56px;background:#1f2937;color:white;display:flex;align-items:center;padding:0 16px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.2)}
.navbar-title{font-size:18px;font-weight:bold;margin-left:12px}
.hamburger{background:none;border:none;color:white;font-size:24px;cursor:pointer;padding:4px 10px}
.drawer{position:fixed;top:0;left:-280px;width:280px;height:100vh;background:#111827;color:white;transition:left 0.3s ease;z-index:10000;padding-top:20px;overflow-y:auto}
.drawer.open{left:0}
.drawer-header{padding:16px 20px;font-size:18px;font-weight:bold;border-bottom:1px solid #374151;display:flex;justify-content:space-between;align-items:center}
.drawer-close{background:none;border:none;color:white;font-size:24px;cursor:pointer}
.drawer a{display:block;padding:16px 20px;color:white;text-decoration:none;border-bottom:1px solid #1f2937;font-size:16px}
.drawer a:hover{background:#1f2937}
.drawer-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:9998;display:none}
.drawer-overlay.show{display:block}
.page-content{padding-top:70px}
</style>
<div class="navbar">
<button class="hamburger" onclick="toggleDrawer()">☰</button>
<span class="navbar-title">Zegseg Shopify Tools</span>
</div>
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
<div class="drawer-header"><span>📧 Menu</span><button class="drawer-close" onclick="toggleDrawer()">×</button></div>
<a href="/" onclick="closeDrawer()">🔍 Email Finder</a>
<a href="/discover" onclick="closeDrawer()">🎯 Store Discovery</a>
<a href="/verify" onclick="closeDrawer()">✅ Verify Emails</a>
<a href="/scout" onclick="closeDrawer()">📨 Email Scout</a>
<a href="/audit" onclick="closeDrawer()">🚀 Analyze & Send</a>
<a href="/settings" onclick="closeDrawer()">⚙️ Settings</a>
<hr style="border-color:#374151;margin:20px 0">
<a href="/logout" onclick="closeDrawer()" style="color:#ef4444">🚪 Logout</a>
</div>
<script>
function toggleDrawer(){document.getElementById('drawer').classList.toggle('open');document.getElementById('drawerOverlay').classList.toggle('show')}
function closeDrawer(){document.getElementById('drawer').classList.remove('open');document.getElementById('drawerOverlay').classList.remove('show')}
</script>
'''

def render_page(title, body):
    return f'<!DOCTYPE html><html><head><title>{title}</title><meta name="viewport" content="width=device-width,initial-scale=1">{NAVBAR}</head><body style="margin:0;font-family:Arial"><div class="page-content">{body}</div></body></html>'

# ==========================================
# AUTH
# ==========================================
SIGNUP_HTML = '''<!DOCTYPE html><html><head><title>Sign Up</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}.box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.3);width:100%;max-width:400px}h2{text-align:center}input{width:100%;padding:12px;margin:8px 0;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box}button{width:100%;padding:12px;background:#667eea;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px}.error{color:#721c24;background:#f8d7da;padding:10px;border-radius:5px;margin-bottom:15px}.link{text-align:center;margin-top:15px}.link a{color:#667eea}</style></head><body>
<div class="box"><h2>📧 Sign Up</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="text" name="sender_name" placeholder="Your name (for emails)" required><input type="password" name="password" placeholder="Password (min 6)" required minlength="6"><button>Sign Up</button></form>
<div class="link">Have account? <a href="/login">Log in</a></div></div></body></html>'''

LOGIN_HTML = '''<!DOCTYPE html><html><head><title>Login</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}.box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.3);width:100%;max-width:400px}h2{text-align:center}input{width:100%;padding:12px;margin:8px 0;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box}button{width:100%;padding:12px;background:#667eea;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px}.error{color:#721c24;background:#f8d7da;padding:10px;border-radius:5px;margin-bottom:15px}.link{text-align:center;margin-top:15px}.link a{color:#667eea}</style></head><body>
<div class="box"><h2>📧 Login</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button>Log In</button></form>
<div class="link">No account? <a href="/signup">Sign up</a></div></div></body></html>'''

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        sender_name = request.form.get('sender_name', '').strip()
        if not email or not password: return render_template_string(SIGNUP_HTML, error="Fill all fields")
        conn = get_db()
        if not conn: return render_template_string(SIGNUP_HTML, error="DB not available")
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password_hash, sender_name) VALUES (%s, %s, %s)", (email, hash_password(password), sender_name))
            conn.commit(); cur.close()
            session['user_id'] = email
            return redirect('/')
        except psycopg2.errors.UniqueViolation:
            return render_template_string(SIGNUP_HTML, error="Email exists")
        except Exception as e:
            return render_template_string(SIGNUP_HTML, error=f"Error: {e}")
        finally: release_db(conn)
    return render_template_string(SIGNUP_HTML, error=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        conn = get_db()
        if not conn: return render_template_string(LOGIN_HTML, error="DB not available")
        try:
            cur = conn.cursor()
            cur.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
            row = cur.fetchone(); cur.close()
            if row and row[0] == hash_password(password):
                session['user_id'] = email
                return redirect('/')
            return render_template_string(LOGIN_HTML, error="Invalid credentials")
        except Exception as e:
            return render_template_string(LOGIN_HTML, error=f"Error: {e}")
        finally: release_db(conn)
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
def logout():
    session.clear(); return redirect('/login')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_email = session.get('user_id')
    msg = ''
    if request.method == 'POST':
        name = request.form.get('sender_name', '').strip()
        set_user_sender_name(user_email, name)
        msg = '✅ Saved!'
    current_name = get_user_sender_name(user_email)
    body = f'''<div style="max-width:600px;margin:20px auto;padding:20px">
<div style="background:#1f2937;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">⚙️ Settings</h1></div>
<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
<h3 style="margin-top:0">Your Name</h3>
<form method="POST">
<input type="text" name="sender_name" placeholder="e.g. Daniel Phillips" value="{current_name}" style="width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box;margin-bottom:10px">
<button type="submit" style="background:#0d9488;color:white;padding:12px 30px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%">Save</button>
</form>
{f'<p style="color:green;margin-top:10px">{msg}</p>' if msg else ''}
</div></div>'''
    return render_page("Settings", body)

# ==========================================
# HOME (Email Finder) — with View/Hide toggle
# ==========================================
@app.route('/')
@login_required
def home():
    preload = request.args.get('url', '')
    body = '''<div style="max-width:700px;margin:20px auto;padding:20px">
<div style="background:white;padding:30px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1);margin-bottom:20px">
<h2 style="color:#333;margin-top:0">🔍 Email Finder</h2>
<p style="color:#666">Paste up to <b>100 store URLs</b> (one per line).</p>
<textarea id="urls" style="width:100%;height:180px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;box-sizing:border-box" placeholder="deluxura.shop&#10;hipchik.com">''' + preload.replace('<','&lt;') + '''</textarea>
<button onclick="findBulkEmails()" style="background:#667eea;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">Search All URLs</button>
<div id="result" style="margin-top:20px;background:#f8f9fa;padding:15px;border-radius:8px;min-height:40px"></div>
</div>
<div style="background:white;padding:20px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
<h3 style="margin-top:0;color:#333">📋 Last 3 Results</h3>
<div id="historyList">Loading...</div>
</div>
</div>
<script>
async function findBulkEmails(){
  const input=document.getElementById('urls').value;
  const result=document.getElementById('result');
  const stores=input.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(stores.length===0){alert('Enter URL');return}
  result.innerHTML='<p style="color:#666">Searching '+stores.length+' stores...</p>';
  try{
    const res=await fetch('/bulk-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stores:stores})});
    const data=await res.json();
    if(data.success){
      let html='<h4 style="color:#155724">✅ '+data.results.length+' stores found:</h4>';
      data.results.forEach(item=>{
        html+='<div style="font-weight:bold;margin-top:15px">📦 <a href="https://'+item.store+'" target="_blank" style="color:#333;text-decoration:none">'+item.store+'</a>:</div>';
        item.emails.forEach(e=>{html+='<div style="background:white;padding:8px;margin:5px 0;border-radius:5px;border-left:4px solid #667eea;font-weight:bold;word-break:break-all">📧 '+e+'</div>'});
      });
      result.innerHTML=html;
      loadHistory();
    } else { result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No emails found</div>'; }
  }catch(e){result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e+'</div>'}
}
async function loadHistory(){
  const res=await fetch('/get-email-scans');const data=await res.json();
  const c=document.getElementById('historyList');
  if(!data.scans || data.scans.length===0){c.innerHTML='<p style="color:#666">No scans yet.</p>';return}
  let html='';
  data.scans.forEach(s=>{
    html+='<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid #667eea">';
    html+='<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">';
    html+='<div><b>'+s.count+' emails</b> from '+s.stores+' stores<br><span style="font-size:12px;color:#666">'+s.created_at+'</span></div>';
    html+='<button id="scanbtn-'+s.id+'" onclick="toggleScanView('+s.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">View</button>';
    html+='</div>';
    html+='<div id="scan-'+s.id+'" style="display:none;margin-top:10px"></div>';
    html+='</div>';
  });
  c.innerHTML=html;
}
async function toggleScanView(id){
  const c = document.getElementById('scan-'+id);
  const btn = document.getElementById('scanbtn-'+id);
  if(c.style.display === 'block'){
    c.style.display = 'none';
    btn.textContent = 'View';
    btn.style.background = '#3b82f6';
    return;
  }
  // Load if not loaded
  if(c.dataset.loaded !== '1'){
    const res=await fetch('/get-email-scan/'+id);
    const data=await res.json();
    if(!data.results || data.results.length===0){
      c.innerHTML='<p style="color:#666">No results.</p>';
    } else {
      let html='<div style="background:white;padding:10px;border-radius:6px;max-height:300px;overflow-y:auto;font-size:13px">';
      data.results.forEach(r=>{
        html+='<div style="padding:8px 0;border-bottom:1px solid #eee"><div style="font-weight:bold;margin-bottom:4px">📦 <a href="https://'+r.store+'" target="_blank" style="color:#3b82f6;text-decoration:none">'+r.store+'</a></div>';
        (r.emails||[]).forEach(e=>{html+='<div style="padding-left:16px;color:#333;word-break:break-all">📧 '+e+'</div>'});
        html+='</div>';
      });
      html+='</div>';
      c.innerHTML = html;
    }
    c.dataset.loaded = '1';
  }
  c.style.display = 'block';
  btn.textContent = 'Hide';
  btn.style.background = '#6b7280';
}
window.onload=loadHistory;
</script>'''
    return render_page("Finder", body)

# ==========================================
# STORE DISCOVERY — with View/Hide toggle
# ==========================================
@app.route('/discover')
@login_required
def discover_page():
    user_email = session.get('user_id')
    hf_offset = get_hf_offset(user_email)
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#8b5cf6;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">🎯 Store Discovery</h1></div>

<div style="background:linear-gradient(135deg,#ff7e5f,#feb47b);color:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📦 Import from Hugging Face Dataset</h3>
<p style="font-size:14px;margin:5px 0">10,000 real Shopify stores. Enter how many to import.</p>
<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px">
<input type="number" id="hfCount" value="200" min="10" max="1000" style="padding:10px;border:none;border-radius:5px;font-size:15px;width:120px;box-sizing:border-box">
<button onclick="importFromHF()" style="background:white;color:#e85d3a;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-size:15px;font-weight:bold">🔍 Import Now</button>
</div>
<div style="font-size:12px;margin-top:8px;opacity:0.9">Current offset: <span id="currentOffset">''' + str(hf_offset) + '''</span> / 10000</div>
<div id="hfStatus" style="margin-top:10px"></div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📋 Last 3 Hugging Face Imports</h3>
<div id="hfHistory">Loading...</div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">🔎 Other Discovery Methods</h3>
<button onclick="runDiscovery('shodan')" style="background:#8b5cf6;color:white;padding:10px 16px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:14px">🔍 Shodan</button>
<button onclick="runDiscovery('theme')" style="background:#ec4899;color:white;padding:10px 16px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:14px">🎨 Theme</button>
<button onclick="runDiscovery('search')" style="background:#3b82f6;color:white;padding:10px 16px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:14px">🌐 Search</button>
<button onclick="runDiscovery('related')" style="background:#f59e0b;color:white;padding:10px 16px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:14px">📚 Related</button>
<div id="discoveryStatus" style="margin-top:12px"></div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
<h3 style="margin-top:0">📋 Discovered Stores (<span id="storeCount">0</span>)</h3>
<div id="storeList">Loading...</div>
<button onclick="sendToFinder()" style="background:#667eea;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-size:14px;margin-top:10px;margin-right:8px">📧 Send All to Email Finder</button>
<button onclick="clearStores()" style="background:#ef4444;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;font-size:14px;margin-top:10px">🗑️ Clear</button>
</div>
</div>
<script>
async function importFromHF(){
  const count = parseInt(document.getElementById('hfCount').value) || 200;
  if(count < 10 || count > 1000){ alert('Enter 10-1000'); return; }
  const status = document.getElementById('hfStatus');
  status.innerHTML = '<p style="color:white">⏳ Importing '+count+' stores... (may take 30s)</p>';
  try{
    const res = await fetch('/import-from-huggingface', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({count: count})});
    const data = await res.json();
    if(data.success){
      status.innerHTML = '<p style="color:white">✅ Imported '+data.added+' (skipped '+data.skipped+') · New offset: '+data.offset_after+'</p>';
      document.getElementById('currentOffset').textContent = data.offset_after;
      loadStores(); loadHFHistory();
    } else {
      status.innerHTML = '<p style="color:white">Error: '+(data.error||'Unknown')+'</p>';
    }
  }catch(e){ status.innerHTML = '<p style="color:white">Error: '+e.message+'</p>'; }
}

async function loadHFHistory(){
  try{
    const res = await fetch('/get-hf-history');
    const data = await res.json();
    const c = document.getElementById('hfHistory');
    if(!data.history || data.history.length===0){ c.innerHTML='<p style="color:#666">No imports yet.</p>'; return; }
    let html = '';
    data.history.forEach(h=>{
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid #ff7e5f">';
      html += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">';
      html += '<div><b>'+h.added+' new stores</b> (skipped '+h.skipped+')<br><span style="font-size:12px;color:#666">'+h.created_at+' · offset now '+h.offset+'</span></div>';
      html += '<button id="hfbtn-'+h.id+'" onclick="toggleHFView('+h.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">View</button>';
      html += '</div><div id="hf-'+h.id+'" style="display:none;margin-top:10px"></div></div>';
    });
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}

async function toggleHFView(id){
  const c = document.getElementById('hf-'+id);
  const btn = document.getElementById('hfbtn-'+id);
  if(c.style.display === 'block'){
    c.style.display = 'none';
    btn.textContent = 'View';
    btn.style.background = '#3b82f6';
    return;
  }
  if(c.dataset.loaded !== '1'){
    const res = await fetch('/get-hf-import/'+id);
    const data = await res.json();
    if(!data.domains || data.domains.length===0){
      c.innerHTML='<p style="color:#666">No domains.</p>';
    } else {
      let html = '<div style="background:white;padding:10px;border-radius:6px;max-height:250px;overflow-y:auto;font-size:12px;word-break:break-all">';
      data.domains.forEach(d=>{ html += '<div style="padding:3px 0">• <a href="https://'+d+'" target="_blank" style="color:#3b82f6">'+d+'</a></div>'; });
      html += '</div>';
      c.innerHTML = html;
    }
    c.dataset.loaded = '1';
  }
  c.style.display = 'block';
  btn.textContent = 'Hide';
  btn.style.background = '#6b7280';
}

async function loadStores(){
  const res=await fetch('/get-discovered');const data=await res.json();
  document.getElementById('storeCount').textContent=data.stores.length;
  const c=document.getElementById('storeList');
  if(data.stores.length===0){c.innerHTML='<p style="color:#666">No stores yet.</p>';return}
  let html='';
  data.stores.slice(0,50).forEach(s=>{
    html+='<div style="background:#f9f9f9;padding:10px;border-radius:6px;margin:6px 0;border-left:4px solid #8b5cf6">';
    html+='<b><a href="https://'+s.domain+'" target="_blank" style="color:#3b82f6">'+s.domain+'</a></b> <span style="font-size:11px;color:#666">('+s.source+')</span></div>';
  });
  if(data.stores.length > 50){ html += '<p style="color:#666;font-size:13px">... and '+(data.stores.length-50)+' more</p>'; }
  c.innerHTML=html;
}

async function sendToFinder(){
  const res = await fetch('/get-discovered');
  const data = await res.json();
  if(!data.stores || data.stores.length===0){ alert('No stores'); return; }
  const domains = data.stores.map(s=>s.domain).slice(0,100);
  window.location.href = '/?url=' + encodeURIComponent(domains.join('\\n'));
}

async function runDiscovery(method){
  const status=document.getElementById('discoveryStatus');
  status.innerHTML='<p style="color:#666">⏳ Running '+method+'...</p>';
  try{
    const res=await fetch('/run-discovery',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method:method})});
    const data=await res.json();
    if(data.success){
      status.innerHTML='<p style="color:green">✅ Found '+data.found+' (saved: '+data.saved+')</p>';
      loadStores();
    } else { status.innerHTML='<p style="color:red">Error: '+(data.error||'Unknown')+'</p>'; }
  }catch(e){status.innerHTML='<p style="color:red">Error: '+e+'</p>'}
}

async function clearStores(){if(!confirm('Delete all discovered stores?'))return;await fetch('/clear-discovered',{method:'POST'});loadStores()}
window.onload = function(){ loadStores(); loadHFHistory(); };
</script>'''
    return render_page("Store Discovery", body)

# ==========================================
# DISCOVERY API
# ==========================================
@app.route('/import-from-huggingface', methods=['POST'])
@login_required
def import_from_hf():
    user_email = session.get('user_id')
    count = int(request.json.get('count', 200))
    if count < 10: count = 10
    if count > 1000: count = 1000
    result = do_hf_import(user_email, count)
    return jsonify(result)

@app.route('/get-hf-history')
@login_required
def get_hf_history_route():
    user_email = session.get('user_id')
    return jsonify({'history': get_hf_history(user_email)})

@app.route('/get-hf-import/<int:import_id>')
@login_required
def get_hf_import_detail_route(import_id):
    user_email = session.get('user_id')
    return jsonify({'domains': get_hf_import_detail(import_id, user_email)})

@app.route('/run-discovery', methods=['POST'])
@login_required
def run_discovery():
    user_email = session.get('user_id')
    method = request.json.get('method', 'all')
    by_method = {}; all_found = []
    try:
        if method in ['shodan', 'all']:
            r = discover_via_shodan(limit=5); by_method['shodan'] = len(r); all_found.extend(r)
        if method in ['theme', 'all']:
            r = discover_via_theme_showcase(); by_method['theme'] = len(r); all_found.extend(r)
        if method in ['search', 'all']:
            r = discover_via_search(''); by_method['search'] = len(r); all_found.extend(r)
        if method in ['related', 'all']:
            r = discover_via_related(user_email); by_method['related'] = len(r); all_found.extend(r)
        unique = {}
        for s in all_found: unique[s['domain']] = s
        found_list = list(unique.values())
        saved = save_discovered(user_email, found_list) if found_list else 0
        return jsonify({'success': True, 'found': len(found_list), 'saved': saved, 'by_method': by_method})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def discover_via_shodan(limit=5):
    discovered = []; seen_roots = set()
    for ip in SHOPIFY_IPS[:limit]:
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                for hn in r.json().get('hostnames', []):
                    root = root_domain(hn)
                    if "shopify" in root: continue
                    if '.' not in root or len(root) < 5: continue
                    if root in seen_roots: continue
                    seen_roots.add(root)
                    discovered.append({'domain': root, 'source': 'shodan'})
            elif r.status_code == 403: break
            time.sleep(1)
        except: continue
    return discovered

def discover_via_theme_showcase():
    discovered = []; seen = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for page in ["https://themes.shopify.com/themes?sort_by=most_recent","https://themes.shopify.com/themes?sort_by=popular"]:
        try:
            r = requests.get(page, headers=headers, timeout=15)
            if r.status_code == 200:
                for m in re.findall(r'https://([a-z0-9\-]+)\.myshopify\.com', r.text, re.IGNORECASE):
                    if m in seen or m in ['www','cdn','checkout','account','admin']: continue
                    seen.add(m)
                    discovered.append({'domain': f"{m}.myshopify.com", 'source': 'theme_showcase'})
        except: continue
    return discovered

def discover_via_search(keyword=''):
    discovered = []; seen_roots = set()
    try:
        query = f'"Powered by Shopify" {keyword}'.strip()
        url = f"https://html.duckduckgo.com/html/?q={requests.utils.quote(query)}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        r = requests.post(url, headers=headers, timeout=15)
        if r.status_code == 200:
            for link in re.findall(r'class="result__a" href="(.*?)"', r.text)[:30]:
                if "uddg=" in link:
                    import urllib.parse
                    parsed = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                    if 'uddg' in parsed: link = parsed['uddg'][0]
                clean = link.replace("https://", "").replace("http://", "").split("/")[0]
                root = root_domain(clean)
                if "shopify.com" in root or "duckduckgo" in root: continue
                if root in seen_roots: continue
                seen_roots.add(root)
                discovered.append({'domain': root, 'source': 'search'})
    except: pass
    return discovered

def discover_via_related(user_email):
    discovered = []; seen_roots = set()
    conn = get_db()
    if not conn: return discovered
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain FROM discovered_stores WHERE user_email = %s LIMIT 5", (user_email,))
        seeds = [r[0] for r in cur.fetchall()]; cur.close()
    finally: release_db(conn)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for seed in seeds:
        try:
            r = requests.get(f"https://{seed}", headers=headers, timeout=8)
            if r.status_code == 200:
                for ext in re.findall(r'href="https?://([a-zA-Z0-9\.\-]+)"', r.text)[:20]:
                    root = root_domain(ext)
                    if root == seed or root in seen_roots: continue
                    if any(s in root for s in ['shopify','facebook','instagram','twitter','youtube','tiktok','pinterest','google','apple']): continue
                    if '.' not in root or len(root) < 5: continue
                    seen_roots.add(root)
                    discovered.append({'domain': root, 'source': 'related'})
        except: continue
    return discovered

def save_discovered(user_email, stores):
    conn = get_db()
    if not conn: return 0
    saved = 0
    try:
        cur = conn.cursor()
        for store in stores:
            try:
                cur.execute("""INSERT INTO discovered_stores (user_email, domain, source)
                    VALUES (%s, %s, %s) ON CONFLICT (user_email, domain) DO NOTHING""",
                    (user_email, store['domain'], store.get('source', 'unknown')))
                if cur.rowcount > 0: saved += 1
            except: pass
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)
    return saved

@app.route('/get-discovered')
@login_required
def get_discovered():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'stores': []})
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain, source, discovered_at FROM discovered_stores WHERE user_email = %s ORDER BY discovered_at DESC LIMIT 500", (user_email,))
        rows = cur.fetchall(); cur.close()
        return jsonify({'stores': [{'domain': r[0], 'source': r[1], 'discovered_at': str(r[2])[:16]} for r in rows]})
    except: return jsonify({'stores': []})
    finally: release_db(conn)

@app.route('/clear-discovered', methods=['POST'])
@login_required
def clear_discovered():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM discovered_stores WHERE user_email = %s", (user_email,))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

# ==========================================
# EMAIL SCAN API
# ==========================================
@app.route('/get-email-scans')
@login_required
def get_email_scans_route():
    user_email = session.get('user_id')
    return jsonify({'scans': get_email_scans(user_email)})

@app.route('/get-email-scan/<int:scan_id>')
@login_required
def get_email_scan_detail_route(scan_id):
    user_email = session.get('user_id')
    return jsonify({'results': get_email_scan_detail(scan_id, user_email)})

# ==========================================
# VERIFY PAGE
# ==========================================
@app.route('/verify')
@login_required
def verify_page():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">✅ Verify Emails</h1></div>
<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📋 Last 3 Jobs</h3>
<div id="jobsList">Loading...</div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<textarea id="emailsInput" style="width:100%;height:180px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="loadFromFinder()" style="background:#f59e0b;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px;margin-top:8px">📥 From Finder</button>
<button onclick="startBackgroundVerify()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-top:8px">▶️ Start Verify</button>
<div id="startMsg" style="margin-top:10px"></div>
</div></div>
<script>
async function loadFromFinder(){const res=await fetch('/get-stored-emails');const data=await res.json();if(data.emails&&data.emails.length>0){document.getElementById('emailsInput').value=data.emails.join('\\n');alert('Loaded '+data.emails.length)}}
async function startBackgroundVerify(){const emails=document.getElementById('emailsInput').value.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);if(emails.length===0){alert('Enter emails');return}const name=prompt('Job name:','Job '+new Date().toLocaleString());document.getElementById('startMsg').innerHTML='<p style="color:#666">Starting...</p>';try{const res=await fetch('/verify-async',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails:emails,name:name||'Untitled'})});const data=await res.json();if(data.success){document.getElementById('startMsg').innerHTML='<p style="color:green">✅ Job #'+data.job_id+' started!</p>';document.getElementById('emailsInput').value='';refreshJobs()}}catch(e){document.getElementById('startMsg').innerHTML='<p style="color:red">Error: '+e+'</p>'}}
async function refreshJobs(){const res=await fetch('/verify-jobs');const data=await res.json();const container=document.getElementById('jobsList');if(!data.jobs||data.jobs.length===0){container.innerHTML='<p style="color:#666">No jobs yet.</p>';return}let html='';data.jobs.forEach(job=>{const percent=job.total>0?Math.round((job.processed/job.total)*100):0;const sc=job.status==='completed'?'#0d9488':(job.status==='running'?'#f59e0b':'#ef4444');const si=job.status==='completed'?'✅':(job.status==='running'?'🔄':'⏹️');html+='<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+sc+'"><div style="font-weight:bold">'+si+' '+job.name+'</div><div style="margin-top:8px;background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+percent+'%;height:16px;background:'+sc+';text-align:center;color:white;font-size:11px;line-height:16px">'+percent+'%</div></div><div style="font-size:13px;margin-top:6px">'+job.processed+' / '+job.total+' | ✅ '+job.valid+' | ❌ '+job.invalid+'</div></div>'});container.innerHTML=html}
window.onload=function(){refreshJobs();setInterval(refreshJobs,10000)};
</script>'''
    return render_page("Verify", body)

# ==========================================
# SCOUT
# ==========================================
@app.route('/scout')
@login_required
def scout():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#0d9488;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📨 Email Scout</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Recipients</h3>
<textarea id="emailsInput" oninput="syncRecipients()" style="width:100%;height:160px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<div id="emailCount" style="margin-top:10px;font-weight:bold">0 recipients</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">✍️ Template</h3>
<input type="text" id="subjectLine" placeholder="Subject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box">
<textarea id="messageBody" rows="5" placeholder="Message" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box"></textarea>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<button onclick="startCampaign()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px">▶️ Start</button>
<button onclick="stopCampaign()" style="background:#ef4444;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">⏹️ Stop</button>
<div id="launchStatus" style="margin-top:10px"></div>
</div></div>
<script>
let recipients=[],scoutedEmails=0,isRunning=false;
function syncRecipients(){const val=document.getElementById('emailsInput').value;recipients=val.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);document.getElementById('emailCount').textContent=recipients.length+' recipients';saveState()}
window.onload=async function(){try{const res=await fetch('/load-scout-state');const data=await res.json();
  if(data.recipients) {recipients = data.recipients;document.getElementById('emailsInput').value = recipients.join('\\n');}
  if(data.subject) document.getElementById('subjectLine').value = data.subject;
  if(data.message) document.getElementById('messageBody').value = data.message;
}catch(e){};document.getElementById('emailCount').textContent=recipients.length+' recipients';};
async function saveState(){try{await fetch('/save-scout-state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients:recipients,subject:document.getElementById('subjectLine').value,message:document.getElementById('messageBody').value,count:scoutedEmails})})}catch(e){}}
function startCampaign(){if(recipients.length===0){alert('Add recipients');return}isRunning=true;openNextEmail()}
function stopCampaign(){isRunning=false}
function openNextEmail(){if(!isRunning)return;if(scoutedEmails>=recipients.length){isRunning=false;return}const email=recipients[scoutedEmails];const subj=document.getElementById('subjectLine').value;const msg=document.getElementById('messageBody').value;const body=msg.replace('{name}','Store Owner').replace('{email}',email);window.location.href='mailto:'+email+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body);scoutedEmails++;saveState()}
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible'&&isRunning)setTimeout(openNextEmail,2000)});
</script>'''
    return render_page("Scout", body)

# ==========================================
# ANALYZE & SEND
# ==========================================
@app.route('/audit')
@login_required
def audit_page():
    user_email = session.get('user_id')
    sender_name = get_user_sender_name(user_email) or ''
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">

<div style="background:#65a30d;color:white;padding:20px;border-radius:10px;margin-bottom:20px;display:flex;align-items:center;gap:16px">
<svg width="56" height="56" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><path d="M32 4L8 14V30C8 45 19 57 32 60C45 57 56 45 56 30V14L32 4Z" fill="white" opacity="0.25" stroke="white" stroke-width="2" stroke-linejoin="round"/><path d="M22 32L29 39L43 25" stroke="white" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>
<div><h1 style="margin:0;font-size:24px">Analyze & Send</h1><p style="margin:4px 0 0 0;font-size:14px;opacity:0.9">Bulk audit + personalized outreach</p></div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📥 Import Emails</h3>
<button onclick="importFrom('finder')" style="background:#667eea;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">🔍 From Finder</button>
<button onclick="importFrom('verified')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">✅ From Verified</button>
<button onclick="toggleManual()" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">✍️ Paste Manual</button>
<div id="manualPaste" style="display:none;margin-top:10px">
<textarea id="manualEmails" placeholder="Paste emails one per line" style="width:100%;height:100px;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="addManual()" style="background:#0d9488;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin-top:5px">Add to Queue</button>
</div>
<div id="importStatus" style="margin-top:10px"></div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
<h3 style="margin:0">📋 Queue (<span id="queueCount">0</span>)</h3>
<button onclick="clearQueue()" style="background:#ef4444;color:white;padding:6px 14px;border:none;border-radius:5px;cursor:pointer;font-size:12px">🗑️ Clear Pending</button>
</div>
<div id="progressBar" style="margin-top:12px;display:none;background:#e0e0e0;border-radius:8px;overflow:hidden">
<div id="progressFill" style="height:20px;background:linear-gradient(90deg,#4ade80,#22c55e);text-align:center;color:white;font-size:12px;line-height:20px;transition:width 0.3s">0%</div>
</div>
<div id="queueList" style="margin-top:12px">Loading...</div>
</div>

<div id="modeButtons" style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">🚀 Start Processing</h3>
<div style="margin-bottom:10px">
<label style="font-weight:bold;font-size:13px">Your name:</label>
<input type="text" id="senderName" value="''' + sender_name.replace('"','') + '''" placeholder="e.g. Daniel Phillips" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;margin:5px 0;box-sizing:border-box;font-size:14px">
</div>
<button onclick="startManualMode()" style="background:#3b82f6;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;margin-right:10px;margin-bottom:10px">▶️ Start Manual</button>
<button onclick="startAutoMode()" style="background:#0d9488;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;margin-bottom:10px">⚡ Start Auto</button>
<button onclick="stopAutoMode()" id="stopBtn" style="background:#ef4444;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;display:none;margin-left:10px">⏹️ Stop Auto</button>
<div id="modeStatus" style="margin-top:10px"></div>
</div>

<div id="auditSection" style="display:none">
<div id="currentEmailLabel" style="background:#65a30d;color:white;padding:10px 16px;border-radius:8px;font-weight:bold;margin-bottom:15px"></div>
<div id="auditResult"></div>

<div id="outreachSection" style="display:none;background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-top:20px">
<h3 style="margin-top:0">✉️ Outreach Email</h3>
<div style="margin-bottom:10px">
<button onclick="regenerateEmail('friendly')" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px;margin-right:5px">😊 Friendly</button>
<button onclick="regenerateEmail('professional')" style="background:#3b82f6;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px;margin-right:5px">💼 Professional</button>
<button onclick="regenerateEmail('casual')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px">😎 Casual</button>
</div>
<div id="emailPreview" style="display:none">
<label style="font-weight:bold;font-size:13px">Subject:</label>
<input type="text" id="genSubject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin:5px 0 10px 0;box-sizing:border-box;font-size:14px">
<label style="font-weight:bold;font-size:13px">Message:</label>
<textarea id="genBody" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-top:5px;box-sizing:border-box;font-size:13px;font-family:monospace"></textarea>
<button onclick="sendToScoutAndOpen()" style="background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px;margin-right:8px">📨 Send to Scout & Open Gmail</button>
<button onclick="skipCurrent()" style="background:#6b7280;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px">⏭️ Skip</button>
<div id="actionStatus" style="font-size:13px;color:green;margin-top:8px"></div>
</div>
</div>
</div>

</div>
<script>
let currentItem = null;
let currentAuditReport = null;
let autoMode = false;
let autoTone = 'friendly';
let pendingAction = false;

async function loadQueue(){
  try{
    const res = await fetch('/get-audit-queue');
    const data = await res.json();
    const c = document.getElementById('queueList');
    document.getElementById('queueCount').textContent = data.items.length;
    const total = data.items.length;
    const done = data.items.filter(i=>i.status==='done'||i.status==='skipped').length;
    if(total > 0){
      document.getElementById('progressBar').style.display='block';
      const pct = Math.round((done/total)*100);
      document.getElementById('progressFill').style.width = pct + '%';
      document.getElementById('progressFill').textContent = pct + '% (' + done + '/' + total + ')';
    }
    if(total === 0){ c.innerHTML='<p style="color:#666">Queue empty. Import emails above.</p>'; return; }
    let html='';
    data.items.forEach(i=>{
      let icon = '⏳'; let color = '#f59e0b';
      if(i.status==='done'){ icon='✅'; color='#16a34a'; }
      else if(i.status==='current'){ icon='▶️'; color='#3b82f6'; }
      else if(i.status==='skipped'){ icon='⏭️'; color='#6b7280'; }
      html += '<div style="background:#f9f9f9;padding:10px;border-radius:6px;margin:6px 0;border-left:4px solid '+color+';display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">';
      html += '<div style="font-size:14px"><span style="margin-right:8px">'+icon+'</span><b>'+i.email+'</b><br><span style="color:#666;font-size:12px">'+i.domain+'</span></div>';
      html += '<div style="display:flex;gap:6px">';
      if(i.status === 'pending' || i.status === 'current'){
        html += '<button onclick="analyzeItem('+i.id+')" style="background:#3b82f6;color:white;padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:12px">Analyze</button>';
        html += '<button onclick="skipItem('+i.id+')" style="background:#6b7280;color:white;padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:12px">Skip</button>';
      } else {
        html += '<button onclick="resetItem('+i.id+')" style="background:#f59e0b;color:white;padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:12px">Undo</button>';
      }
      html += '</div></div>';
    });
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}

async function importFrom(source){
  const status = document.getElementById('importStatus');
  status.innerHTML = '<p style="color:#666">⏳ Importing...</p>';
  try{
    const res = await fetch('/import-to-queue', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({source: source})});
    const data = await res.json();
    if(data.success){
      status.innerHTML = '<p style="color:green">✅ Added '+data.added+' (skipped '+data.skipped+')</p>';
      loadQueue();
    } else { status.innerHTML = '<p style="color:red">Error: '+(data.error||'Unknown')+'</p>'; }
  }catch(e){ status.innerHTML = '<p style="color:red">Error: '+e.message+'</p>'; }
}

function toggleManual(){ const el = document.getElementById('manualPaste'); el.style.display = el.style.display === 'none' ? 'block' : 'none'; }
async function addManual(){
  const text = document.getElementById('manualEmails').value;
  const emails = text.split('\\n').map(s=>s.trim()).filter(s=>s.includes('@'));
  if(emails.length === 0){ alert('No valid emails'); return; }
  const res = await fetch('/add-to-queue', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails: emails})});
  const data = await res.json();
  if(data.success){
    document.getElementById('importStatus').innerHTML = '<p style="color:green">✅ Added '+data.added+' (skipped '+data.skipped+')</p>';
    document.getElementById('manualEmails').value='';
    loadQueue();
  }
}
async function clearQueue(){ if(!confirm('Clear all pending items?')) return; await fetch('/clear-queue', {method:'POST'}); loadQueue(); }
async function skipItem(id){ await fetch('/update-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id, status:'skipped'})}); loadQueue(); if(autoMode) nextAuto(); }
async function resetItem(id){ await fetch('/update-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id, status:'pending'})}); loadQueue(); }

async function analyzeItem(id){
  document.getElementById('auditSection').style.display = 'block';
  document.getElementById('auditResult').innerHTML = '<p style="color:#666;padding:20px;text-align:center">⏳ Running audit... 30-45 seconds</p>';
  document.getElementById('outreachSection').style.display = 'none';
  document.getElementById('currentEmailLabel').textContent = '🔍 Loading...';
  await fetch('/update-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id, status:'current'})});
  try{
    const res = await fetch('/analyze-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    const data = await res.json();
    if(data.success){
      currentItem = data.item;
      currentAuditReport = data.item.report;
      document.getElementById('currentEmailLabel').textContent = '📧 ' + currentItem.email + '  →  ' + currentItem.domain;
      renderReport(data.item.report);
      document.getElementById('outreachSection').style.display = 'block';
      await generateEmail(autoTone);
      loadQueue();
      if(autoMode && !pendingAction){
        pendingAction = true;
        setTimeout(async()=>{ pendingAction = false; await autoSend(); }, 1500);
      }
    } else {
      document.getElementById('auditResult').innerHTML = '<p style="color:red">Error: '+(data.error||'Unknown')+'</p>';
      if(autoMode) setTimeout(nextAuto, 3000);
    }
  }catch(e){
    document.getElementById('auditResult').innerHTML = '<p style="color:red">Error: '+e.message+'</p>';
    if(autoMode) setTimeout(nextAuto, 3000);
  }
}

function scoreColor(s){if(s>=75)return '#16a34a';if(s>=50)return '#f59e0b';return '#ef4444'}
function scoreBar(l,s){const c=scoreColor(s);return '<div style="margin:10px 0"><div style="display:flex;justify-content:space-between;margin-bottom:4px"><b>'+l+'</b><span style="color:'+c+';font-weight:bold">'+s+'%</span></div><div style="background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+s+'%;height:12px;background:'+c+'"></div></div></div>'}

function renderReport(r){
  const ch=r.checks||{};const sc=r.scores||{};const iss=r.issues||[];
  let h='';
  h+='<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:15px"><h2 style="margin:0">Store Audit Overview</h2><div style="color:#666;font-size:13px;margin-top:6px">Store: <a href="https://'+r.domain+'" target="_blank" style="color:#3b82f6">https://'+r.domain+'/</a></div>'+(r.case_id?'<div style="background:#f3f4f6;padding:6px 12px;border-radius:6px;font-size:13px;color:#374151;margin-top:8px;display:inline-block">Case ID: <b>'+r.case_id+'</b></div>':'')+'</div>';
  h+='<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:15px"><h3 style="margin-top:0">📈 Scores</h3>'+scoreBar('Overall',sc.overall_score||0)+scoreBar('Trust',sc.trust_score||0)+scoreBar('Technical',sc.technical_score||0)+scoreBar('Marketing',sc.marketing_score||0)+'</div>';
  const hi=iss.filter(i=>i.severity==='high');
  if(hi.length>0)h+='<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:15px;border-radius:8px;margin-bottom:15px"><div style="color:#991b1b;font-weight:bold">⚠️ '+hi.length+' critical issue(s)</div></div>';
  if(iss.length>0){h+='<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:15px"><h3 style="margin-top:0;color:#991b1b">⚠️ Issues ('+iss.length+')</h3>';iss.forEach(i=>{const c=i.severity==='high'?'#ef4444':(i.severity==='medium'?'#f59e0b':'#6b7280');h+='<div style="background:#fef2f2;border-left:4px solid '+c+';padding:12px;border-radius:6px;margin:8px 0"><div style="font-weight:bold;font-size:14px">⚠️ '+i.title+'</div><div style="color:#374151;font-size:13px;margin:4px 0">'+i.description+'</div><div style="background:#fef3c7;padding:8px;border-radius:5px;font-size:12px;color:#78350f"><b>💡</b> '+i.recommendation+'</div></div>'});h+='</div>'}
  if(r.positives&&r.positives.length>0){h+='<div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:12px;border-radius:6px;margin-bottom:15px"><b style="color:#166534">✅ Works Well</b>';r.positives.forEach(p=>{h+='<div style="margin:4px 0;color:#14532d;font-size:13px">✅ '+p+'</div>'});h+='</div>'}
  document.getElementById('auditResult').innerHTML=h;
}

async function generateEmail(tone){
  if(!currentAuditReport){ return; }
  const senderName = document.getElementById('senderName').value.trim();
  try{
    const res = await fetch('/generate-email', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({report: currentAuditReport, tone: tone, sender_name: senderName})});
    const data = await res.json();
    if(data.success){
      document.getElementById('genSubject').value = data.subject;
      document.getElementById('genBody').value = data.body;
      document.getElementById('emailPreview').style.display = 'block';
      if(senderName){
        fetch('/save-sender-name',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sender_name:senderName})});
      }
    }
  }catch(e){ console.error(e); }
}

async function regenerateEmail(tone){ autoTone = tone; await generateEmail(tone); }

async function sendToScoutAndOpen(){
  if(!currentItem){ alert('No active item'); return; }
  const subj = document.getElementById('genSubject').value;
  const body = document.getElementById('genBody').value;
  if(!subj || !body){ alert('Generate email first'); return; }
  await fetch('/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, subject:subj, message:body})});
  await fetch('/save-scout-recipients', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients: [currentItem.email]})});
  await fetch('/save-scout-state', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients: [currentItem.email], subject:subj, message:body, count:0})});
  await fetch('/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, status:'done'})});
  await fetch('/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({email: currentItem.email})});
  const mailto = 'mailto:' + currentItem.email + '?subject=' + encodeURIComponent(subj) + '&body=' + encodeURIComponent(body);
  window.location.href = mailto;
}

async function skipCurrent(){
  if(!currentItem){ return; }
  await fetch('/update-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, status:'skipped'})});
  currentItem = null;
  document.getElementById('auditSection').style.display = 'none';
  loadQueue();
  if(autoMode) nextAuto();
}

async function startManualMode(){
  autoMode = false;
  document.getElementById('modeStatus').innerHTML = '<p style="color:blue">▶️ Manual mode: click each email to analyze</p>';
  document.getElementById('stopBtn').style.display = 'none';
}

async function startAutoMode(){
  const tone = prompt('Choose tone:\\n1 = Friendly\\n2 = Professional\\n3 = Casual\\n\\nEnter 1, 2, or 3 (default 1)', '1');
  if(tone === '2') autoTone = 'professional';
  else if(tone === '3') autoTone = 'casual';
  else autoTone = 'friendly';
  autoMode = true;
  document.getElementById('modeStatus').innerHTML = '<p style="color:green">⚡ Auto mode ON ('+autoTone+')</p>';
  document.getElementById('stopBtn').style.display = 'inline-block';
  nextAuto();
}

function stopAutoMode(){
  autoMode = false;
  pendingAction = false;
  document.getElementById('modeStatus').innerHTML = '<p style="color:red">⏹️ Auto mode stopped</p>';
  document.getElementById('stopBtn').style.display = 'none';
}

async function nextAuto(){
  if(!autoMode) return;
  try{
    const res = await fetch('/get-next-pending');
    const data = await res.json();
    if(data.item){
      document.getElementById('modeStatus').innerHTML = '<p style="color:green">⚡ Auto: analyzing '+data.item.email+'...</p>';
      await analyzeItem(data.item.id);
    } else {
      autoMode = false;
      document.getElementById('modeStatus').innerHTML = '<p style="color:blue">🎉 Auto complete! All emails processed.</p>';
      document.getElementById('stopBtn').style.display = 'none';
    }
  }catch(e){ console.error(e); if(autoMode) setTimeout(nextAuto, 3000); }
}

async function autoSend(){
  if(!autoMode) return;
  if(!currentItem) { nextAuto(); return; }
  const subj = document.getElementById('genSubject').value;
  const body = document.getElementById('genBody').value;
  if(!subj || !body){
    await fetch('/update-queue-item', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, status:'skipped'})});
    nextAuto();
    return;
  }
  await fetch('/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, subject:subj, message:body})});
  await fetch('/save-scout-recipients', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients: [currentItem.email]})});
  await fetch('/save-scout-state', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients: [currentItem.email], subject:subj, message:body, count:0})});
  await fetch('/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id, status:'done'})});
  await fetch('/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'},body:JSON.stringify({email: currentItem.email})});
  loadQueue();
  const mailto = 'mailto:' + currentItem.email + '?subject=' + encodeURIComponent(subj) + '&body=' + encodeURIComponent(body);
  localStorage.setItem('lastAutoSentId', currentItem.id.toString());
  window.location.href = mailto;
}

document.addEventListener('visibilitychange', function(){
  if(document.visibilityState === 'visible' && autoMode){
    const lastSent = localStorage.getItem('lastAutoSentId');
    if(lastSent){
      localStorage.removeItem('lastAutoSentId');
      currentItem = null;
      setTimeout(nextAuto, 1500);
    }
  }
});

window.onload = function(){ loadQueue(); };
</script>'''
    return render_page("Analyze & Send", body)

# ==========================================
# QUEUE API
# ==========================================
@app.route('/get-audit-queue')
@login_required
def get_audit_queue_route():
    user_email = session.get('user_id')
    return jsonify({'items': get_queue(user_email)})

@app.route('/import-to-queue', methods=['POST'])
@login_required
def import_to_queue():
    user_email = session.get('user_id')
    source = request.json.get('source', '')
    emails = []
    try:
        if source == 'finder':
            state = load_user_state(user_email)
            emails = state.get('found_emails', [])
        elif source == 'verified':
            state = load_user_state(user_email)
            emails = state.get('verified_emails', [])
            if not emails:
                conn = get_db()
                if conn:
                    try:
                        cur = conn.cursor()
                        cur.execute("SELECT valid_emails FROM verify_jobs WHERE user_email = %s AND status = 'completed' ORDER BY created_at DESC LIMIT 1", (user_email,))
                        row = cur.fetchone(); cur.close()
                        if row and row[0]: emails = row[0].split('|||')
                    except: pass
                    finally: release_db(conn)
        else:
            return jsonify({'success': False, 'error': 'Unknown source'})
        if not emails: return jsonify({'success': False, 'error': 'No emails available'})
        added, skipped = add_to_queue(user_email, emails)
        return jsonify({'success': True, 'added': added, 'skipped': skipped})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/add-to-queue', methods=['POST'])
@login_required
def add_to_queue_route():
    user_email = session.get('user_id')
    emails = request.json.get('emails', [])
    added, skipped = add_to_queue(user_email, emails)
    return jsonify({'success': True, 'added': added, 'skipped': skipped})

@app.route('/update-queue-item', methods=['POST'])
@login_required
def update_queue_item_route():
    user_email = session.get('user_id')
    data = request.json
    item_id = data.pop('id', None)
    if not item_id: return jsonify({'success': False, 'error': 'No id'})
    update_queue_item(item_id, user_email, **data)
    return jsonify({'success': True})

@app.route('/mark-sent', methods=['POST'])
@login_required
def mark_sent_route():
    user_email = session.get('user_id')
    email = request.json.get('email', '')
    if email: mark_sent(user_email, email)
    return jsonify({'success': True})

@app.route('/clear-queue', methods=['POST'])
@login_required
def clear_queue_route():
    user_email = session.get('user_id')
    n = clear_queue(user_email, only_pending=True)
    return jsonify({'success': True, 'cleared': n})

@app.route('/get-next-pending')
@login_required
def get_next_pending_route():
    user_email = session.get('user_id')
    item = get_next_pending_item(user_email)
    return jsonify({'item': item})

@app.route('/analyze-queue-item', methods=['POST'])
@login_required
def analyze_queue_item():
    user_email = session.get('user_id')
    item_id = request.json.get('id')
    item = get_queue_item(item_id, user_email)
    if not item: return jsonify({'success': False, 'error': 'Item not found'})
    if item.get('report'):
        return jsonify({'success': True, 'item': item})
    case_id = generate_case_id()
    report = audit_store(item['domain'], case_id)
    update_queue_item(item_id, user_email, report=report, status='current')
    save_audit_history(user_email, item['domain'], report)
    item = get_queue_item(item_id, user_email)
    return jsonify({'success': True, 'item': item})

@app.route('/save-sender-name', methods=['POST'])
@login_required
def save_sender_name():
    user_email = session.get('user_id')
    name = request.json.get('sender_name', '').strip()
    if user_email and name:
        set_user_sender_name(user_email, name)
    return jsonify({'success': True})

@app.route('/generate-email', methods=['POST'])
@login_required
def generate_email_route():
    data = request.json
    report = data.get('report', {})
    tone = data.get('tone', 'friendly')
    sender_name = data.get('sender_name', '').strip()
    if not sender_name:
        sender_name = get_user_sender_name(session.get('user_id')) or ''
    if not report: return jsonify({'success': False, 'error': 'No report'})
    try:
        result = generate_outreach_email(report, tone, sender_name)
        return jsonify({'success': True, 'subject': result['subject'], 'body': result['body']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/verify-async', methods=['POST'])
@login_required
def verify_async():
    user_email = session.get('user_id')
    data = request.json
    emails = data.get('emails', [])
    job_name = data.get('name', f"Job {int(time.time())}")
    if not emails: return jsonify({'error': 'No emails'}), 400
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO verify_jobs (user_email, job_name, total, remaining_emails, valid_emails, invalid_emails, status)
            VALUES (%s, %s, %s, %s, '', '', 'pending') RETURNING id""", (user_email, job_name, len(emails), '|||'.join(emails)))
        job_id = cur.fetchone()[0]
        conn.commit(); cur.close()
    finally: release_db(conn)
    thread = threading.Thread(target=background_verify_worker, args=(job_id,), daemon=True)
    thread.start()
    return jsonify({'success': True, 'job_id': job_id, 'total': len(emails)})

@app.route('/verify-jobs')
@login_required
def verify_jobs_list():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'jobs': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, job_name, total, processed, status, created_at, valid_emails, invalid_emails FROM verify_jobs WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (user_email,))
        rows = cur.fetchall(); cur.close()
        return jsonify({'jobs': [{'id': r[0], 'name': r[1], 'total': r[2], 'processed': r[3], 'status': r[4], 'created_at': str(r[5]), 'valid': len(r[6].split('|||')) if r[6] else 0, 'invalid': len(r[7].split('|||')) if r[7] else 0} for r in rows]})
    finally: release_db(conn)

@app.route('/bulk-email', methods=['POST'])
@login_required
def bulk_email():
    stores = request.json.get('stores', [])[:100]
    results = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(find_emails, s.strip()): s for s in stores if '.' in s}
        for f in as_completed(futures):
            try:
                emails = f.result()
                if emails: results.append({'store': futures[f], 'emails': emails})
            except: continue
    user_email = session.get('user_id')
    all_found = []
    for r in results: all_found.extend(r['emails'])
    if user_email:
        save_user_state(user_email, found_emails='|||'.join(all_found))
        save_email_scan(user_email, results, len(results))
    return jsonify({'success': bool(results), 'results': results})

@app.route('/get-stored-emails')
@login_required
def get_stored_emails():
    user_email = session.get('user_id')
    state = load_user_state(user_email) if user_email else {}
    return jsonify({'emails': state.get('found_emails', [])})

@app.route('/save-scout-recipients', methods=['POST'])
@login_required
def save_scout_recipients():
    user_email = session.get('user_id')
    recipients = request.json.get('recipients', [])
    if user_email: save_user_state(user_email, scout_recipients='|||'.join(recipients))
    return jsonify({'success': True})

@app.route('/load-scout-state')
@login_required
def load_scout_state():
    user_email = session.get('user_id')
    state = load_user_state(user_email) if user_email else {}
    return jsonify({'recipients': state.get('scout_recipients', []), 'subject': state.get('scout_subject', ''), 'message': state.get('scout_message', ''), 'count': state.get('scout_count', 0)})

@app.route('/save-scout-state', methods=['POST'])
@login_required
def save_scout_state_route():
    user_email = session.get('user_id')
    data = request.json
    if user_email:
        save_user_state(user_email, scout_recipients='|||'.join(data.get('recipients', [])), scout_subject=data.get('subject', ''), scout_message=data.get('message', ''), scout_count=data.get('count', 0))
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
