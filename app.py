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

MAX_WORKERS = 10
DEFAULT_SEND_LIMIT = 70

PUBLIC_EMAIL_DOMAINS = {
    'gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com',
    'live.com','msn.com','protonmail.com','proton.me','mail.com','yandex.com',
    'zoho.com','gmx.com','gmx.net','me.com','mac.com','qq.com','163.com'
}

PLACEHOLDER_DOMAINS = {
    'yourstore.com','example.com','example.org','example.net','domain.com',
    'yoursite.com','mysite.com','sitename.com','site.com','test.com',
    'mystore.com','store.com','shop.com','company.com','website.com'
}

WIX_CATEGORIES = ["fashion", "jewelry", "toys", "home-decor", "beauty", "food", "accessories", "gifts"]
CC_INDEXES = ["CC-MAIN-2024-44", "CC-MAIN-2024-40", "CC-MAIN-2024-33", "CC-MAIN-2024-26", "CC-MAIN-2024-18", "CC-MAIN-2024-10"]
WIX_STORE_PATTERNS = ["*/product-page/*", "*/shop/*", "*/store/*"]
WIX_STORE_SIGNALS = ['wixstores','wix-ecom','product-page','add-to-cart','add_to_cart','shopping-cart','wixstore','wixstorefront']

# ==========================================
# DB POOL
# ==========================================
_db_pool = None

def init_pool():
    global _db_pool
    if not DATABASE_URL: return
    try:
        _db_pool = pool.SimpleConnectionPool(1, 5, DATABASE_URL, sslmode='require')
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
            session_sent_count INTEGER DEFAULT 0,
            session_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            send_limit INTEGER DEFAULT 70,
            wix_found_emails TEXT, wix_verified_emails TEXT,
            wix_scout_recipients TEXT, wix_scout_subject TEXT, wix_scout_message TEXT,
            wix_session_sent_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        for col in ['session_sent_count INTEGER DEFAULT 0','session_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP','send_limit INTEGER DEFAULT 70','wix_found_emails TEXT','wix_verified_emails TEXT','wix_scout_recipients TEXT','wix_scout_subject TEXT','wix_scout_message TEXT','wix_session_sent_count INTEGER DEFAULT 0']:
            try: cur.execute(f"ALTER TABLE user_state ADD COLUMN IF NOT EXISTS {col}")
            except: pass
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
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_stores (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL, source VARCHAR(50),
            country VARCHAR(10),
            has_email BOOLEAN DEFAULT FALSE,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, domain))""")
        try: cur.execute("ALTER TABLE wix_stores ADD COLUMN IF NOT EXISTS country VARCHAR(10)")
        except: pass
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_discovery_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            category VARCHAR(100),
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            found INTEGER DEFAULT 0, saved INTEGER DEFAULT 0,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
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
        cur.execute("""CREATE TABLE IF NOT EXISTS email_finder_master (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            emails_found INTEGER DEFAULT 0,
            status VARCHAR(50) DEFAULT 'running',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS email_finder_subjobs (
            id SERIAL PRIMARY KEY, master_id INTEGER,
            user_email VARCHAR(255) NOT NULL,
            sub_index INTEGER DEFAULT 0,
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            emails_found INTEGER DEFAULT 0,
            remaining_urls TEXT, results TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS hf_imports (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            requested INTEGER DEFAULT 0, added INTEGER DEFAULT 0, skipped INTEGER DEFAULT 0,
            offset_before INTEGER DEFAULT 0, offset_after INTEGER DEFAULT 0,
            domains TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS email_finder_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            emails_found INTEGER DEFAULT 0, stores_with_email INTEGER DEFAULT 0,
            results TEXT, remaining_urls TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS store_catalogues (
            id SERIAL PRIMARY KEY, domain VARCHAR(255) UNIQUE NOT NULL,
            product_count INTEGER DEFAULT 0, categories TEXT, vendors TEXT, tags TEXT,
            sold_out_count INTEGER DEFAULT 0, bestsellers TEXT,
            crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_warehouse (
            id BIGSERIAL PRIMARY KEY, url TEXT UNIQUE NOT NULL, domain TEXT NOT NULL,
            source TEXT, title TEXT, country TEXT,
            status TEXT DEFAULT 'pending',
            seo_score INTEGER, tech_spend INTEGER, crawled_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(), verified_at TIMESTAMPTZ,
            audited_at TIMESTAMPTZ, notes TEXT)""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wix_warehouse_status ON wix_warehouse(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wix_warehouse_created ON wix_warehouse(created_at DESC)")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_email_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0, emails_found INTEGER DEFAULT 0,
            status VARCHAR(50) DEFAULT 'pending', remaining_urls TEXT, results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_verify_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            job_name VARCHAR(255), total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            valid_emails TEXT, invalid_emails TEXT, remaining_emails TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_audit_queue (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL, domain VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending', report JSONB, subject TEXT, message TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, email))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_sent_log (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL, sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, email))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_audit_history (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            domain VARCHAR(255) NOT NULL, report JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.commit(); cur.close()
        print("✅ DB ready")
    except Exception as e: print(f"❌ DB: {e}")
    finally: release_db(conn)

try:
    init_pool(); init_db()
except: pass

def reset_stuck_current_items():
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("UPDATE audit_queue SET status='pending', updated_at=NOW() WHERE status='current'")
        cur.execute("UPDATE wix_audit_queue SET status='pending', updated_at=NOW() WHERE status='current'")
        conn.commit(); cur.close()
    except Exception as e: print(f"⚠️ reset_stuck: {e}")
    finally: release_db(conn)

try: reset_stuck_current_items()
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
        cur.execute("""SELECT found_emails, verified_emails, scout_recipients, scout_subject, scout_message, scout_count,
            wix_found_emails, wix_verified_emails, wix_scout_recipients, wix_scout_subject, wix_scout_message, wix_session_sent_count
            FROM user_state WHERE user_email = %s""", (user_email,))
        row = cur.fetchone(); cur.close()
        if row:
            return {
                'found_emails': row[0].split('|||') if row[0] else [],
                'verified_emails': row[1].split('|||') if row[1] else [],
                'scout_recipients': row[2].split('|||') if row[2] else [],
                'scout_subject': row[3] or '',
                'scout_message': row[4] or '',
                'scout_count': row[5] or 0,
                'wix_found_emails': row[6].split('|||') if row[6] else [],
                'wix_verified_emails': row[7].split('|||') if row[7] else [],
                'wix_scout_recipients': row[8].split('|||') if row[8] else [],
                'wix_scout_subject': row[9] or '',
                'wix_scout_message': row[10] or '',
                'wix_session_sent_count': row[11] or 0
            }
        return {}
    except Exception as e:
        print(f"load_user_state: {e}")
        return {}
    finally: release_db(conn)

def load_found_pairs(user_email, platform='shopify'):
    state = load_user_state(user_email)
    key = 'found_emails' if platform == 'shopify' else 'wix_found_emails'
    pairs = []
    for item in state.get(key, []):
        if not item: continue
        if ':::' in item:
            parts = item.split(':::', 1)
            email = parts[0].strip().lower()
            store = parts[1].strip().lower() if len(parts) > 1 else ''
            if email:
                if not store: store = email
                pairs.append((email, store))
        else:
            email = item.strip().lower()
            if email:
                pairs.append((email, email))
    return pairs

# ==========================================
# SESSION SEND COUNTER (SHOPIFY)
# ==========================================
def get_session_sent_count(user_email):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT session_sent_count FROM user_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        return row[0] if row and row[0] is not None else 0
    except: return 0
    finally: release_db(conn)

def increment_session_sent_count(user_email):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_state (user_email, session_sent_count) VALUES (%s, 0)", (user_email,))
        cur.execute("UPDATE user_state SET session_sent_count = COALESCE(session_sent_count,0) + 1, updated_at=NOW() WHERE user_email=%s RETURNING session_sent_count", (user_email,))
        new_count = cur.fetchone()[0]; conn.commit(); cur.close()
        return new_count
    except: return 0
    finally: release_db(conn)

def reset_session_sent_count(user_email):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_state (user_email, session_sent_count) VALUES (%s, 0)", (user_email,))
        cur.execute("UPDATE user_state SET session_sent_count = 0, session_started_at = NOW(), updated_at=NOW() WHERE user_email=%s", (user_email,))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def get_send_limit(user_email):
    conn = get_db()
    if not conn: return DEFAULT_SEND_LIMIT
    try:
        cur = conn.cursor()
        cur.execute("SELECT send_limit FROM user_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        val = row[0] if row and row[0] else DEFAULT_SEND_LIMIT
        if val < 1: val = DEFAULT_SEND_LIMIT
        return val
    except: return DEFAULT_SEND_LIMIT
    finally: release_db(conn)

def set_send_limit(user_email, limit):
    if limit < 1: limit = 1
    if limit > 10000: limit = 10000
    conn = get_db()
    if not conn: return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_state (user_email, send_limit) VALUES (%s, %s)", (user_email, limit))
        cur.execute("UPDATE user_state SET send_limit = %s, updated_at=NOW() WHERE user_email = %s", (limit, user_email))
        conn.commit(); cur.close()
        return True
    except: return False
    finally: release_db(conn)

def counter_status(user_email):
    count = get_session_sent_count(user_email)
    limit = get_send_limit(user_email)
    at_milestone = (count > 0 and count % limit == 0)
    next_milestone = ((count // limit) + 1) * limit
    return {'count': count, 'limit': limit, 'next_milestone': next_milestone, 'at_milestone': at_milestone}

# ==========================================
# SESSION SEND COUNTER (WIX)
# ==========================================
def wix_get_session_sent_count(user_email):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT wix_session_sent_count FROM user_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        return row[0] if row and row[0] is not None else 0
    except: return 0
    finally: release_db(conn)

def wix_increment_session_sent_count(user_email):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO user_state (user_email, wix_session_sent_count) VALUES (%s, 0)", (user_email,))
        cur.execute("UPDATE user_state SET wix_session_sent_count = COALESCE(wix_session_sent_count,0) + 1, updated_at=NOW() WHERE user_email=%s RETURNING wix_session_sent_count", (user_email,))
        new_count = cur.fetchone()[0]; conn.commit(); cur.close()
        return new_count
    except: return 0
    finally: release_db(conn)

def wix_counter_status(user_email):
    count = wix_get_session_sent_count(user_email)
    limit = get_send_limit(user_email)
    at_milestone = (count > 0 and count % limit == 0)
    next_milestone = ((count // limit) + 1) * limit
    return {'count': count, 'limit': limit, 'next_milestone': next_milestone, 'at_milestone': at_milestone}

# ==========================================
# SHOPIFY CATALOGUE CRAWLER
# ==========================================
def get_cached_catalogue(domain, max_age_hours=24):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("""SELECT product_count, categories, vendors, tags, sold_out_count, bestsellers
            FROM store_catalogues WHERE domain = %s AND crawled_at > NOW() - INTERVAL '%s hours'""",
            (domain, max_age_hours))
        row = cur.fetchone(); cur.close()
        if not row: return None
        return {'product_count': row[0] or 0,
                'categories': row[1].split('|||') if row[1] else [],
                'vendors': row[2].split('|||') if row[2] else [],
                'tags': row[3].split('|||') if row[3] else [],
                'sold_out_count': row[4] or 0,
                'bestsellers': json.loads(row[5]) if row[5] else []}
    except: return None
    finally: release_db(conn)

def save_catalogue_cache(domain, cat):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO store_catalogues (domain, product_count, categories, vendors, tags, sold_out_count, bestsellers, crawled_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (domain) DO UPDATE SET product_count=EXCLUDED.product_count, categories=EXCLUDED.categories,
                vendors=EXCLUDED.vendors, tags=EXCLUDED.tags, sold_out_count=EXCLUDED.sold_out_count,
                bestsellers=EXCLUDED.bestsellers, crawled_at=NOW()""",
            (domain, cat.get('product_count', 0),
             '|||'.join(cat.get('categories', [])), '|||'.join(cat.get('vendors', [])),
             '|||'.join(cat.get('tags', [])), cat.get('sold_out_count', 0),
             json.dumps(cat.get('bestsellers', []))))
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)

def crawl_catalogue(domain, limit=50):
    try:
        domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        if not domain or '.' not in domain: return None
        cached = get_cached_catalogue(domain)
        if cached is not None: return cached
        url = f"https://{domain}/products.json?limit={limit}"
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        if r.status_code != 200: return None
        products = r.json().get('products', [])
        if not products: return None
        categories = {}; vendors = {}; tags = {}; sold_out = 0; product_details = []
        for p in products:
            pt = (p.get('product_type') or 'Uncategorized').strip()
            if pt: categories[pt] = categories.get(pt, 0) + 1
            v = (p.get('vendor') or 'Unknown').strip()
            if v: vendors[v] = vendors.get(v, 0) + 1
            for t in p.get('tags', [])[:5]:
                t = (t or '').strip()
                if t: tags[t] = tags.get(t, 0) + 1
            variants = p.get('variants', [])
            if any(not vv.get('available', True) for vv in variants): sold_out += 1
            product_details.append({'title': (p.get('title') or '')[:80], 'variants': len(variants), 'price': variants[0].get('price', '') if variants else ''})
        result = {'product_count': len(products),
                  'categories': [c[0] for c in sorted(categories.items(), key=lambda x: -x[1])[:5]],
                  'vendors': [v[0] for v in sorted(vendors.items(), key=lambda x: -x[1])[:5]],
                  'tags': [t[0] for t in sorted(tags.items(), key=lambda x: -x[1])[:10]],
                  'sold_out_count': sold_out,
                  'bestsellers': sorted(product_details, key=lambda x: -x['variants'])[:5]}
        save_catalogue_cache(domain, result)
        return result
    except: return None

# ==========================================
# EMAIL FINDER (shared)
# ==========================================
def find_emails(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    if not domain or '.' not in domain: return []
    if domain in PLACEHOLDER_DOMAINS: return []
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
                for e in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean): emails.append(e.lower())
                for cf in re.findall(r'data-cfemail="([a-f0-9]+)"', r.text):
                    try:
                        k = int(cf[:2], 16)
                        d = ''.join([chr(int(cf[i:i+2], 16) ^ k) for i in range(2, len(cf), 2)])
                        if '@' in d and '.' in d: emails.append(d.lower())
                    except: pass
                for e in re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text): emails.append(e.lower())
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

def wix_find_emails(domain): return find_emails(domain)

def process_subjob(subjob_id):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_urls, results, master_id, sub_index, user_email FROM email_finder_subjobs WHERE id = %s", (subjob_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        try: results = json.loads(row[1]) if row[1] else []
        except: results = []
        master_id = row[2]; sub_index = row[3]; user_email = row[4]
    finally: release_db(conn)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE email_finder_subjobs SET status='running' WHERE id=%s", (subjob_id,))
            cur.execute("UPDATE email_finder_master SET status='running' WHERE id=%s", (master_id,))
            conn.commit(); cur.close()
        finally: release_db(conn)
    while remaining:
        chunk = remaining[:5]; remaining = remaining[5:]
        chunk_results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(find_emails, u): u for u in chunk}
            for f in as_completed(futures):
                try:
                    emails = f.result()
                    if emails: chunk_results.append({'store': futures[f], 'emails': emails})
                except: pass
        results.extend(chunk_results)
        total = sum(len(r.get('emails', [])) for r in results)
        conn = get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            cur.execute("""UPDATE email_finder_subjobs SET processed=%s, emails_found=%s, results=%s, remaining_urls=%s, status=%s WHERE id=%s""",
                (len(results), total, json.dumps(results), '|||'.join(remaining), 'running' if remaining else 'completed', subjob_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE email_finder_subjobs SET status='completed' WHERE id=%s", (subjob_id,))
            conn.commit(); cur.close()
        finally: release_db(conn)
    trigger_next_subjob(master_id, sub_index + 1, user_email)

def trigger_next_subjob(master_id, next_index, user_email):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM email_finder_subjobs WHERE master_id=%s AND sub_index=%s AND status='pending'", (master_id, next_index))
        row = cur.fetchone(); cur.close()
    finally: release_db(conn)
    if row:
        time.sleep(1)
        threading.Thread(target=process_subjob, args=(row[0],), daemon=True).start()
    else:
        conn = get_db()
        if not conn: return
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM email_finder_subjobs WHERE master_id=%s AND status!='completed'", (master_id,))
            pending = cur.fetchone()[0]; cur.close()
        finally: release_db(conn)
        if pending == 0:
            all_results = []
            conn = get_db()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("SELECT results FROM email_finder_subjobs WHERE master_id=%s ORDER BY sub_index ASC", (master_id,))
                    for r in cur.fetchall():
                        if r[0]:
                            try: all_results.extend(json.loads(r[0]))
                            except: pass
                    total = sum(len(r.get('emails', [])) for r in all_results)
                    cur.execute("UPDATE email_finder_master SET status='completed', processed=%s, emails_found=%s WHERE id=%s", (len(all_results), total, master_id))
                    conn.commit(); cur.close()
                finally: release_db(conn)
            if user_email:
                pairs = []
                for r in all_results:
                    store = r.get('store', '')
                    for e in r.get('emails', []): pairs.append(f"{e}:::{store}")
                if pairs: save_user_state(user_email, found_emails='|||'.join(pairs))

def resume_unfinished_masters():
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, user_email FROM email_finder_master WHERE status IN ('running','pending')")
        rows = cur.fetchall(); cur.close()
    finally: release_db(conn)
    for mid, ue in rows:
        conn = get_db()
        if not conn: continue
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM email_finder_subjobs WHERE master_id=%s AND status!='completed' ORDER BY sub_index ASC LIMIT 1", (mid,))
            row = cur.fetchone(); cur.close()
        finally: release_db(conn)
        if row:
            threading.Thread(target=process_subjob, args=(row[0],), daemon=True).start()

def get_email_finder_masters(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, total, emails_found, status, created_at FROM email_finder_master
            WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'total': r[1], 'emails': r[2], 'stores': 0, 'status': r[3], 'created_at': str(r[4])[:16]} for r in rows]
    except: return []
    finally: release_db(conn)

def get_email_finder_master_detail(job_id, user_email):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, total, status FROM email_finder_master WHERE id = %s AND user_email = %s", (job_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return None
        results = []
        conn2 = get_db()
        if conn2:
            try:
                cur2 = conn2.cursor()
                cur2.execute("SELECT results FROM email_finder_subjobs WHERE master_id=%s ORDER BY sub_index ASC", (job_id,))
                for s in cur2.fetchall():
                    if s[0]:
                        try: results.extend(json.loads(s[0]))
                        except: pass
                cur2.close()
            finally: release_db(conn2)
        return {'results': results, 'status': row[2], 'total': row[1]}
    except: return None
    finally: release_db(conn)

# ==========================================
# WIX EMAIL FINDER (background)
# ==========================================
def wix_process_subjob(job_id):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_urls, results, user_email FROM wix_email_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        try: results = json.loads(row[1]) if row[1] else []
        except: results = []
        user_email = row[2]
    finally: release_db(conn)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_email_jobs SET status='running' WHERE id=%s", (job_id,))
            conn.commit(); cur.close()
        finally: release_db(conn)
    while remaining:
        chunk = remaining[:5]; remaining = remaining[5:]
        chunk_results = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(wix_find_emails, u): u for u in chunk}
            for f in as_completed(futures):
                try:
                    emails = f.result()
                    if emails: chunk_results.append({'store': futures[f], 'emails': emails})
                except: pass
        results.extend(chunk_results)
        total = sum(len(r.get('emails', [])) for r in results)
        conn = get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            cur.execute("""UPDATE wix_email_jobs SET processed=%s, emails_found=%s, results=%s, remaining_urls=%s, status=%s WHERE id=%s""",
                (len(results), total, json.dumps(results), '|||'.join(remaining), 'running' if remaining else 'completed', job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_email_jobs SET status='completed' WHERE id=%s", (job_id,))
            conn.commit(); cur.close()
        finally: release_db(conn)
    if user_email:
        pairs = []
        for r in results:
            store = r.get('store', '')
            for e in r.get('emails', []): pairs.append(f"{e}:::{store}")
        if pairs: save_user_state(user_email, wix_found_emails='|||'.join(pairs))

def wix_get_email_jobs(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, total, emails_found, status, created_at FROM wix_email_jobs
            WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'total': r[1], 'emails': r[2], 'status': r[3], 'created_at': str(r[4])[:16]} for r in rows]
    except: return []
    finally: release_db(conn)

def wix_get_email_job_detail(job_id, user_email):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, total, results, status FROM wix_email_jobs WHERE id = %s AND user_email = %s", (job_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return None
        try: results = json.loads(row[2]) if row[2] else []
        except: results = []
        return {'id': row[0], 'total': row[1], 'results': results, 'status': row[3]}
    except: return None
    finally: release_db(conn)

# ==========================================
# WIX DETECTION / AUDIT
# ==========================================
def is_wix_site(html):
    if not html: return False
    low = html.lower()
    return any(x in low for x in ['wix.com', 'wixstatic.com', 'wix-code', 'wixstores', '_wixcss', 'parastorage.com', 'wixsite.com'])

def has_wix_store_signals(html):
    if not html: return False
    low = html.lower()
    return any(sig in low for sig in WIX_STORE_SIGNALS)

def extract_wix_products(html, base_url, max_products=3):
    products = []
    product_links = re.findall(r'href="(https?://[^"]*?/(?:product-page|shop|store|product)/[^"?#]+)"', html)
    product_links += re.findall(r'href="(/[^"]*?/(?:product-page|shop|store|product)/[^"?#]+)"', html)
    seen = set(); unique_links = []
    for l in product_links:
        if l.startswith('/'): l = base_url.rstrip('/') + l
        if l in seen: continue
        seen.add(l); unique_links.append(l)
        if len(unique_links) >= max_products: break
    try:
        sitemap_url = f"{base_url.rstrip('/')}/store-products-sitemap.xml"
        sr = requests.get(sitemap_url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        if sr.status_code == 200:
            for sl in re.findall(r'<loc>(.*?)</loc>', sr.text)[:max_products]:
                if sl not in seen:
                    unique_links.append(sl); seen.add(sl)
                    if len(unique_links) >= max_products: break
    except: pass
    for link in unique_links[:max_products]:
        try:
            pr = requests.get(link, timeout=8, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            if pr.status_code != 200: continue
            title_m = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', pr.text, re.I)
            price_m = re.search(r'<meta[^>]+property=["\'](?:og:price:amount|product:price:amount)["\'][^>]+content=["\']([^"\']+)', pr.text, re.I)
            if not title_m: title_m = re.search(r'<title[^>]*>(.*?)</title>', pr.text, re.I | re.S)
            title = (title_m.group(1).strip() if title_m else '')[:100]
            price = price_m.group(1).strip() if price_m else ''
            if title: products.append({'title': title, 'price': price, 'url': link})
        except: continue
        if len(products) >= max_products: break
    return products

def audit_store_wix(domain, case_id):
    raw = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    report = {"domain": raw, "case_id": case_id, "platform": "Wix",
              "audited_at": datetime.now().isoformat(),
              "checks": {}, "scores": {}, "issues": [], "positives": [], "top_products": []}
    if not raw or '.' not in raw:
        report['error'] = "Invalid domain"; return report
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept-Language": "en-US,en;q=0.5"}
    base_url = f"https://{raw}"
    try:
        start = time.time()
        r = requests.get(base_url, headers=headers, timeout=12, allow_redirects=True)
        lt = round(time.time() - start, 2)
        html = r.text
        report["checks"]["http_status"] = r.status_code
        report["checks"]["load_time_seconds"] = lt
        report["checks"]["final_url"] = r.url
        report["checks"]["https"] = True
        if lt < 1.5: report["positives"].append(f"Fast load time ({lt}s)")
        elif lt > 3: report["issues"].append({"title": "Slow Load Time", "description": f"Took {lt}s to load.", "recommendation": "Optimize images.", "severity": "medium"})
    except Exception as e:
        report["checks"]["https"] = False
        report["error"] = f"Could not reach store: {str(e)[:100]}"
        return report
    report["checks"]["is_wix"] = is_wix_site(html)
    report["checks"]["has_store_signals"] = has_wix_store_signals(html)
    if report["checks"]["is_wix"]: report["positives"].append("Confirmed Wix site")
    if report["checks"]["has_store_signals"]: report["positives"].append("Wix Store app installed")
    else: report["issues"].append({"title": "No Store Signals Detected", "description": "Could not detect Wix Stores app.", "recommendation": "Ensure Wix Stores is installed.", "severity": "medium"})
    try:
        products = extract_wix_products(html, base_url, max_products=3)
        report["top_products"] = products
        if products: report["positives"].append(f"Detected {len(products)} products on storefront")
        else: report["issues"].append({"title": "No Products Detected", "description": "Could not find product pages.", "recommendation": "Feature products on your homepage.", "severity": "high"})
    except: pass
    hv = 'name="viewport"' in html.lower()
    report["checks"]["mobile_responsive"] = hv
    if hv: report["positives"].append("Mobile responsive")
    else: report["issues"].append({"title": "Not Mobile Responsive", "description": "Missing viewport meta.", "recommendation": "Enable mobile in Wix editor.", "severity": "high"})
    he = bool(re.search(r'mailto:[^"\']+', html)); hp = bool(re.search(r'tel:[^"\']+', html))
    report["checks"]["has_email_link"] = he; report["checks"]["has_phone_link"] = hp
    if he or hp: report["positives"].append("Contact info present")
    else: report["issues"].append({"title": "No Contact Info", "description": "No email/phone links on homepage.", "recommendation": "Add Contact page.", "severity": "high"})
    socials = [p.split('.')[0] for p in ['facebook.com','instagram.com','twitter.com','tiktok.com','youtube.com','pinterest.com'] if p in html.lower()]
    report["checks"]["social_links"] = socials
    if len(socials) >= 2: report["positives"].append(f"{len(socials)} social links")
    elif len(socials) == 0: report["issues"].append({"title": "No Social Media", "description": "None found.", "recommendation": "Add social profiles.", "severity": "medium"})
    policies = ['/terms', '/privacy', '/shipping', '/returns', '/policies']
    pf = 0
    for pol in policies:
        try:
            pr = requests.get(f"{base_url.rstrip('/')}{pol}", headers=headers, timeout=5)
            if pr.status_code == 200: pf += 1
        except: pass
    report["checks"]["policy_pages_found"] = f"{pf}/5"
    if pf >= 4: report["positives"].append("Policies present")
    elif pf < 2: report["issues"].append({"title": "Missing Policies", "description": f"Only {pf}/5 found.", "recommendation": "Add terms, privacy, shipping, returns.", "severity": "high"})
    html_low = html.lower()
    payments = []
    for name, sigs in {"PayPal": ["paypal.com/sdk", "paypal"], "Stripe": ["stripe.com", "js.stripe"],
                       "Apple Pay": ["apple-pay", "applepay"], "Google Pay": ["google-pay", "googlepay"],
                       "Klarna": ["klarna"], "Afterpay": ["afterpay"]}.items():
        for s in sigs:
            if s in html_low: payments.append(name); break
    report["checks"]["payment_methods"] = payments
    if len(payments) >= 2: report["positives"].append(f"{len(payments)} payment options")
    else: report["issues"].append({"title": "Limited Payment Options", "description": f"Only {len(payments)} detected.", "recommendation": "Add PayPal, Stripe, or Apple Pay.", "severity": "medium"})
    review_apps = []
    for name, sigs in {"Wix Reviews":["wix-reviews"],"Judge.me":["judge.me","judgeme"],"Yotpo":["yotpo"],"Trustpilot":["trustpilot"]}.items():
        for s in sigs:
            if s in html_low: review_apps.append(name); break
    report["checks"]["review_apps"] = review_apps
    if review_apps: report["positives"].append(f"Reviews: {', '.join(review_apps)}")
    else: report["issues"].append({"title": "No Reviews App", "description": "No review system detected.", "recommendation": "Install Wix Reviews (free).", "severity": "high"})
    free_ship = any(x in html_low for x in ['free shipping', 'free delivery', 'shipping on us'])
    report["checks"]["free_shipping_advertised"] = free_ship
    if free_ship: report["positives"].append("Free shipping advertised")
    else: report["issues"].append({"title": "No Free Shipping Banner", "description": "Top buyer priority.", "recommendation": "Add a free shipping threshold.", "severity": "medium"})
    title_m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    desc_m = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.I | re.S)
    title = title_m.group(1).strip() if title_m else ''
    desc = desc_m.group(1).strip() if desc_m else ''
    report["checks"]["meta_title_length"] = len(title)
    report["checks"]["meta_description_length"] = len(desc)
    if not title: report["issues"].append({"title": "Missing Page Title", "description": "No title tag.", "recommendation": "Add SEO title.", "severity": "high"})
    if not desc: report["issues"].append({"title": "Missing Meta Description", "description": "No description.", "recommendation": "Add 150-160 chars.", "severity": "medium"})
    trust = 0
    if he or hp: trust += 20
    trust += min(int((pf/5)*30), 30)
    if len(socials) >= 2: trust += 15
    elif len(socials) == 1: trust += 8
    if review_apps: trust += 15
    if len(payments) >= 2: trust += 10
    report["scores"]["trust_score"] = min(trust, 100)
    tech = 0
    if report["checks"].get("https"): tech += 25
    if report["checks"].get("http_status") == 200: tech += 15
    if hv: tech += 20
    if lt < 1.5: tech += 20
    elif lt < 3: tech += 12
    elif lt < 5: tech += 5
    report["scores"]["technical_score"] = min(tech, 100)
    mkt = 0
    if report["top_products"]: mkt += 20
    if len(socials) >= 3: mkt += 20
    elif len(socials) >= 1: mkt += 10
    if free_ship: mkt += 10
    if len(payments) >= 3: mkt += 10
    if review_apps: mkt += 15
    report["scores"]["marketing_score"] = min(mkt, 100)
    report["scores"]["overall_score"] = int((report["scores"]["trust_score"] + report["scores"]["technical_score"] + report["scores"]["marketing_score"]) / 3)
    return report

# ==========================================
# SHOPIFY AUDIT
# ==========================================
def audit_store(domain, case_id, include_catalogue=False):
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
    is_wix = is_wix_site(html)
    report["checks"]["is_shopify"] = is_shop
    report["checks"]["is_wix"] = is_wix
    report["checks"]["platform"] = "Shopify" if is_shop else ("Wix" if is_wix else "Unknown")
    if is_shop: report["positives"].append("Confirmed Shopify store")
    if is_wix: report["positives"].append("Confirmed Wix store")
    try:
        r2 = requests.get(f"{base_url}/products.json?limit=250", headers=headers, timeout=10)
        if r2.status_code == 200:
            products_data = r2.json().get('products', [])
            pc = len(products_data)
            report["checks"]["product_count"] = pc
            if pc == 0: report["issues"].append({"title": "No Products Visible", "description": "No products.", "recommendation": "Add products.", "severity": "high"})
            elif pc < 10: report["issues"].append({"title": f"Only {pc} Products", "description": "Few products.", "recommendation": "Aim for 20+.", "severity": "medium"})
            else: report["positives"].append(f"{pc}+ products")
    except: report["checks"]["product_count"] = None
    hv = 'name="viewport"' in html.lower()
    report["checks"]["mobile_responsive"] = hv
    if hv: report["positives"].append("Mobile responsive")
    else: report["issues"].append({"title": "Not Mobile Responsive", "description": "Missing viewport.", "recommendation": "Use mobile theme.", "severity": "high"})
    he = bool(re.search(r'mailto:[^"\']+', html)); hp = bool(re.search(r'tel:[^"\']+', html))
    report["checks"]["has_email_link"] = he; report["checks"]["has_phone_link"] = hp
    if he or hp: report["positives"].append("Contact info present")
    else: report["issues"].append({"title": "No Contact Info", "description": "No email/phone.", "recommendation": "Add Contact page.", "severity": "high"})
    socials = [p.split('.')[0] for p in ['facebook.com','instagram.com','twitter.com','tiktok.com','youtube.com','pinterest.com'] if p in html.lower()]
    report["checks"]["social_links"] = socials
    if len(socials) >= 2: report["positives"].append(f"{len(socials)} socials")
    else: report["issues"].append({"title": "No Social Media", "description": "None found.", "recommendation": "Add social profiles.", "severity": "medium"})
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
    payments = []
    html_low = html.lower()
    for name, sigs in {"PayPal": ["paypal.com/sdk", "paypal-button"],"Stripe": ["js.stripe.com", "stripe.com/v3"],"Apple Pay": ["apple-pay", "applepay"],"Google Pay": ["google-pay", "googlepay"],"Shop Pay": ["shop-pay", "shop_pay"],"Klarna": ["klarna"]}.items():
        for s in sigs:
            if s in html_low: payments.append(name); break
    report["checks"]["payment_methods"] = payments
    if len(payments) >= 2: report["positives"].append(f"{len(payments)} payment options")
    else: report["issues"].append({"title": "Limited Payment Options", "description": f"Only {len(payments)} detected.", "recommendation": "Add PayPal, Shop Pay.", "severity": "medium"})
    review_apps = []
    for name, sigs in {"Judge.me":["judge.me","judgeme"],"Loox":["loox.io"],"Yotpo":["yotpo"],"Stamped":["stamped.io"]}.items():
        for s in sigs:
            if s in html_low: review_apps.append(name); break
    report["checks"]["review_apps"] = review_apps
    if review_apps: report["positives"].append(f"Reviews: {', '.join(review_apps)}")
    else: report["issues"].append({"title": "No Reviews App", "description": "No review system.", "recommendation": "Install Judge.me (free).", "severity": "high"})
    free_ship = any(x in html_low for x in ['free shipping', 'free delivery', 'shipping on us'])
    report["checks"]["free_shipping_advertised"] = free_ship
    if free_ship: report["positives"].append("Free shipping advertised")
    else: report["issues"].append({"title": "No Free Shipping Banner", "description": "Top buyer priority.", "recommendation": "Add $50+ threshold.", "severity": "medium"})
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
    report["scores"]["technical_score"] = min(tech, 100)
    mkt = 0
    if len(socials) >= 3: mkt += 20
    elif len(socials) >= 1: mkt += 10
    pc = report["checks"].get("product_count") or 0
    if pc >= 10: mkt += 15
    elif pc >= 5: mkt += 8
    if free_ship: mkt += 10
    if len(payments) >= 3: mkt += 10
    report["scores"]["marketing_score"] = min(mkt, 100)
    report["scores"]["overall_score"] = int((report["scores"]["trust_score"] + report["scores"]["technical_score"] + report["scores"]["marketing_score"]) / 3)
    if include_catalogue:
        try:
            cat = crawl_catalogue(raw, limit=50)
            if cat: report["catalogue"] = cat
        except: pass
    return report

# ==========================================
# EMAIL GENERATORS
# ==========================================
GREETINGS = {'friendly': ["Hi {brand} team,","Hey {brand} folks,","Hello {brand},","Hey {brand},","Hi {brand},"],
             'professional': ["Hello {brand} team,","Dear {brand} team,","Greetings {brand} team,","Hello {brand},"],
             'casual': ["Hey {brand},","Yo {brand},","What's up {brand}?","Hey {brand} team,"]}
OPENERS_WITH_URL = {
    'friendly': ["Just had a quick look at {url} — spotted a few things.","Went through {url} today and noticed a few issues.","Spent a few minutes on {url} — here's what stood out."],
    'professional': ["I reviewed {url} and identified several areas for improvement.","After analyzing {url}, I found a few notable issues.","I ran a quick audit of {url} today."],
    'casual': ["Just checked {url} — found a few things.","Took a look at {url} and noticed some stuff.","Was browsing {url} and saw a few issues."]}
OPENERS_NO_URL = {
    'friendly': ["Just had a quick look at your store — spotted a few things.","Went through your store today."],
    'professional': ["I reviewed your store and identified several areas for improvement.","After analyzing your store, I found a few issues."],
    'casual': ["Just checked your store — found a few things.","Took a look at your store."]}
ISSUES_INTROS = {'friendly': ["Top issues I found:","Here's what I noticed:","Quick list:"],
                 'professional': ["Key findings:","Issues identified:","Summary of findings:"],
                 'casual': ["Here's what I found:","Quick rundown:","Stuff I noticed:"]}
CTAS = {'friendly': ["Want me to send a quick 2-min video?","Want a short checklist?","Should I send over the details?"],
        'professional': ["Would a short walkthrough be useful?","Shall I send over the detailed findings?","Can I share a quick report?"],
        'casual': ["Want a quick video?","Should I send the details?","Want a checklist?"]}
SIGNOFF_LINES = {'friendly': ["No pitch — just thought it was worth sharing.","No pressure either way.","Just sharing in case it's useful."],
                 'professional': ["Happy to provide a detailed report if helpful.","No obligation — just wanted to flag it."],
                 'casual': ["No pitch — just sharing.","No pressure.","Just thought I'd share."]}
SIGNOFFS = ["Best regards,", "Cheers,", "Best,", "Warmly,"]

def pick(pool):
    try: return random.choice(pool)
    except: return pool[0] if pool else ''

def generate_outreach_email_wix(report, tone='friendly', sender_name='', email=''):
    tone = tone if tone in GREETINGS else 'friendly'
    domain = report.get('domain', '')
    is_email_as_domain = '@' in domain if domain else False
    if is_email_as_domain: brand = domain.split('@')[0]; display_url = ''
    elif domain and domain.lower() in PUBLIC_EMAIL_DOMAINS:
        brand = email.split('@')[0] if email and '@' in email else 'there'; display_url = ''
    else: brand = domain.split('.')[0].title() if domain else 'there'; display_url = domain
    issues = report.get('issues', []); scores = report.get('scores', {})
    top_products = report.get('top_products', [])
    overall = scores.get('overall_score', 0)
    priority = {'high': 0, 'medium': 1, 'low': 2}
    sorted_issues = sorted(issues, key=lambda x: priority.get(x.get('severity', 'low'), 3))
    issue_bullets = [i.get('title', '') for i in sorted_issues[:3]]
    subj_target = display_url if display_url else 'your store'
    if overall < 50: subject = f"Found {len(issues)} issues on {subj_target}"
    elif overall < 75: subject = f"Quick idea for {subj_target}"
    else: subject = f"Nice store! One thing I noticed on {subj_target}"
    greeting = pick(GREETINGS[tone]).replace('{brand}', brand)
    opener = pick(OPENERS_WITH_URL[tone] if display_url else OPENERS_NO_URL[tone]).replace('{url}', display_url)
    issues_intro = pick(ISSUES_INTROS[tone]); cta = pick(CTAS[tone])
    signoff_line = pick(SIGNOFF_LINES[tone]); signoff = pick(SIGNOFFS)
    signature = sender_name.strip() if sender_name and sender_name.strip() else "[Your name]"
    body_parts = [greeting, "", opener, ""]
    if top_products:
        prod_names = [p.get('title', '') for p in top_products[:3] if p.get('title')]
        if prod_names:
            prod_line = "Nice lineup — noticed you're selling " + ", ".join([f'"{n[:40]}"' for n in prod_names[:2]])
            if len(prod_names) >= 3: prod_line += f', and "{prod_names[2][:40]}"'
            body_parts.append(prod_line + ". That's a solid catalog to work with.")
            body_parts.append("")
    body_parts.append(issues_intro); body_parts.append("")
    for b in issue_bullets: body_parts.append(f"• {b}")
    body_parts.append("")
    body_parts.append(f"Overall score: {overall}/100 — most are 1-day fixes.")
    body_parts.append(""); body_parts.append(cta); body_parts.append("")
    body_parts.append(signoff_line); body_parts.append(""); body_parts.append(signoff); body_parts.append(signature)
    return {'subject': subject, 'body': "\n".join(body_parts), 'tone': tone}

def generate_outreach_email(report, tone='friendly', sender_name='', email=''):
    tone = tone if tone in GREETINGS else 'friendly'
    domain = report.get('domain', '')
    is_email_as_domain = '@' in domain if domain else False
    if is_email_as_domain: brand = domain.split('@')[0]; display_url = ''
    elif domain and domain.lower() in PUBLIC_EMAIL_DOMAINS:
        brand = email.split('@')[0] if email and '@' in email else 'there'; display_url = ''
    else: brand = domain.split('.')[0].title() if domain else 'there'; display_url = domain
    issues = report.get('issues', []); scores = report.get('scores', {})
    overall = scores.get('overall_score', 0)
    priority = {'high': 0, 'medium': 1, 'low': 2}
    sorted_issues = sorted(issues, key=lambda x: priority.get(x.get('severity', 'low'), 3))
    issue_bullets = [i.get('title', '') for i in sorted_issues[:3]]
    subj_target = display_url if display_url else 'your store'
    if overall < 50: subject = f"Found {len(issues)} issues on {subj_target}"
    elif overall < 75: subject = f"Quick idea for {subj_target}"
    else: subject = f"Nice store! One thing I noticed on {subj_target}"
    greeting = pick(GREETINGS[tone]).replace('{brand}', brand)
    opener = pick(OPENERS_WITH_URL[tone] if display_url else OPENERS_NO_URL[tone]).replace('{url}', display_url)
    issues_intro = pick(ISSUES_INTROS[tone]); cta = pick(CTAS[tone])
    signoff_line = pick(SIGNOFF_LINES[tone]); signoff = pick(SIGNOFFS)
    signature = sender_name.strip() if sender_name and sender_name.strip() else "[Your name]"
    body_parts = [greeting, "", opener, "", issues_intro, ""]
    for b in issue_bullets: body_parts.append(f"• {b}")
    body_parts.append("")
    cat = report.get('catalogue')
    if cat and (cat.get('product_count') or cat.get('categories')):
        pc = cat.get('product_count', 0); cats = cat.get('categories', [])[:3]
        if pc and cats: body_parts.append(f"Also noticed: {pc} products — top categories: {', '.join(cats)}")
        elif pc: body_parts.append(f"Also noticed: {pc} products live")
        body_parts.append("")
    body_parts.append(f"Overall score: {overall}/100 — most are 1-day fixes.")
    body_parts.append(""); body_parts.append(cta); body_parts.append("")
    body_parts.append(signoff_line); body_parts.append(""); body_parts.append(signoff); body_parts.append(signature)
    return {'subject': subject, 'body': "\n".join(body_parts), 'tone': tone}

# ==========================================
# NAVBAR
# ==========================================
NAVBAR = '''
<style>
.navbar{position:fixed;top:0;left:0;right:0;height:56px;background:#1f2937;color:white;display:flex;align-items:center;padding:0 16px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,0.2)}
.navbar-title{font-size:18px;font-weight:bold;margin-left:12px}
.hamburger{background:none;border:none;color:white;font-size:24px;cursor:pointer;padding:4px 10px}
.drawer{position:fixed;top:0;left:-300px;width:300px;height:100vh;background:#111827;color:white;transition:left 0.3s ease;z-index:10000;padding-top:20px;overflow-y:auto}
.drawer.open{left:0}
.drawer-header{padding:16px 20px;font-size:18px;font-weight:bold;border-bottom:1px solid #374151;display:flex;justify-content:space-between;align-items:center}
.drawer-close{background:none;border:none;color:white;font-size:24px;cursor:pointer}
.drawer a{display:block;padding:14px 20px;color:white;text-decoration:none;border-bottom:1px solid #1f2937;font-size:15px}
.drawer a:hover{background:#1f2937}
.drawer-section{padding:12px 20px 6px;font-size:12px;font-weight:bold;color:#9ca3af;letter-spacing:1px;text-transform:uppercase;background:#0f172a}
.drawer-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:9998;display:none}
.drawer-overlay.show{display:block}
.page-content{padding-top:70px}
</style>
<div class="navbar">
<button class="hamburger" onclick="toggleDrawer()">☰</button>
<span class="navbar-title">Zegseg Tools</span>
</div>
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
<div class="drawer-header"><span>📧 Menu</span><button class="drawer-close" onclick="toggleDrawer()">×</button></div>

<div class="drawer-section">🛍️ Shopify</div>
<a href="/" onclick="closeDrawer()">🔍 Email Finder</a>
<a href="/discover" onclick="closeDrawer()">🎯 Store Discovery</a>
<a href="/verify" onclick="closeDrawer()">✅ Verify Emails</a>
<a href="/scout" onclick="closeDrawer()">📨 Email Scout</a>
<a href="/audit" onclick="closeDrawer()">🚀 Analyze & Send</a>

<div class="drawer-section">🎨 Wix</div>
<a href="/wix" onclick="closeDrawer()">🔍 Wix Store Finder</a>
<a href="/wix/finder" onclick="closeDrawer()">📧 Wix Email Finder</a>
<a href="/wix/verify" onclick="closeDrawer()">✅ Wix Verify</a>
<a href="/wix/scout" onclick="closeDrawer()">📨 Wix Scout</a>
<a href="/wix/audit" onclick="closeDrawer()">🚀 Wix Analyze & Send</a>

<div class="drawer-section">⚙️ Account</div>
<a href="/settings" onclick="closeDrawer()">⚙️ Settings</a>
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
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="text" name="sender_name" placeholder="Your name" required><input type="password" name="password" placeholder="Password (min 6)" required minlength="6"><button>Sign Up</button></form>
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
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">Your Name</h3>
<form method="POST">
<input type="text" name="sender_name" placeholder="e.g. Daniel Phillips" value="{current_name}" style="width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box;margin-bottom:10px">
<button type="submit" style="background:#0d9488;color:white;padding:12px 30px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%">Save</button>
</form>
{f'<p style="color:green;margin-top:10px">{msg}</p>' if msg else ''}
</div></div>'''
    return render_page("Settings", body)

# ==========================================
# SHOPIFY HOME (Email Finder)
# ==========================================
@app.route('/')
@login_required
def home():
    preload = request.args.get('url', '')
    body = '''<div style="max-width:700px;margin:20px auto;padding:20px">
<div style="background:white;padding:30px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1);margin-bottom:20px">
<h2 style="color:#333;margin-top:0">🔍 Email Finder (Shopify)</h2>
<p style="color:#666">Paste Shopify store URLs (one per line). Background job, batch of 100.</p>
<textarea id="urls" style="width:100%;height:180px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;box-sizing:border-box" placeholder="deluxura.shop&#10;hipchik.com">''' + preload.replace('<','&lt;') + '''</textarea>
<button onclick="startBackgroundSearch()" style="background:#667eea;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">🚀 Search All URLs</button>
<button onclick="importFromDiscovery()" style="background:#8b5cf6;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin-bottom:10px">📥 Import from Discovery</button>
<div id="result" style="margin-top:20px;background:#f8f9fa;padding:15px;border-radius:8px;min-height:40px"></div>
</div>
<div style="background:white;padding:20px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
<h3 style="margin-top:0">📋 Last 3 Jobs</h3>
<div id="jobsList">Loading...</div>
</div>
</div>
<script>
async function startBackgroundSearch(){
  const input=document.getElementById('urls').value;
  const result=document.getElementById('result');
  const stores=input.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(stores.length===0){alert('Enter URL');return}
  result.innerHTML='<p style="color:#666">⏳ Starting...</p>';
  try{
    const res=await fetch('/start-email-finder-job',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls: stores})});
    const data=await res.json();
    if(data.success){
      result.innerHTML='<div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:12px;border-radius:5px;color:#166534"><b>✅ Job #'+data.job_id+' started!</b> You can close the browser.</div>';
      document.getElementById('urls').value=''; loadJobs();
    } else { result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(data.error||'Unknown')+'</div>'; }
  }catch(e){result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e.message+'</div>'}
}
async function importFromDiscovery(){
  const result=document.getElementById('result');
  try{
    const res = await fetch('/get-discovered'); const data = await res.json();
    if(!data.stores || data.stores.length === 0){ result.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No discovered stores.</div>'; return; }
    const domains = data.stores.map(s=>s.domain);
    document.getElementById('urls').value = domains.join('\\n');
    result.innerHTML = '<div style="background:#f0fdf4;padding:10px;color:#166534">✅ Loaded '+domains.length+' URLs</div>';
  }catch(e){ result.innerHTML = '<div style="color:red">Error: '+e.message+'</div>'; }
}
async function loadJobs(){
  try{
    const res = await fetch('/get-email-finder-jobs'); const data = await res.json();
    const c = document.getElementById('jobsList');
    if(!data.jobs || data.jobs.length === 0){ c.innerHTML = '<p style="color:#666">No jobs yet.</p>'; return; }
    let html = '';
    data.jobs.forEach(j => {
      let color = j.status === 'completed' ? '#16a34a' : '#f59e0b';
      let icon = j.status === 'completed' ? '✅' : '🔄';
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+color+'">';
      html += '<b>'+icon+' Job #'+j.id+'</b> — '+j.emails+' emails from '+j.total+' stores<br>';
      html += '<button onclick="viewJob('+j.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-top:6px">View</button>';
      if(j.status === 'completed' && j.emails > 0){
        html += ' <button onclick="sendToVerify('+j.id+')" style="background:#f59e0b;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-top:6px">📨 Send to Verify</button>';
      }
      html += '<div id="job-'+j.id+'" style="display:none;margin-top:10px"></div></div>';
    });
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}
async function viewJob(id){
  const c = document.getElementById('job-'+id);
  if(c.style.display === 'block'){ c.style.display = 'none'; return; }
  c.innerHTML = '<p style="color:#666">Loading...</p>'; c.style.display = 'block';
  try{
    const res = await fetch('/get-email-finder-job/'+id); const data = await res.json();
    if(!data.results || data.results.length === 0){ c.innerHTML = '<p style="color:#666">No results yet.</p>'; return; }
    let html = '<div style="background:white;padding:10px;border-radius:6px;max-height:300px;overflow-y:auto;font-size:13px">';
    data.results.forEach(r => {
      html += '<div style="padding:8px 0;border-bottom:1px solid #eee"><b>'+r.store+'</b>';
      (r.emails||[]).forEach(e => { html += '<div style="padding-left:16px">📧 '+e+'</div>'; });
      html += '</div>';
    });
    c.innerHTML = html + '</div>';
  }catch(e){ c.innerHTML = '<p style="color:red">Error</p>'; }
}
async function sendToVerify(id){
  try{
    const res = await fetch('/get-email-finder-job/'+id); const data = await res.json();
    if(!data.results) return;
    const pairs = [];
    data.results.forEach(r => { (r.emails||[]).forEach(e => pairs.push({email: e, store: r.store || ''})); });
    if(pairs.length === 0){ alert('No emails'); return; }
    await fetch('/store-emails', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pairs: pairs})});
    alert('✅ Saved. Go to Verify → From Finder.');
  }catch(e){ alert('Error: '+e.message); }
}
window.onload = function(){ loadJobs(); setInterval(loadJobs, 5000); };
</script>'''
    return render_page("Finder", body)

@app.route('/start-email-finder-job', methods=['POST'])
@login_required
def start_email_finder_job():
    user_email = session.get('user_id')
    urls = request.json.get('urls', [])
    if not urls: return jsonify({'success': False, 'error': 'No URLs'})
    conn = get_db()
    if not conn: return jsonify({'success': False, 'error': 'No DB'})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO email_finder_master (user_email, total, status) VALUES (%s, %s, 'running') RETURNING id", (user_email, len(urls)))
        master_id = cur.fetchone()[0]
        for i in range(0, len(urls), 100):
            chunk = urls[i:i+100]
            cur.execute("""INSERT INTO email_finder_subjobs (master_id, user_email, sub_index, total, remaining_urls, results, status)
                VALUES (%s, %s, %s, %s, %s, '[]', 'pending')""",
                (master_id, user_email, i//100, len(chunk), '|||'.join(chunk)))
        conn.commit(); cur.close()
    finally: release_db(conn)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM email_finder_subjobs WHERE master_id=%s ORDER BY sub_index ASC LIMIT 1", (master_id,))
            row = cur.fetchone(); cur.close()
        finally: release_db(conn)
        if row: threading.Thread(target=process_subjob, args=(row[0],), daemon=True).start()
    return jsonify({'success': True, 'job_id': master_id, 'total': len(urls)})

@app.route('/get-email-finder-jobs')
@login_required
def get_email_finder_jobs_route():
    return jsonify({'jobs': get_email_finder_masters(session.get('user_id'))})

@app.route('/get-email-finder-job/<int:job_id>')
@login_required
def get_email_finder_job_route(job_id):
    detail = get_email_finder_master_detail(job_id, session.get('user_id'))
    return jsonify(detail or {'results': [], 'subjobs': []})

@app.route('/store-emails', methods=['POST'])
@login_required
def store_emails():
    user_email = session.get('user_id')
    data = request.json
    pairs = data.get('pairs', [])
    if pairs:
        items = []
        for p in pairs:
            e = p.get('email', '').strip().lower()
            s = (p.get('store', '') or '').strip().lower()
            if e: items.append(f"{e}:::{s}" if s else e)
        if user_email: save_user_state(user_email, found_emails='|||'.join(items))
    return jsonify({'success': True})

# ==========================================
# SHOPIFY DISCOVERY
# ==========================================
@app.route('/discover')
@login_required
def discover_page():
    user_email = session.get('user_id')
    hf_offset = get_hf_offset(user_email)
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#8b5cf6;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">🎯 Shopify Store Discovery</h1></div>
<div style="background:linear-gradient(135deg,#ff7e5f,#feb47b);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📦 Import from Hugging Face</h3>
<div style="display:flex;gap:8px;margin-top:10px">
<input type="number" id="hfCount" value="200" min="10" max="1000" style="padding:10px;border:none;border-radius:5px;font-size:15px;width:120px">
<button onclick="importFromHF()" style="background:white;color:#e85d3a;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-weight:bold">🔍 Import</button>
</div>
<div style="font-size:12px;margin-top:8px">Offset: <span id="currentOffset">''' + str(hf_offset) + '''</span>/10000</div>
<div id="hfStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">📋 Discovered (<span id="storeCount">0</span>)</h3>
<div id="storeList">Loading...</div>
<button onclick="sendAllToFinder()" style="background:#667eea;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-top:10px">📧 Send All to Finder</button>
<button onclick="clearStores()" style="background:#ef4444;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin-top:10px">🗑️ Clear</button>
</div>
</div>
<script>
async function importFromHF(){
  const count = parseInt(document.getElementById('hfCount').value) || 200;
  const status = document.getElementById('hfStatus');
  status.innerHTML = '<p style="color:white">⏳ Importing…</p>';
  try{
    const res = await fetch('/import-from-huggingface', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({count: count})});
    const data = await res.json();
    if(data.success){ status.innerHTML = '<p style="color:white">✅ '+data.added+' new</p>'; document.getElementById('currentOffset').textContent = data.offset_after; loadStores(); }
  }catch(e){ status.innerHTML = '<p style="color:white">Error</p>'; }
}
async function loadStores(){
  const res=await fetch('/get-discovered'); const data=await res.json();
  document.getElementById('storeCount').textContent = data.stores.length;
  const c=document.getElementById('storeList');
  if(data.stores.length===0){c.innerHTML='<p style="color:#666">None yet.</p>';return}
  let html='';
  data.stores.slice(0,50).forEach(s=>{ html+='<div style="padding:8px 0;border-bottom:1px solid #eee"><a href="https://'+s.domain+'" target="_blank">'+s.domain+'</a></div>'; });
  c.innerHTML=html;
}
async function sendAllToFinder(){
  const res = await fetch('/get-discovered'); const data = await res.json();
  if(!data.stores || data.stores.length===0){ alert('None'); return; }
  window.location.href = '/?url=' + encodeURIComponent(data.stores.map(s=>s.domain).join('\\n'));
}
async function clearStores(){ if(!confirm('Clear?')) return; await fetch('/clear-discovered',{method:'POST'}); loadStores(); }
window.onload = loadStores;
</script>'''
    return render_page("Discovery", body)

@app.route('/import-from-huggingface', methods=['POST'])
@login_required
def import_from_hf():
    user_email = session.get('user_id')
    count = int(request.json.get('count', 200))
    count = max(10, min(count, 1000))
    # Simplified — fetch a few rows and insert into discovered_stores
    try:
        url = f"https://datasets-server.huggingface.co/rows?dataset={requests.utils.quote(HF_DATASET)}&config=default&split=train&offset={get_hf_offset(user_email)}&length={count}"
        r = requests.get(url, timeout=20)
        if r.status_code != 200: return jsonify({'success': False, 'error': 'HF failed'})
        rows = r.json().get('rows', [])
        conn = get_db()
        if not conn: return jsonify({'success': False})
        added = 0; skipped = 0; seen = set()
        cur = conn.cursor()
        for item in rows:
            u = item.get('row', {}).get('url', '')
            clean = u.replace("https://","").replace("http://","").replace("www.","").split("/")[0].strip().lower()
            if not clean or '.' not in clean or clean in seen or clean in PLACEHOLDER_DOMAINS: skipped += 1; continue
            seen.add(clean)
            try:
                cur.execute("INSERT INTO discovered_stores (user_email, domain, source) VALUES (%s,%s,'huggingface') ON CONFLICT (user_email,domain) DO NOTHING", (user_email, clean))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except: skipped += 1
        conn.commit(); cur.close()
        new_off = get_hf_offset(user_email) + len(rows)
        set_hf_offset(user_email, new_off if new_off < 10000 else 0)
        return jsonify({'success': True, 'added': added, 'skipped': skipped, 'offset_after': new_off})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)[:200]})
    finally: release_db(conn)

@app.route('/get-discovered')
@login_required
def get_discovered():
    conn = get_db()
    if not conn: return jsonify({'stores': []})
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain, source, discovered_at FROM discovered_stores WHERE user_email = %s ORDER BY discovered_at DESC LIMIT 10000", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'stores': [{'domain': r[0], 'source': r[1], 'discovered_at': str(r[2])[:16]} for r in rows]})
    except: return jsonify({'stores': []})
    finally: release_db(conn)

@app.route('/clear-discovered', methods=['POST'])
@login_required
def clear_discovered():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM discovered_stores WHERE user_email = %s", (session.get('user_id'),))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

# ==========================================
# SHOPIFY VERIFY
# ==========================================
@app.route('/verify')
@login_required
def verify_page():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">✅ Verify Emails</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
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
async function loadFromFinder(){ const res=await fetch('/get-stored-emails'); const data=await res.json(); if(data.emails&&data.emails.length>0){ document.getElementById('emailsInput').value=data.emails.join('\\n'); alert('Loaded '+data.emails.length); } }
async function startBackgroundVerify(){ const emails=document.getElementById('emailsInput').value.split('\\n').map(s=>s.trim()).filter(s=>s.length>0); if(emails.length===0){alert('Enter emails');return} const name='Job '+new Date().toLocaleString(); try{ const res=await fetch('/verify-async',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails:emails,name:name})}); const data=await res.json(); if(data.success){ document.getElementById('startMsg').innerHTML='<p style="color:green">✅ Job #'+data.job_id+' started</p>'; refreshJobs(); } }catch(e){} }
async function refreshJobs(){ const res=await fetch('/verify-jobs'); const data=await res.json(); const c=document.getElementById('jobsList'); if(!data.jobs||data.jobs.length===0){c.innerHTML='<p style="color:#666">No jobs yet.</p>';return} let html=''; data.jobs.forEach(job=>{ const pct=job.total>0?Math.round((job.processed/job.total)*100):0; const sc=job.status==='completed'?'#0d9488':(job.status==='running'?'#f59e0b':'#ef4444'); html+='<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+sc+'"><b>'+job.name+'</b><div style="margin-top:8px;background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+pct+'%;height:16px;background:'+sc+';text-align:center;color:white;font-size:11px;line-height:16px">'+pct+'%</div></div><div style="font-size:13px;margin-top:6px">'+job.processed+'/'+job.total+' | ✅ '+job.valid+' | ❌ '+job.invalid+'</div></div>'; }); c.innerHTML=html; }
window.onload=function(){refreshJobs();setInterval(refreshJobs,10000)};
</script>'''
    return render_page("Verify", body)

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
        job_id = cur.fetchone()[0]; conn.commit(); cur.close()
    finally: release_db(conn)
    threading.Thread(target=background_verify_worker, args=(job_id,), daemon=True).start()
    return jsonify({'success': True, 'job_id': job_id, 'total': len(emails)})

def verify_email(email):
    try:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email): return email, False, "Invalid syntax"
        domain = email.split('@')[1]
        mx = resolve_mx(domain)
        if mx is None: return email, False, "No mail server"
        try:
            server = smtplib.SMTP(mx[0], timeout=3); server.ehlo()
            resp = server.verify(email); server.quit()
            return (email, True, "Valid") if resp[0] == 250 else (email, False, "May not exist")
        except: return email, True, "Valid (domain)"
    except: return email, False, "Unknown"

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
        chunk = remaining[:CHUNK_SIZE]; remaining = remaining[CHUNK_SIZE:]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
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
            cur.execute("""UPDATE verify_jobs SET processed=%s, valid_emails=%s, invalid_emails=%s, remaining_emails=%s, status=%s, updated_at=NOW() WHERE id=%s""",
                (len(valid)+len(invalid), '|||'.join(valid), '|||'.join(invalid), '|||'.join(remaining), new_status, job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    if user_email and valid: save_user_state(user_email, verified_emails='|||'.join(valid))

@app.route('/verify-jobs')
@login_required
def verify_jobs_list():
    conn = get_db()
    if not conn: return jsonify({'jobs': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, job_name, total, processed, status, created_at, valid_emails, invalid_emails
            FROM verify_jobs WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'jobs': [{'id': r[0], 'name': r[1], 'total': r[2], 'processed': r[3], 'status': r[4], 'created_at': str(r[5]), 'valid': len(r[6].split('|||')) if r[6] else 0, 'invalid': len(r[7].split('|||')) if r[7] else 0} for r in rows]})
    finally: release_db(conn)

@app.route('/get-stored-emails')
@login_required
def get_stored_emails():
    state = load_user_state(session.get('user_id'))
    emails = []
    for item in state.get('found_emails', []):
        if not item: continue
        if ':::' in item: emails.append(item.split(':::', 1)[0].strip())
        else: emails.append(item.strip())
    return jsonify({'emails': [e for e in emails if e]})

@app.route('/get-verified-emails')
@login_required
def get_verified_emails():
    conn = get_db()
    if not conn: return jsonify({'emails': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT valid_emails FROM verify_jobs WHERE user_email = %s AND status = 'completed' ORDER BY created_at DESC LIMIT 1""", (session.get('user_id'),))
        row = cur.fetchone(); cur.close()
        if row and row[0]: return jsonify({'emails': [e.strip() for e in row[0].split('|||') if e.strip()]})
        return jsonify({'emails': []})
    except: return jsonify({'emails': []})
    finally: release_db(conn)

# ==========================================
# SHOPIFY SCOUT
# ==========================================
@app.route('/scout')
@login_required
def scout():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#0d9488;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📨 Email Scout</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Recipients</h3>
<button onclick="loadFromVerified()" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;margin-bottom:10px">✅ From Verified</button>
<textarea id="emailsInput" style="width:100%;height:160px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<div id="emailCount" style="margin-top:10px;font-weight:bold">0 recipients</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">✍️ Template</h3>
<input type="text" id="subjectLine" placeholder="Subject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box">
<textarea id="messageBody" rows="5" placeholder="Message" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box"></textarea>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<button onclick="startCampaign()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">▶️ Start</button>
<button onclick="stopCampaign()" style="background:#ef4444;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">⏹️ Stop</button>
</div></div>
<script>
let recipients=[], scouted=0, isRunning=false;
window.onload = async function(){ const res = await fetch('/get-verified-emails'); const d = await res.json(); if(d.emails && d.emails.length > 0){ recipients = d.emails; document.getElementById('emailsInput').value = d.emails.join('\\n'); document.getElementById('emailCount').textContent = recipients.length + ' recipients'; } };
async function loadFromVerified(){ const res = await fetch('/get-verified-emails'); const d = await res.json(); if(d.emails && d.emails.length > 0){ document.getElementById('emailsInput').value = d.emails.join('\\n'); recipients = d.emails; document.getElementById('emailCount').textContent = recipients.length + ' recipients'; } else { alert('No verified emails'); } }
function startCampaign(){ const v = document.getElementById('emailsInput').value; recipients = v.split('\\n').map(s=>s.trim()).filter(s=>s.length>0); if(recipients.length===0){alert('None');return} isRunning=true; openNext(); }
function stopCampaign(){ isRunning=false; }
function openNext(){ if(!isRunning) return; if(scouted>=recipients.length){ isRunning=false; return; } const e=recipients[scouted]; const subj=document.getElementById('subjectLine').value; const body=document.getElementById('messageBody').value; window.location.href='mailto:'+e+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body); scouted++; }
document.addEventListener('visibilitychange', function(){ if(document.visibilityState === 'visible' && isRunning) setTimeout(openNext, 2000); });
</script>'''
    return render_page("Scout", body)

# ==========================================
# SHOPIFY AUDIT
# ==========================================
@app.route('/audit')
@login_required
def audit_page():
    user_email = session.get('user_id')
    sender_name = get_user_sender_name(user_email) or ''
    current_limit = get_send_limit(user_email)
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#65a30d;color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🚀 Analyze & Send (Shopify)</h1>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Import Emails</h3>
<button onclick="importFrom('finder')" style="background:#667eea;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">🔍 From Finder</button>
<button onclick="importFrom('verified')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">✅ From Verified</button>
<div id="importStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📋 Queue (<span id="queueCount">0</span>)</h3>
<div id="queueList" style="margin-top:12px">Loading...</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🚀 Process</h3>
<label style="font-weight:bold;font-size:13px">Your name:</label>
<input type="text" id="senderName" value="''' + sender_name.replace('"','') + '''" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;margin:5px 0 15px 0;box-sizing:border-box">
<button onclick="analyzeNext()" style="background:#3b82f6;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-size:15px">▶️ Analyze Next</button>
<div id="modeStatus" style="margin-top:10px"></div>
</div>
<div id="auditSection" style="display:none">
<div id="currentLabel" style="background:#65a30d;color:white;padding:10px;border-radius:8px;font-weight:bold;margin-bottom:15px"></div>
<div id="auditResult"></div>
<div id="outreachSection" style="display:none;background:white;padding:20px;border-radius:10px;margin-top:20px">
<h3 style="margin-top:0">✉️ Email</h3>
<label style="font-weight:bold">Subject:</label>
<input type="text" id="genSubject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin:5px 0 10px 0;box-sizing:border-box">
<label style="font-weight:bold">Message:</label>
<textarea id="genBody" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="sendCurrent()" style="background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px;margin-right:8px">📨 Send & Open Gmail</button>
<button onclick="skipCurrent()" style="background:#6b7280;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px">⏭️ Skip</button>
</div>
</div>
</div>
<script>
let currentItem = null, currentReport = null;

async function importFrom(source){
  const status = document.getElementById('importStatus');
  status.innerHTML = '<p style="color:#666">⏳ Importing…</p>';
  try{
    const res = await fetch('/import-to-queue', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({source: source})});
    const d = await res.json();
    if(d.success){ status.innerHTML = '<p style="color:green">✅ Added ' + d.added + ' (skipped ' + d.skipped + ')</p>'; loadQueue(); }
    else { status.innerHTML = '<p style="color:red">Error: ' + (d.error||'Unknown') + '</p>'; }
  }catch(e){ status.innerHTML = '<p style="color:red">Error: ' + e.message + '</p>'; }
}
async function loadQueue(){
  const res = await fetch('/get-audit-queue'); const d = await res.json();
  document.getElementById('queueCount').textContent = d.items.length;
  const c = document.getElementById('queueList');
  if(d.items.length === 0){ c.innerHTML = '<p style="color:#666">Queue empty.</p>'; return; }
  let html = '';
  d.items.forEach(i => {
    let color = i.status==='done'?'#16a34a':(i.status==='current'?'#3b82f6':(i.status==='skipped'?'#6b7280':'#f59e0b'));
    html += '<div style="padding:10px;border-radius:6px;margin:6px 0;background:#f9f9f9;border-left:4px solid '+color+'"><b>'+i.email+'</b><br><span style="color:#666;font-size:12px">'+i.domain+'</span></div>';
  });
  c.innerHTML = html;
}
async function analyzeNext(){
  const res = await fetch('/get-next-pending'); const d = await res.json();
  if(!d.item){ alert('Queue empty'); return; }
  currentItem = d.item;
  document.getElementById('auditSection').style.display='block';
  document.getElementById('auditResult').innerHTML='<p style="color:#666;padding:20px;text-align:center">⏳ Analyzing…</p>';
  document.getElementById('outreachSection').style.display='none';
  await fetch('/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id, status: 'current'})});
  try{
    const res = await fetch('/analyze-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id})});
    const d = await res.json();
    if(d.success){
      currentReport = d.item.report;
      document.getElementById('currentLabel').textContent = '📧 ' + d.item.email + ' → ' + d.item.domain;
      renderReport(d.item.report);
      document.getElementById('outreachSection').style.display='block';
      await genEmail();
      loadQueue();
    }
  }catch(e){ document.getElementById('auditResult').innerHTML = '<p style="color:red">Error: ' + e.message + '</p>'; }
}
function scoreBar(l,s){ const c = s>=75?'#16a34a':(s>=50?'#f59e0b':'#ef4444'); return '<div style="margin:10px 0"><b>'+l+'</b> <span style="color:'+c+';font-weight:bold">'+s+'%</span><div style="background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+s+'%;height:12px;background:'+c+'"></div></div></div>'; }
function renderReport(r){
  const sc = r.scores||{}, iss = r.issues||[];
  let h = '<div style="background:white;padding:20px;border-radius:10px;margin-bottom:15px"><h3 style="margin-top:0">Scores</h3>' + scoreBar('Overall', sc.overall_score||0) + scoreBar('Trust', sc.trust_score||0) + scoreBar('Technical', sc.technical_score||0) + scoreBar('Marketing', sc.marketing_score||0) + '</div>';
  if(iss.length > 0){ h += '<div style="background:white;padding:20px;border-radius:10px"><h3 style="margin-top:0;color:#991b1b">⚠️ Issues</h3>'; iss.forEach(i => { h += '<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:10px;border-radius:6px;margin:8px 0"><b>'+i.title+'</b><div style="font-size:13px">'+i.description+'</div></div>'; }); h += '</div>'; }
  document.getElementById('auditResult').innerHTML = h;
}
async function genEmail(){
  const res = await fetch('/generate-email', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({report: currentReport, tone: 'friendly', sender_name: document.getElementById('senderName').value, email: currentItem.email})});
  const d = await res.json();
  if(d.success){ document.getElementById('genSubject').value = d.subject; document.getElementById('genBody').value = d.body; }
}
async function sendCurrent(){
  if(!currentItem) return;
  await fetch('/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email: currentItem.email})});
  await fetch('/delete-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id})});
  loadQueue();
  window.location.href = 'mailto:' + currentItem.email + '?subject=' + encodeURIComponent(document.getElementById('genSubject').value) + '&body=' + encodeURIComponent(document.getElementById('genBody').value);
}
async function skipCurrent(){ if(!currentItem) return; await fetch('/update-queue-item',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id,status:'skipped'})}); document.getElementById('auditSection').style.display='none'; currentItem=null; loadQueue(); }
window.onload = loadQueue;
</script>'''
    return render_page("Analyze & Send", body)

@app.route('/get-audit-queue')
@login_required
def get_audit_queue_route():
    conn = get_db()
    if not conn: return jsonify({'items': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, email, domain, status FROM audit_queue WHERE user_email=%s
            ORDER BY CASE status WHEN 'pending' THEN 1 WHEN 'current' THEN 2 ELSE 3 END, added_at ASC""", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'items': [{'id': r[0], 'email': r[1], 'domain': r[2], 'status': r[3]} for r in rows]})
    finally: release_db(conn)

@app.route('/import-to-queue', methods=['POST'])
@login_required
def import_to_queue():
    user_email = session.get('user_id')
    source = request.json.get('source', '')
    pairs = []
    if source == 'finder': pairs = load_found_pairs(user_email, 'shopify')
    elif source == 'verified':
        state = load_user_state(user_email)
        emails = state.get('verified_emails', [])
        fp = load_found_pairs(user_email, 'shopify')
        e2s = {}
        for e, s in fp:
            if e not in e2s: e2s[e] = s
        for e in emails: pairs.append((e, e2s.get(e, '')))
    else: return jsonify({'success': False, 'error': 'Unknown source'})
    if not pairs: return jsonify({'success': False, 'error': 'No emails'})
    conn = get_db()
    if not conn: return jsonify({'success': False})
    added = skipped = 0
    try:
        cur = conn.cursor()
        for email, store in pairs:
            email = email.strip().lower()
            if not email or '@' not in email: continue
            store = (store or email).strip().lower()
            if store in PUBLIC_EMAIL_DOMAINS: store = email
            try:
                cur.execute("""INSERT INTO audit_queue (user_email, email, domain, status) VALUES (%s,%s,%s,'pending')
                    ON CONFLICT (user_email, email) DO NOTHING""", (user_email, email, store))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except: pass
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)
    return jsonify({'success': True, 'added': added, 'skipped': skipped})

@app.route('/update-queue-item', methods=['POST'])
@login_required
def update_queue_item_route():
    user_email = session.get('user_id')
    data = request.json; item_id = data.pop('id', None)
    if not item_id: return jsonify({'success': False})
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        for k, v in data.items():
            if v is not None: cur.execute(f"UPDATE audit_queue SET {k}=%s, updated_at=NOW() WHERE id=%s AND user_email=%s", (v, item_id, user_email))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

@app.route('/delete-queue-item', methods=['POST'])
@login_required
def delete_queue_item_route():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_queue WHERE id=%s AND user_email=%s", (request.json.get('id'), session.get('user_id')))
        conn.commit(); cur.close(); return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

@app.route('/mark-sent', methods=['POST'])
@login_required
def mark_sent_route():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO sent_log (user_email, email) VALUES (%s, %s) ON CONFLICT DO NOTHING", (session.get('user_id'), request.json.get('email','')))
        conn.commit(); cur.close(); return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

@app.route('/get-next-pending')
@login_required
def get_next_pending_route():
    conn = get_db()
    if not conn: return jsonify({'item': None})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain FROM audit_queue WHERE user_email=%s AND status='pending' ORDER BY added_at ASC LIMIT 1", (session.get('user_id'),))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'item': None})
        return jsonify({'item': {'id': row[0], 'email': row[1], 'domain': row[2]}})
    finally: release_db(conn)

@app.route('/analyze-queue-item', methods=['POST'])
@login_required
def analyze_queue_item():
    user_email = session.get('user_id')
    item_id = request.json.get('id')
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain, report FROM audit_queue WHERE id=%s AND user_email=%s", (item_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'success': False, 'error': 'Not found'})
        item_id, email, domain, report_json = row
        if report_json:
            try: report = json.loads(report_json) if isinstance(report_json, str) else report_json
            except: report = None
            if report: return jsonify({'success': True, 'item': {'id': item_id, 'email': email, 'domain': domain, 'report': report}})
    finally: release_db(conn)
    case_id = generate_case_id()
    report = audit_store(domain, case_id)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE audit_queue SET report=%s, status='current', updated_at=NOW() WHERE id=%s", (json.dumps(report), item_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    return jsonify({'success': True, 'item': {'id': item_id, 'email': email, 'domain': domain, 'report': report}})

@app.route('/generate-email', methods=['POST'])
@login_required
def generate_email_route():
    d = request.json
    report = d.get('report', {}); tone = d.get('tone', 'friendly')
    name = d.get('sender_name','').strip() or get_user_sender_name(session.get('user_id')) or ''
    email = d.get('email','').strip()
    if not report: return jsonify({'success': False})
    try:
        r = generate_outreach_email(report, tone, name, email)
        return jsonify({'success': True, 'subject': r['subject'], 'body': r['body']})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

# ==========================================
# WIX WAREHOUSE
# ==========================================
@app.route('/wix/ingest', methods=['GET', 'POST'])
def wix_ingest_route():
    header_secret = request.headers.get('X-Cron-Secret', '')
    cron_secret = os.environ.get('CRON_SECRET', '')
    valid_cron = bool(cron_secret) and header_secret == cron_secret
    valid_user = ('user_id' in session) and header_secret == 'MANUAL_FROM_UI'
    if not (valid_cron or valid_user): return jsonify({'status': 'error', 'error': 'forbidden'}), 403
    if valid_user and not valid_cron:
        try:
            import importlib, ingest_leadita
            importlib.reload(ingest_leadita)
            result = ingest_leadita.run(get_db, release_db)
            return jsonify(result), (200 if result.get('status') == 'ok' else 500)
        except Exception as e: return jsonify({'status': 'error', 'error': str(e)[:300]}), 500
    def _bg():
        try:
            import importlib, ingest_leadita
            importlib.reload(ingest_leadita)
            print(f"🕒 {ingest_leadita.run(get_db, release_db)}")
        except Exception as e: print(f"🕒 error: {e}")
    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({'status': 'accepted'}), 202

@app.route('/wix/warehouse')
@login_required
def wix_warehouse_status():
    conn = get_db()
    if not conn: return jsonify({'error': 'no db'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM wix_warehouse"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='pending'"); pending = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='processing'"); processing = cur.fetchone()[0]
        cur.execute("SELECT DATE(created_at) d, COUNT(*) c FROM wix_warehouse GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC LIMIT 14")
        daily = [{'date': str(r[0]), 'count': r[1]} for r in cur.fetchall()]
        cur.close()
        return jsonify({'total': total, 'pending': pending, 'processing': processing, 'daily_last_14': daily})
    except Exception as e: return jsonify({'error': str(e)[:200]}), 500
    finally: release_db(conn)

@app.route('/wix/request', methods=['POST'])
@login_required
def wix_request():
    n = int((request.get_json(silent=True) or {}).get('count', 500)); n = max(1, min(n, 5000))
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("""UPDATE wix_warehouse SET status='processing' WHERE id IN
            (SELECT id FROM wix_warehouse WHERE status='pending' ORDER BY created_at DESC LIMIT %s) RETURNING domain""", (n,))
        rows = cur.fetchall(); conn.commit(); cur.close()
        return jsonify({'success': True, 'pulled': len(rows), 'domains': [r[0] for r in rows]})
    except Exception as e: return jsonify({'success': False, 'error': str(e)[:200]})
    finally: release_db(conn)

@app.route('/wix/warehouse/reset', methods=['POST'])
@login_required
def wix_warehouse_reset():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("UPDATE wix_warehouse SET status='pending' WHERE status='processing'")
        n = cur.rowcount; conn.commit(); cur.close()
        return jsonify({'success': True, 'reset': n})
    except: return jsonify({'success': False})
    finally: release_db(conn)

# ==========================================
# WIX PAGES
# ==========================================
@app.route('/wix')
@login_required
def wix_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🔍 Wix Store Finder</h1>
<p style="margin:4px 0 0 0;font-size:14px;opacity:0.9">Warehouse · 500 fresh domains daily</p>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🏭 Warehouse</h3>
<div id="warehouseStats" style="background:#f3f4f6;padding:12px;border-radius:6px;margin:10px 0">Loading…</div>
<button onclick="ingestNow()" style="background:#7c3aed;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;width:100%;margin-bottom:10px">📥 Ingest Today's Batch</button>
<div style="display:flex;gap:8px">
<input type="number" id="wixPullCount" value="500" min="1" max="5000" style="flex:1;padding:10px;border:1px solid #ddd;border-radius:6px;box-sizing:border-box">
<button onclick="pullFromWarehouse()" style="flex:2;background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold">📧 Send to Wix Finder</button>
</div>
<button onclick="resetWarehouse()" style="background:#6b7280;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;margin-top:8px">🔄 Reset pulled rows to pending</button>
<div id="ingestStatus" style="margin-top:10px"></div>
<div id="pullStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">🎯 Wix Pipeline</h3>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/wix/finder" style="flex:1;min-width:120px;background:#0d9488;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">📧 Email Finder</a>
<a href="/wix/verify" style="flex:1;min-width:120px;background:#f59e0b;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">✅ Verify</a>
<a href="/wix/scout" style="flex:1;min-width:120px;background:#8b5cf6;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">📨 Scout</a>
<a href="/wix/audit" style="flex:1;min-width:120px;background:#65a30d;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">🚀 Audit</a>
</div>
</div>
</div>
<script>
async function loadWarehouseStats(){
  try{
    const r = await fetch('/wix/warehouse'); const d = await r.json();
    let rows = '';
    (d.daily_last_14||[]).slice(0,5).forEach(x => { rows += '<div>'+x.date+': <b>+'+x.count+'</b></div>'; });
    document.getElementById('warehouseStats').innerHTML = '<div><b>Total:</b> '+d.total+' | <b>Pending:</b> '+d.pending+' | <b>Processing:</b> '+d.processing+'</div><div style="margin-top:6px;color:#666">Last 5 days:</div>'+rows;
  }catch(e){ document.getElementById('warehouseStats').textContent = 'Error'; }
}
async function ingestNow(){
  const s = document.getElementById('ingestStatus');
  s.innerHTML = '<p style="color:#666">⏳ Ingesting…</p>';
  try{
    const r = await fetch('/wix/ingest', {method:'POST', headers:{'X-Cron-Secret': 'MANUAL_FROM_UI'}});
    const d = await r.json();
    if(d.status === 'ok'){ s.innerHTML = '<div style="color:#166534;background:#f0fdf4;padding:10px;border-radius:5px"><b>✅ +'+d.new+' new</b> (skipped '+d.duplicates_skipped+')</div>'; loadWarehouseStats(); }
    else { s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(d.error||'Unknown')+'</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">Error: '+e.message+'</div>'; }
}
async function pullFromWarehouse(){
  const s = document.getElementById('pullStatus');
  const n = parseInt(document.getElementById('wixPullCount').value) || 500;
  s.innerHTML = '<p style="color:#666">⏳ Pulling…</p>';
  try{
    const r = await fetch('/wix/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({count: n})});
    const d = await r.json();
    if(d.success && d.pulled > 0){ s.innerHTML = '<div style="color:#166534;background:#f0fdf4;padding:10px;border-radius:5px"><b>✅ Pulled '+d.pulled+'</b>. Redirecting…</div>'; sessionStorage.setItem('wix_pending_domains', d.domains.join('\\n')); setTimeout(()=>window.location.href='/wix/finder', 800); }
    else if(d.pulled === 0){ s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No pending rows.</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">Error: '+e.message+'</div>'; }
}
async function resetWarehouse(){ if(!confirm('Reset?')) return; const r = await fetch('/wix/warehouse/reset',{method:'POST'}); const d = await r.json(); if(d.success) { alert('✅ Reset '+d.reset+' rows'); loadWarehouseStats(); } }
window.onload = loadWarehouseStats;
</script>'''
    return render_page("Wix Store Finder", body)

@app.route('/wix/finder')
@login_required
def wix_finder_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📧 Wix Email Finder</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 URLs to Scan</h3>
<textarea id="urls" style="width:100%;height:200px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:13px;font-family:monospace;box-sizing:border-box" placeholder="example.wixsite.com"></textarea>
<button onclick="startFinder()" style="background:#0d9488;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">🚀 Find Emails (Background)</button>
<div id="result"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">📋 Last 3 Jobs</h3>
<div id="jobsList">Loading…</div>
</div>
</div>
<script>
window.onload = function(){
  const c = sessionStorage.getItem('wix_pending_domains');
  if(c){ document.getElementById('urls').value = c; sessionStorage.removeItem('wix_pending_domains'); }
  loadJobs(); setInterval(loadJobs, 5000);
};
async function startFinder(){
  const stores = document.getElementById('urls').value.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(stores.length===0){ alert('Enter URLs'); return; }
  const result = document.getElementById('result');
  result.innerHTML = '<p style="color:#666">⏳ Starting…</p>';
  try{
    const r = await fetch('/wix/start-email-finder-job', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({urls: stores})});
    const d = await r.json();
    if(d.success){ result.innerHTML = '<div style="color:#166534;background:#f0fdf4;padding:12px;border-radius:5px"><b>✅ Job #'+d.job_id+' started</b>. Close browser if you want.</div>'; document.getElementById('urls').value=''; loadJobs(); }
    else { result.innerHTML = '<div style="color:red">Error: '+(d.error||'Unknown')+'</div>'; }
  }catch(e){ result.innerHTML = '<div style="color:red">Error: '+e.message+'</div>'; }
}
async function loadJobs(){
  try{
    const r = await fetch('/wix/get-email-finder-jobs'); const d = await r.json();
    const c = document.getElementById('jobsList');
    if(!d.jobs || d.jobs.length===0){ c.innerHTML = '<p style="color:#666">No jobs yet.</p>'; return; }
    let html = '';
    d.jobs.forEach(j => {
      const color = j.status === 'completed' ? '#16a34a' : '#f59e0b';
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+color+'">';
      html += '<b>Job #'+j.id+'</b> — '+j.emails+' emails from '+j.total+' stores<br>';
      html += '<button onclick="viewJob('+j.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-top:6px">View</button>';
      if(j.status === 'completed' && j.emails > 0){
        html += ' <button onclick="toVerify('+j.id+')" style="background:#f59e0b;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-top:6px">→ Verify</button>';
      }
      html += '<div id="job-'+j.id+'" style="display:none;margin-top:10px"></div></div>';
    });
    c.innerHTML = html;
  }catch(e){}
}
async function viewJob(id){
  const c = document.getElementById('job-'+id);
  if(c.style.display === 'block'){ c.style.display='none'; return; }
  c.innerHTML = 'Loading…'; c.style.display='block';
  try{
    const r = await fetch('/wix/get-email-finder-job/'+id); const d = await r.json();
    if(!d.results || d.results.length === 0){ c.innerHTML = '<p style="color:#666">No results yet.</p>'; return; }
    let html = '<div style="background:white;padding:10px;border-radius:6px;max-height:300px;overflow-y:auto;font-size:13px">';
    d.results.forEach(r => {
      html += '<div style="padding:8px 0;border-bottom:1px solid #eee"><b>'+r.store+'</b>';
      (r.emails||[]).forEach(e => { html += '<div style="padding-left:14px">📧 '+e+'</div>'; });
      html += '</div>';
    });
    c.innerHTML = html + '</div>';
  }catch(e){ c.innerHTML = 'Error'; }
}
async function toVerify(id){
  try{
    const r = await fetch('/wix/get-email-finder-job/'+id); const d = await r.json();
    if(!d.results) return;
    const pairs = [];
    d.results.forEach(r => { (r.emails||[]).forEach(e => pairs.push({email:e, store:r.store||''})); });
    if(pairs.length === 0){ alert('No emails'); return; }
    await fetch('/wix/store-emails', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pairs: pairs})});
    alert('✅ '+pairs.length+' emails saved. Go to Wix Verify → From Finder.');
  }catch(e){ alert('Error: '+e.message); }
}
</script>'''
    return render_page("Wix Email Finder", body)

@app.route('/wix/start-email-finder-job', methods=['POST'])
@login_required
def wix_start_email_finder_job():
    user_email = session.get('user_id')
    urls = request.json.get('urls', [])
    if not urls: return jsonify({'success': False, 'error': 'No URLs'})
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_email_jobs (user_email, total, remaining_urls, results, status) VALUES (%s,%s,%s,'[]','pending') RETURNING id",
                    (user_email, len(urls), '|||'.join(urls)))
        job_id = cur.fetchone()[0]; conn.commit(); cur.close()
    finally: release_db(conn)
    threading.Thread(target=wix_process_subjob, args=(job_id,), daemon=True).start()
    return jsonify({'success': True, 'job_id': job_id, 'total': len(urls)})

@app.route('/wix/get-email-finder-jobs')
@login_required
def wix_get_email_jobs_route():
    return jsonify({'jobs': wix_get_email_jobs(session.get('user_id'))})

@app.route('/wix/get-email-finder-job/<int:job_id>')
@login_required
def wix_get_email_job_route(job_id):
    return jsonify(wix_get_email_job_detail(job_id, session.get('user_id')) or {'results': []})

@app.route('/wix/store-emails', methods=['POST'])
@login_required
def wix_store_emails():
    user_email = session.get('user_id')
    pairs = request.json.get('pairs', [])
    items = []
    for p in pairs:
        e = p.get('email', '').strip().lower()
        s = (p.get('store', '') or '').strip().lower()
        if e: items.append(f"{e}:::{s}" if s else e)
    if user_email and items: save_user_state(user_email, wix_found_emails='|||'.join(items))
    return jsonify({'success': True})

@app.route('/wix/get-wix-emails')
@login_required
def wix_get_emails():
    state = load_user_state(session.get('user_id'))
    emails = []
    for item in state.get('wix_found_emails', []):
        if not item: continue
        emails.append(item.split(':::', 1)[0].strip() if ':::' in item else item.strip())
    return jsonify({'emails': [e for e in emails if e]})

@app.route('/wix/verify')
@login_required
def wix_verify_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">✅ Wix Verify</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📋 Last 3 Jobs</h3>
<div id="jobsList">Loading…</div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<textarea id="emailsInput" style="width:100%;height:180px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="fromFinder()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px;margin-top:8px">📥 From Wix Finder</button>
<button onclick="startVerify()" style="background:#f59e0b;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-top:8px">▶️ Start Verify</button>
<div id="startMsg" style="margin-top:10px"></div>
</div></div>
<script>
async function fromFinder(){ const r = await fetch('/wix/get-wix-emails'); const d = await r.json(); if(d.emails && d.emails.length > 0){ document.getElementById('emailsInput').value = d.emails.join('\\n'); alert('Loaded '+d.emails.length); } else { alert('No Wix emails yet'); } }
async function startVerify(){ const emails = document.getElementById('emailsInput').value.split('\\n').map(s=>s.trim()).filter(s=>s.length>0); if(emails.length===0){ alert('Enter emails'); return; } const name = 'Wix Job '+new Date().toLocaleString(); try{ const r = await fetch('/wix/verify-async', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({emails: emails, name: name})}); const d = await r.json(); if(d.success){ document.getElementById('startMsg').innerHTML='<p style="color:green">✅ Job #'+d.job_id+' started</p>'; refreshJobs(); } }catch(e){} }
async function refreshJobs(){ const r = await fetch('/wix/verify-jobs'); const d = await r.json(); const c = document.getElementById('jobsList'); if(!d.jobs || d.jobs.length===0){ c.innerHTML='<p style="color:#666">No jobs yet.</p>'; return; } let html=''; d.jobs.forEach(j => { const pct = j.total>0?Math.round((j.processed/j.total)*100):0; const sc = j.status==='completed'?'#0d9488':(j.status==='running'?'#f59e0b':'#ef4444'); html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+sc+'"><b>'+j.name+'</b><div style="background:#e0e0e0;border-radius:8px;overflow:hidden;margin-top:8px"><div style="width:'+pct+'%;height:16px;background:'+sc+';text-align:center;color:white;font-size:11px;line-height:16px">'+pct+'%</div></div><div style="font-size:13px;margin-top:6px">'+j.processed+'/'+j.total+' | ✅ '+j.valid+' | ❌ '+j.invalid+'</div></div>'; }); c.innerHTML = html; }
window.onload = function(){ refreshJobs(); setInterval(refreshJobs, 10000); };
</script>'''
    return render_page("Wix Verify", body)

@app.route('/wix/verify-async', methods=['POST'])
@login_required
def wix_verify_async():
    user_email = session.get('user_id')
    d = request.json
    emails = d.get('emails', [])
    name = d.get('name', f"Wix Job {int(time.time())}")
    if not emails: return jsonify({'error': 'No emails'}), 400
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO wix_verify_jobs (user_email, job_name, total, remaining_emails, valid_emails, invalid_emails, status)
            VALUES (%s,%s,%s,%s,'','','pending') RETURNING id""", (user_email, name, len(emails), '|||'.join(emails)))
        job_id = cur.fetchone()[0]; conn.commit(); cur.close()
    finally: release_db(conn)
    threading.Thread(target=wix_verify_worker, args=(job_id,), daemon=True).start()
    return jsonify({'success': True, 'job_id': job_id, 'total': len(emails)})

def wix_verify_worker(job_id):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_emails, valid_emails, invalid_emails, user_email FROM wix_verify_jobs WHERE id=%s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        valid = row[1].split('|||') if row[1] else []
        invalid = row[2].split('|||') if row[2] else []
        user_email = row[3]
    finally: release_db(conn)
    CHUNK_SIZE = 100
    while remaining:
        chunk = remaining[:CHUNK_SIZE]; remaining = remaining[CHUNK_SIZE:]
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
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
            cur.execute("""UPDATE wix_verify_jobs SET processed=%s, valid_emails=%s, invalid_emails=%s, remaining_emails=%s, status=%s, updated_at=NOW() WHERE id=%s""",
                (len(valid)+len(invalid), '|||'.join(valid), '|||'.join(invalid), '|||'.join(remaining), new_status, job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)
    if user_email and valid: save_user_state(user_email, wix_verified_emails='|||'.join(valid))

@app.route('/wix/verify-jobs')
@login_required
def wix_verify_jobs_list():
    conn = get_db()
    if not conn: return jsonify({'jobs': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, job_name, total, processed, status, created_at, valid_emails, invalid_emails
            FROM wix_verify_jobs WHERE user_email=%s ORDER BY created_at DESC LIMIT 3""", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'jobs': [{'id': r[0], 'name': r[1], 'total': r[2], 'processed': r[3], 'status': r[4], 'created_at': str(r[5]), 'valid': len(r[6].split('|||')) if r[6] else 0, 'invalid': len(r[7].split('|||')) if r[7] else 0} for r in rows]})
    finally: release_db(conn)

@app.route('/wix/get-wix-verified-emails')
@login_required
def wix_get_verified_emails():
    state = load_user_state(session.get('user_id'))
    return jsonify({'emails': [e.strip() for e in state.get('wix_verified_emails', []) if e.strip()]})

@app.route('/wix/scout')
@login_required
def wix_scout_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#8b5cf6;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📨 Wix Scout</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Recipients</h3>
<button onclick="fromVerified()" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:13px;margin-bottom:10px">✅ From Wix Verified</button>
<textarea id="emailsInput" style="width:100%;height:160px;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<div id="count" style="margin-top:10px;font-weight:bold">0 recipients</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">✍️ Template</h3>
<input type="text" id="subjectLine" placeholder="Subject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box">
<textarea id="messageBody" rows="5" placeholder="Message" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box"></textarea>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<button onclick="start()" style="background:#8b5cf6;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">▶️ Start</button>
<button onclick="stop()" style="background:#ef4444;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">⏹️ Stop</button>
</div></div>
<script>
let recipients=[], i=0, running=false;
async function fromVerified(){ const r = await fetch('/wix/get-wix-verified-emails'); const d = await r.json(); if(d.emails && d.emails.length > 0){ document.getElementById('emailsInput').value = d.emails.join('\\n'); recipients = d.emails; document.getElementById('count').textContent = recipients.length+' recipients'; } else { alert('No verified Wix emails'); } }
function start(){ const v = document.getElementById('emailsInput').value; recipients = v.split('\\n').map(s=>s.trim()).filter(s=>s.length>0); if(recipients.length===0){ alert('None'); return; } running=true; i=0; next(); }
function stop(){ running=false; }
function next(){ if(!running) return; if(i >= recipients.length){ running=false; return; } const e = recipients[i]; const subj = document.getElementById('subjectLine').value; const body = document.getElementById('messageBody').value; window.location.href = 'mailto:' + e + '?subject=' + encodeURIComponent(subj) + '&body=' + encodeURIComponent(body); i++; }
document.addEventListener('visibilitychange', function(){ if(document.visibilityState==='visible' && running) setTimeout(next, 2000); });
</script>'''
    return render_page("Wix Scout", body)

@app.route('/wix/audit')
@login_required
def wix_audit_page():
    user_email = session.get('user_id')
    sender_name = get_user_sender_name(user_email) or ''
    current_limit = get_send_limit(user_email)
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#65a30d;color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🚀 Wix Analyze & Send</h1>
<p style="margin:4px 0 0 0;font-size:14px">Wix-specific audit — extracts top products from HTML</p>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Import Wix Emails</h3>
<button onclick="imp('finder')" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">🔍 From Wix Finder</button>
<button onclick="imp('verified')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px;font-size:13px">✅ From Wix Verified</button>
<div id="importStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📋 Queue (<span id="queueCount">0</span>)</h3>
<div id="queueList" style="margin-top:12px">Loading…</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🚀 Process</h3>
<label style="font-weight:bold;font-size:13px">Your name:</label>
<input type="text" id="senderName" value="''' + sender_name.replace('"','') + '''" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;margin:5px 0 15px 0;box-sizing:border-box">
<button onclick="analyzeNext()" style="background:#3b82f6;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-size:15px">▶️ Analyze Next</button>
<div id="status" style="margin-top:10px"></div>
</div>
<div id="auditSection" style="display:none">
<div id="label" style="background:#65a30d;color:white;padding:10px;border-radius:8px;font-weight:bold;margin-bottom:15px"></div>
<div id="result"></div>
<div id="outreach" style="display:none;background:white;padding:20px;border-radius:10px;margin-top:20px">
<h3 style="margin-top:0">✉️ Email</h3>
<label style="font-weight:bold">Subject:</label>
<input type="text" id="genSubject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin:5px 0 10px 0;box-sizing:border-box">
<label style="font-weight:bold">Message:</label>
<textarea id="genBody" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="sendIt()" style="background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px;margin-right:8px">📨 Send & Open Gmail</button>
<button onclick="skipIt()" style="background:#6b7280;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px">⏭️ Skip</button>
</div>
</div>
</div>
<script>
let currentItem = null, currentReport = null;
async function imp(source){
  const s = document.getElementById('importStatus');
  s.innerHTML = '<p style="color:#666">⏳ Importing…</p>';
  try{
    const r = await fetch('/wix/import-to-queue', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({source: source})});
    const d = await r.json();
    if(d.success){ s.innerHTML = '<p style="color:green">✅ Added '+d.added+' (skipped '+d.skipped+')</p>'; loadQueue(); }
    else { s.innerHTML = '<p style="color:red">Error: '+(d.error||'Unknown')+'</p>'; }
  }catch(e){ s.innerHTML = '<p style="color:red">Error: '+e.message+'</p>'; }
}
async function loadQueue(){
  const r = await fetch('/wix/get-audit-queue'); const d = await r.json();
  document.getElementById('queueCount').textContent = d.items.length;
  const c = document.getElementById('queueList');
  if(d.items.length === 0){ c.innerHTML = '<p style="color:#666">Queue empty.</p>'; return; }
  let html = '';
  d.items.forEach(i => {
    const color = i.status==='done'?'#16a34a':(i.status==='current'?'#3b82f6':(i.status==='skipped'?'#6b7280':'#f59e0b'));
    html += '<div style="padding:10px;border-radius:6px;margin:6px 0;background:#f9f9f9;border-left:4px solid '+color+'"><b>'+i.email+'</b><br><span style="color:#666;font-size:12px">'+i.domain+'</span></div>';
  });
  c.innerHTML = html;
}
async function analyzeNext(){
  const r = await fetch('/wix/get-next-pending'); const d = await r.json();
  if(!d.item){ alert('Queue empty'); return; }
  currentItem = d.item;
  document.getElementById('auditSection').style.display='block';
  document.getElementById('result').innerHTML='<p style="color:#666;padding:20px;text-align:center">⏳ Analyzing Wix store… (extracts top products)</p>';
  document.getElementById('outreach').style.display='none';
  await fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id, status:'current'})});
  try{
    const r = await fetch('/wix/analyze-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id})});
    const d = await r.json();
    if(d.success){
      currentReport = d.item.report;
      document.getElementById('label').textContent = '📧 '+d.item.email+' → '+d.item.domain;
      renderReport(d.item.report);
      document.getElementById('outreach').style.display='block';
      await genEmail();
      loadQueue();
    } else { document.getElementById('result').innerHTML = '<p style="color:red">Error</p>'; }
  }catch(e){ document.getElementById('result').innerHTML = '<p style="color:red">Error: '+e.message+'</p>'; }
}
function bar(l,s){ const c = s>=75?'#16a34a':(s>=50?'#f59e0b':'#ef4444'); return '<div style="margin:10px 0"><b>'+l+'</b> <span style="color:'+c+';font-weight:bold">'+s+'%</span><div style="background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+s+'%;height:12px;background:'+c+'"></div></div></div>'; }
function renderReport(r){
  const sc = r.scores||{}, iss = r.issues||[], prods = r.top_products||[];
  let h = '<div style="background:white;padding:20px;border-radius:10px;margin-bottom:15px"><h3 style="margin-top:0">Scores</h3>'+bar('Overall', sc.overall_score||0)+bar('Trust', sc.trust_score||0)+bar('Technical', sc.technical_score||0)+bar('Marketing', sc.marketing_score||0)+'</div>';
  if(prods.length > 0){ h += '<div style="background:white;padding:20px;border-radius:10px;margin-bottom:15px"><h3 style="margin-top:0">🛍️ Top Products Detected</h3>'; prods.forEach(p => { h += '<div style="padding:8px 0;border-bottom:1px solid #eee"><b>'+p.title+'</b>'+(p.price?' — '+p.price:'')+'</div>'; }); h += '</div>'; }
  if(iss.length > 0){ h += '<div style="background:white;padding:20px;border-radius:10px"><h3 style="margin-top:0;color:#991b1b">⚠️ Issues</h3>'; iss.forEach(i => { h += '<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:10px;border-radius:6px;margin:8px 0"><b>'+i.title+'</b><div style="font-size:13px">'+i.description+'</div></div>'; }); h += '</div>'; }
  document.getElementById('result').innerHTML = h;
}
async function genEmail(){
  const r = await fetch('/wix/generate-email', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({report: currentReport, tone:'friendly', sender_name: document.getElementById('senderName').value, email: currentItem.email})});
  const d = await r.json();
  if(d.success){ document.getElementById('genSubject').value = d.subject; document.getElementById('genBody').value = d.body; }
}
async function sendIt(){
  if(!currentItem) return;
  await fetch('/wix/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email: currentItem.email})});
  await fetch('/wix/delete-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id: currentItem.id})});
  loadQueue();
  window.location.href = 'mailto:' + currentItem.email + '?subject=' + encodeURIComponent(document.getElementById('genSubject').value) + '&body=' + encodeURIComponent(document.getElementById('genBody').value);
}
async function skipIt(){ if(!currentItem) return; await fetch('/wix/update-queue-item',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:currentItem.id,status:'skipped'})}); document.getElementById('auditSection').style.display='none'; currentItem=null; loadQueue(); }
window.onload = loadQueue;
</script>'''
    return render_page("Wix Analyze & Send", body)

@app.route('/wix/import-to-queue', methods=['POST'])
@login_required
def wix_import_to_queue():
    user_email = session.get('user_id')
    source = request.json.get('source', '')
    pairs = []
    if source == 'finder': pairs = load_found_pairs(user_email, 'wix')
    elif source == 'verified':
        state = load_user_state(user_email)
        emails = state.get('wix_verified_emails', [])
        fp = load_found_pairs(user_email, 'wix')
        e2s = {}
        for e, s in fp:
            if e not in e2s: e2s[e] = s
        for e in emails: pairs.append((e, e2s.get(e, '')))
    else: return jsonify({'success': False, 'error': 'Unknown source'})
    if not pairs: return jsonify({'success': False, 'error': 'No emails'})
    conn = get_db()
    if not conn: return jsonify({'success': False})
    added = skipped = 0
    try:
        cur = conn.cursor()
        for email, store in pairs:
            email = email.strip().lower()
            if not email or '@' not in email: continue
            store = (store or email).strip().lower()
            if store in PUBLIC_EMAIL_DOMAINS: store = email
            try:
                cur.execute("""INSERT INTO wix_audit_queue (user_email, email, domain, status) VALUES (%s,%s,%s,'pending')
                    ON CONFLICT (user_email, email) DO NOTHING""", (user_email, email, store))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except: pass
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)
    return jsonify({'success': True, 'added': added, 'skipped': skipped})

@app.route('/wix/get-audit-queue')
@login_required
def wix_get_audit_queue():
    conn = get_db()
    if not conn: return jsonify({'items': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, email, domain, status FROM wix_audit_queue WHERE user_email=%s
            ORDER BY CASE status WHEN 'pending' THEN 1 WHEN 'current' THEN 2 ELSE 3 END, added_at ASC""", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'items': [{'id': r[0], 'email': r[1], 'domain': r[2], 'status': r[3]} for r in rows]})
    finally: release_db(conn)

@app.route('/wix/update-queue-item', methods=['POST'])
@login_required
def wix_update_queue_item():
    user_email = session.get('user_id')
    d = request.json; item_id = d.pop('id', None)
    if not item_id: return jsonify({'success': False})
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        for k, v in d.items():
            if v is not None: cur.execute(f"UPDATE wix_audit_queue SET {k}=%s, updated_at=NOW() WHERE id=%s AND user_email=%s", (v, item_id, user_email))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

@app.route('/wix/delete-queue-item', methods=['POST'])
@login_required
def wix_delete_queue_item():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM wix_audit_queue WHERE id=%s AND user_email=%s", (request.json.get('id'), session.get('user_id')))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

@app.route('/wix/get-next-pending')
@login_required
def wix_get_next_pending():
    conn = get_db()
    if not conn: return jsonify({'item': None})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain FROM wix_audit_queue WHERE user_email=%s AND status='pending' ORDER BY added_at ASC LIMIT 1", (session.get('user_id'),))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'item': None})
        return jsonify({'item': {'id': row[0], 'email': row[1], 'domain': row[2]}})
    finally: release_db(conn)

@app.route('/wix/analyze-queue-item', methods=['POST'])
@login_required
def wix_analyze_queue_item():
    user_email = session.get('user_id')
    item_id = request.json.get('id')
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain, report FROM wix_audit_queue WHERE id=%s AND user_email=%s", (item_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'success': False, 'error': 'Not found'})
        item_id, email, domain, report_json = row
        if report_json:
            try: report = json.loads(report_json) if isinstance(report_json, str) else report_json
            except: report = None
            if report: return jsonify({'success': True, 'item': {'id': item_id, 'email': email, 'domain': domain, 'report': report}})
    finally: release_db(conn)
    case_id = generate_case_id()
    report = audit_store_wix(domain, case_id)
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_audit_queue SET report=%s, status='current', updated_at=NOW() WHERE id=%s", (json.dumps(report), item_id))
            cur.execute("INSERT INTO wix_audit_history (user_email, domain, report) VALUES (%s,%s,%s)", (user_email, domain, json.dumps(report)))
            conn.commit(); cur.close()
        finally: release_db(conn)
    return jsonify({'success': True, 'item': {'id': item_id, 'email': email, 'domain': domain, 'report': report}})

@app.route('/wix/generate-email', methods=['POST'])
@login_required
def wix_generate_email():
    d = request.json
    report = d.get('report', {}); tone = d.get('tone', 'friendly')
    name = d.get('sender_name','').strip() or get_user_sender_name(session.get('user_id')) or ''
    email = d.get('email','').strip()
    if not report: return jsonify({'success': False})
    try:
        r = generate_outreach_email_wix(report, tone, name, email)
        return jsonify({'success': True, 'subject': r['subject'], 'body': r['body']})
    except Exception as e: return jsonify({'success': False, 'error': str(e)})

@app.route('/wix/mark-sent', methods=['POST'])
@login_required
def wix_mark_sent():
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_sent_log (user_email, email) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    (session.get('user_id'), request.json.get('email','')))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

# ==========================================
# STARTUP
# ==========================================
try:
    resume_unfinished_masters()
except Exception as e:
    print(f"⚠️ resume: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
