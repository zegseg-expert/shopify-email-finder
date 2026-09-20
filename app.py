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
# MEMORY FIX: Reduced worker count
# ==========================================
MAX_WORKERS = 10

# ==========================================
# DEFAULT SESSION SEND LIMIT (users can override)
# ==========================================
DEFAULT_SEND_LIMIT = 70

# ==========================================
# PUBLIC EMAIL PROVIDERS
# ==========================================
PUBLIC_EMAIL_DOMAINS = {
    'gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com',
    'live.com','msn.com','protonmail.com','proton.me','mail.com','yandex.com',
    'zoho.com','gmx.com','gmx.net','me.com','mac.com','qq.com','163.com'
}

# ==========================================
# PLACEHOLDER DOMAINS (blocked on import)
# ==========================================
PLACEHOLDER_DOMAINS = {
    'yourstore.com','example.com','example.org','example.net','domain.com',
    'yoursite.com','mysite.com','sitename.com','site.com','test.com',
    'mystore.com','store.com','shop.com','company.com','website.com'
}

# ==========================================
# WIX DISCOVERY CONFIG
# ==========================================
WIX_CATEGORIES = [
    "fashion", "jewelry", "toys", "home-decor",
    "beauty", "food", "accessories", "gifts"
]

# Common Crawl indexes to query (6 months of coverage)
CC_INDEXES = [
    "CC-MAIN-2024-44", "CC-MAIN-2024-40", "CC-MAIN-2024-33",
    "CC-MAIN-2024-26", "CC-MAIN-2024-18", "CC-MAIN-2024-10"
]

# URL patterns that only exist on real Wix Stores
WIX_STORE_PATTERNS = [
    "*/product-page/*",
    "*/shop/*",
    "*/store/*"
]

# Signals that prove a page is a real Wix Store
WIX_STORE_SIGNALS = [
    'wixstores',
    'wix-ecom',
    'product-page',
    'add-to-cart',
    'add_to_cart',
    'shopping-cart',
    'wixstore',
    'wixstorefront'
]

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
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS session_sent_count INTEGER DEFAULT 0")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS session_started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS send_limit INTEGER DEFAULT 70")
        except: pass
        # ===== WIX COLUMNS (ADDITIVE) =====
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_found_emails TEXT")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_verified_emails TEXT")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_scout_recipients TEXT")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_scout_subject TEXT")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_scout_message TEXT")
        except: pass
        try: cur.execute("ALTER TABLE user_state ADD COLUMN IF NOT EXISTS wix_session_sent_count INTEGER DEFAULT 0")
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
            requested INTEGER DEFAULT 0,
            added INTEGER DEFAULT 0,
            skipped INTEGER DEFAULT 0,
            offset_before INTEGER DEFAULT 0,
            offset_after INTEGER DEFAULT 0,
            domains TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
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
            product_count INTEGER DEFAULT 0,
            categories TEXT, vendors TEXT, tags TEXT,
            sold_out_count INTEGER DEFAULT 0,
            bestsellers TEXT,
            crawled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        # ===== WIX WAREHOUSE TABLE =====
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_warehouse (
            id BIGSERIAL PRIMARY KEY,
            url TEXT UNIQUE NOT NULL,
            domain TEXT NOT NULL,
            source TEXT,
            title TEXT,
            country TEXT,
            status TEXT DEFAULT 'pending',
            seo_score INTEGER,
            tech_spend INTEGER,
            crawled_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            verified_at TIMESTAMPTZ,
            audited_at TIMESTAMPTZ,
            notes TEXT)""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wix_warehouse_status ON wix_warehouse(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_wix_warehouse_created ON wix_warehouse(created_at DESC)")
        # ===== WIX PIPELINE TABLES =====
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_email_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            emails_found INTEGER DEFAULT 0,
            status VARCHAR(50) DEFAULT 'pending',
            remaining_urls TEXT, results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_verify_jobs (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            job_name VARCHAR(255), total INTEGER DEFAULT 0, processed INTEGER DEFAULT 0,
            valid_emails TEXT, invalid_emails TEXT, remaining_emails TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_audit_queue (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL, domain VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            report JSONB, subject TEXT, message TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_email, email))""")
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_sent_log (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        try: cur.execute("UPDATE wix_audit_queue SET status='pending', updated_at=NOW() WHERE status='current'")
        except: pass
        n = cur.rowcount
        conn.commit(); cur.close()
        if n > 0:
            print(f"🔄 Reset {n} stuck 'current' queue items to 'pending'")
    except Exception as e:
        print(f"⚠️ reset_stuck_current_items: {e}")
    finally: release_db(conn)

try:
    reset_stuck_current_items()
except Exception as e:
    print(f"⚠️ reset_stuck_current_items startup: {e}")

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

def load_found_pairs(user_email):
    state = load_user_state(user_email)
    pairs = []
    for item in state.get('found_emails', []):
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
# SESSION SEND COUNTER + LIMIT
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
        new_count = cur.fetchone()[0]
        conn.commit(); cur.close()
        return new_count
    except Exception as e:
        print(f"increment_session_sent_count: {e}")
        return 0
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
    except Exception as e:
        print(f"set_send_limit: {e}")
        return False
    finally: release_db(conn)

def counter_status(user_email):
    count = get_session_sent_count(user_email)
    limit = get_send_limit(user_email)
    at_milestone = (count > 0 and count % limit == 0)
    next_milestone = ((count // limit) + 1) * limit
    return {
        'count': count,
        'limit': limit,
        'next_milestone': next_milestone,
        'at_milestone': at_milestone
    }

# ==========================================
# CATALOGUE CRAWLER (Shopify)
# ==========================================
def get_cached_catalogue(domain, max_age_hours=24):
    conn = get_db()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("""SELECT product_count, categories, vendors, tags, sold_out_count, bestsellers
            FROM store_catalogues WHERE domain = %s
            AND crawled_at > NOW() - INTERVAL '%s hours'""", (domain, max_age_hours))
        row = cur.fetchone(); cur.close()
        if not row: return None
        return {
            'product_count': row[0] or 0,
            'categories': row[1].split('|||') if row[1] else [],
            'vendors': row[2].split('|||') if row[2] else [],
            'tags': row[3].split('|||') if row[3] else [],
            'sold_out_count': row[4] or 0,
            'bestsellers': json.loads(row[5]) if row[5] else []
        }
    except: return None
    finally: release_db(conn)

def save_catalogue_cache(domain, cat):
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO store_catalogues
            (domain, product_count, categories, vendors, tags, sold_out_count, bestsellers, crawled_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (domain) DO UPDATE SET
                product_count=EXCLUDED.product_count,
                categories=EXCLUDED.categories,
                vendors=EXCLUDED.vendors,
                tags=EXCLUDED.tags,
                sold_out_count=EXCLUDED.sold_out_count,
                bestsellers=EXCLUDED.bestsellers,
                crawled_at=NOW()""",
            (domain,
             cat.get('product_count', 0),
             '|||'.join(cat.get('categories', [])),
             '|||'.join(cat.get('vendors', [])),
             '|||'.join(cat.get('tags', [])),
             cat.get('sold_out_count', 0),
             json.dumps(cat.get('bestsellers', []))))
        conn.commit(); cur.close()
    except Exception as e:
        print(f"save_catalogue_cache: {e}")
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
        data = r.json()
        products = data.get('products', [])
        if not products: return None

        categories = {}
        vendors = {}
        tags = {}
        sold_out = 0
        product_details = []

        for p in products:
            pt = (p.get('product_type') or 'Uncategorized').strip()
            if pt: categories[pt] = categories.get(pt, 0) + 1

            v = (p.get('vendor') or 'Unknown').strip()
            if v: vendors[v] = vendors.get(v, 0) + 1

            for t in p.get('tags', [])[:5]:
                t = (t or '').strip()
                if t: tags[t] = tags.get(t, 0) + 1

            variants = p.get('variants', [])
            if any(not v.get('available', True) for v in variants):
                sold_out += 1

            product_details.append({
                'title': (p.get('title') or '')[:80],
                'variants': len(variants),
                'price': variants[0].get('price', '') if variants else ''
            })

        top_categories = [c[0] for c in sorted(categories.items(), key=lambda x: -x[1])[:5]]
        top_vendors = [v[0] for v in sorted(vendors.items(), key=lambda x: -x[1])[:5]]
        top_tags = [t[0] for t in sorted(tags.items(), key=lambda x: -x[1])[:10]]
        bestsellers = sorted(product_details, key=lambda x: -x['variants'])[:5]

        result = {
            'product_count': len(products),
            'categories': top_categories,
            'vendors': top_vendors,
            'tags': top_tags,
            'sold_out_count': sold_out,
            'bestsellers': bestsellers
        }
        save_catalogue_cache(domain, result)
        return result
    except Exception as e:
        print(f"crawl_catalogue({domain}): {e}")
        return None

# ==========================================
# EMAIL FINDER BACKGROUND JOBS (Shopify)
# ==========================================
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
        master_id = row[2]
        sub_index = row[3]
        user_email = row[4]
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
            cur.execute("""UPDATE email_finder_subjobs SET processed=%s, emails_found=%s,
                results=%s, remaining_urls=%s, status=%s WHERE id=%s""",
                (len(results), total, json.dumps(results), '|||'.join(remaining),
                 'running' if remaining else 'completed', subjob_id))
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
                    rows = cur.fetchall()
                    for r in rows:
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
                    for e in r.get('emails', []):
                        pairs.append(f"{e}:::{store}")
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
        cur.execute("""SELECT id, total, emails_found, status, created_at
            FROM email_finder_master WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (user_email,))
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
                subs = cur2.fetchall(); cur2.close()
                for s in subs:
                    if s[0]:
                        try: results.extend(json.loads(s[0]))
                        except: pass
            finally: release_db(conn2)
        return {'results': results, 'status': row[2], 'total': row[1]}
    except: return None
    finally: release_db(conn)

# ==========================================
# HUGGING FACE IMPORT (Shopify)
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
            if clean in PLACEHOLDER_DOMAINS: skipped += 1; continue
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
# WIX DISCOVERY - Common Crawl CDX (6 indexes × 3 patterns)
# ==========================================
def is_wix_site(html):
    if not html: return False
    low = html.lower()
    return any(x in low for x in [
        'wix.com', 'wixstatic.com', 'wix-code', 'wixstores',
        '_wixcss', 'parastorage.com', 'wixsite.com'
    ])

def has_wix_store_signals(html):
    if not html: return False
    low = html.lower()
    return any(sig in low for sig in WIX_STORE_SIGNALS)

def verify_wix_store(domain, timeout=8):
    """Fetch homepage and check for Wix + Store signals."""
    try:
        domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
        if not domain or '.' not in domain: return False, ''
        url = f"https://{domain}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if r.status_code != 200:
            return False, ''
        html = r.text
        if not is_wix_site(html):
            return False, ''
        if not has_wix_store_signals(html):
            return False, ''
        # Determine country from final URL or HTML
        country = detect_country(r.url, html)
        return True, country
    except Exception as e:
        print(f"verify_wix_store({domain}): {e}")
        return False, ''

def detect_country(url, html):
    """Very lightweight country detection."""
    low_url = (url or '').lower()
    low_html = (html or '').lower()[:20000]
    if '.co.uk' in low_url or '£' in low_html or 'gbp' in low_html: return 'UK'
    if '.ca' in low_url or 'cad' in low_html: return 'CA'
    if '.com.au' in low_url or 'aud' in low_html: return 'AU'
    if '.de' in low_url or 'eur' in low_html: return 'EU'
    return 'US'

def save_wix_stores(user_email, stores):
    conn = get_db()
    if not conn: return 0
    saved = 0
    try:
        cur = conn.cursor()
        for store in stores:
            try:
                cur.execute("""INSERT INTO wix_stores (user_email, domain, source, country)
                    VALUES (%s, %s, %s, %s) ON CONFLICT (user_email, domain) DO NOTHING""",
                    (user_email, store['domain'], store.get('source', 'unknown'), store.get('country', '')))
                if cur.rowcount > 0: saved += 1
            except: pass
        conn.commit(); cur.close()
    except: pass
    finally: release_db(conn)
    return saved

def query_cc_index(index_name, pattern, limit=50):
    """Query one Common Crawl index for one URL pattern. Returns list of domains."""
    discovered = []
    seen = set()
    try:
        query_url = f"*.wixsite.com/{pattern}"
        api = f"https://index.commoncrawl.org/{index_name}-index?url={requests.utils.quote(query_url)}&output=json&limit={limit}"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; WixDiscovery/1.0)"}
        r = requests.get(api, headers=headers, timeout=30)
        if r.status_code != 200:
            return []
        for line in r.text.strip().split("\n"):
            if not line.strip(): continue
            try:
                data = json.loads(line)
                raw = data.get('url', '')
                clean = raw.replace("https://", "").replace("http://", "").split("/")[0].strip().lower()
                if not clean or '.' not in clean: continue
                if not clean.endswith('.wixsite.com'): continue
                if clean in seen: continue
                seen.add(clean)
                discovered.append(clean)
            except: continue
    except Exception as e:
        print(f"  ⚠️ CC [{index_name}/{pattern}]: {e}")
    return discovered

def discover_wix_via_commoncrawl_all():
    """Query all 6 indexes × 3 store patterns = 18 queries. Returns unique domains."""
    all_domains = set()
    for index_name in CC_INDEXES:
        for pattern in WIX_STORE_PATTERNS:
            try:
                domains = query_cc_index(index_name, pattern, limit=50)
                all_domains.update(domains)
                print(f"  📡 {index_name} / {pattern}: {len(domains)} (total unique: {len(all_domains)})")
            except Exception as e:
                print(f"  ⚠️ {index_name}/{pattern}: {e}")
            time.sleep(1)
    return [{'domain': d, 'source': 'wix_cc'} for d in all_domains]

def discover_wix_via_related(user_email, seeds_limit=8):
    discovered = []; seen_roots = set()
    conn = get_db()
    if not conn: return discovered
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain FROM wix_stores WHERE user_email = %s ORDER BY discovered_at DESC LIMIT %s", (user_email, seeds_limit))
        seeds = [r[0] for r in cur.fetchall()]; cur.close()
    finally: release_db(conn)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for seed in seeds:
        try:
            r = requests.get(f"https://{seed}", headers=headers, timeout=8)
            if r.status_code != 200: continue
            if not is_wix_site(r.text): continue
            for ext in re.findall(r'href="https?://([a-zA-Z0-9\.\-]+\.wixsite\.com)', r.text)[:20]:
                if ext in seen_roots or ext == seed: continue
                seen_roots.add(ext)
                discovered.append({'domain': ext, 'source': 'wix_related'})
        except: continue
    return discovered

def background_wix_discovery(job_id):
    print(f"🛍️ Wix discovery job #{job_id} started")
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT user_email FROM wix_discovery_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        user_email = row[0]
    finally: release_db(conn)

    # Phase 1: Common Crawl query (all indexes × patterns)
    print(f"  🔎 Phase 1: querying {len(CC_INDEXES)} indexes × {len(WIX_STORE_PATTERNS)} patterns")
    candidates = discover_wix_via_commoncrawl_all()
    print(f"  ✅ Found {len(candidates)} candidate domains")

    # Update progress
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_discovery_jobs SET total=%s, processed=%s, found=%s, status='running', updated_at=NOW() WHERE id=%s",
                        (len(candidates), 1, len(candidates), job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)

    # Phase 2: Verify each candidate
    print(f"  🔍 Phase 2: verifying {len(candidates)} candidates")
    verified = []
    verified_count = 0
    for i, cand in enumerate(candidates):
        try:
            is_store, country = verify_wix_store(cand['domain'])
            if is_store:
                verified.append({'domain': cand['domain'], 'source': cand['source'], 'country': country})
                verified_count += 1
        except: pass
        # Update progress every 10
        if (i + 1) % 10 == 0:
            conn = get_db()
            if conn:
                try:
                    cur = conn.cursor()
                    cur.execute("UPDATE wix_discovery_jobs SET processed=%s, saved=%s, updated_at=NOW() WHERE id=%s",
                                (i + 1 + 1, verified_count, job_id))
                    conn.commit(); cur.close()
                finally: release_db(conn)
            print(f"    Verified {i+1}/{len(candidates)}, {verified_count} real stores")
    print(f"  ✅ Verified {verified_count} real Wix Stores")

    # Save verified stores
    saved = save_wix_stores(user_email, verified)

    # Phase 3: Related discovery (from verified stores)
    print(f"  🔗 Phase 3: related discovery")
    try:
        related = discover_wix_via_related(user_email, seeds_limit=8)
        if related:
            # Verify related too
            verified_related = []
            for r in related[:30]:
                try:
                    is_store, country = verify_wix_store(r['domain'])
                    if is_store:
                        verified_related.append({'domain': r['domain'], 'source': 'wix_related', 'country': country})
                except: pass
            saved += save_wix_stores(user_email, verified_related)
    except Exception as e:
        print(f"related error: {e}")

    # Mark complete
    conn = get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_discovery_jobs SET status='completed', processed=%s, saved=%s, updated_at=NOW() WHERE id=%s",
                        (len(candidates) + 1, saved, job_id))
            conn.commit(); cur.close()
        finally: release_db(conn)

    print(f"✅ Wix discovery job #{job_id} complete ({saved} stores saved)")

def get_wix_discovery_jobs(user_email):
    conn = get_db()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, category, total, processed, found, saved, status, created_at
            FROM wix_discovery_jobs WHERE user_email = %s ORDER BY created_at DESC LIMIT 3""", (user_email,))
        rows = cur.fetchall(); cur.close()
        return [{'id': r[0], 'category': r[1] or 'all', 'total': r[2], 'processed': r[3],
                 'found': r[4], 'saved': r[5], 'status': r[6], 'created_at': str(r[7])[:16]} for r in rows]
    except: return []
    finally: release_db(conn)

# ==========================================
# QUEUE
# ==========================================
def add_to_queue(user_email, pairs):
    conn = get_db()
    if not conn: return 0, 0
    added = 0; skipped = 0
    try:
        cur = conn.cursor()
        for item in pairs:
            if isinstance(item, (list, tuple)):
                email = item[0]; store = item[1] if len(item) > 1 else ''
            else:
                email = item; store = ''
            email = email.strip().lower()
            if not email or '@' not in email: continue
            domain_from_email_val = domain_from_email(email)
            if domain_from_email_val in PLACEHOLDER_DOMAINS:
                skipped += 1; continue
            store = (store or '').strip().lower()
            if not store or store in PUBLIC_EMAIL_DOMAINS:
                store = email
            if store in PLACEHOLDER_DOMAINS:
                store = email
            cur.execute("SELECT id FROM sent_log WHERE user_email = %s AND email = %s", (user_email, email))
            if cur.fetchone(): skipped += 1; continue
            try:
                cur.execute("""INSERT INTO audit_queue (user_email, email, domain, status)
                    VALUES (%s, %s, %s, 'pending') ON CONFLICT (user_email, email) DO NOTHING""",
                    (user_email, email, store))
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

def delete_queue_item(item_id, user_email):
    conn = get_db()
    if not conn: return False
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_queue WHERE id=%s AND user_email=%s", (item_id, user_email))
        deleted = cur.rowcount > 0
        conn.commit(); cur.close()
        return deleted
    except: return False
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

def clear_queue(user_email, mode='done'):
    conn = get_db()
    if not conn: return 0
    try:
        cur = conn.cursor()
        if mode == 'done':
            cur.execute("DELETE FROM audit_queue WHERE user_email = %s AND status IN ('done','skipped')", (user_email,))
        elif mode == 'all':
            cur.execute("DELETE FROM audit_queue WHERE user_email = %s", (user_email,))
        else:
            cur.execute("DELETE FROM audit_queue WHERE user_email = %s AND status IN ('pending','current')", (user_email,))
        n = cur.rowcount
        conn.commit(); cur.close()
        return n
    except: return 0
    finally: release_db(conn)

def fix_queue_domains(user_email):
    pairs = load_found_pairs(user_email)
    lookup = {}
    for e, s in pairs:
        if e and e not in lookup:
            lookup[e] = s
    conn = get_db()
    if not conn: return 0
    fixed = 0
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, email, domain FROM audit_queue WHERE user_email = %s AND status IN ('pending','current','done','skipped')", (user_email,))
        rows = cur.fetchall()
        for item_id, email, domain in rows:
            if not domain: continue
            if domain.lower() in PUBLIC_EMAIL_DOMAINS or domain.lower() in PLACEHOLDER_DOMAINS:
                real_store = lookup.get(email.lower(), '')
                if not real_store or real_store.lower() in PUBLIC_EMAIL_DOMAINS:
                    real_store = email
                cur.execute("UPDATE audit_queue SET domain=%s, updated_at=NOW() WHERE id=%s", (real_store, item_id))
                fixed += 1
        conn.commit(); cur.close()
    except Exception as e:
        print(f"fix_queue_domains: {e}")
    finally: release_db(conn)
    return fixed

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
# AUDIT (Shopify — UNCHANGED)
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
            report["checks"]["product_count"] = pc; report["checks"]["product_count_capped"] = (pc == 250)
            if pc == 0: report["issues"].append({"title": "No Products Visible", "description": "No products.", "recommendation": "Add products.", "severity": "high"})
            elif pc < 10: report["issues"].append({"title": f"Only {pc} Products", "description": "Few products.", "recommendation": "Aim for 20+.", "severity": "medium"})
            else: report["positives"].append(f"{pc}+ products")
            max_img_kb = 0
            for p in products_data[:5]:
                for img in p.get('images', [])[:2]:
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

    if include_catalogue:
        try:
            cat = crawl_catalogue(raw, limit=50)
            if cat:
                report["catalogue"] = cat
        except Exception as e:
            print(f"catalogue during audit: {e}")
    return report

# ==========================================
# EMAIL GENERATOR (RANDOMIZED) — SHOPIFY (UNCHANGED)
# ==========================================
GREETINGS = {
    'friendly': ["Hi {brand} team,", "Hey {brand} folks,", "Hello {brand},", "Hey {brand},", "Hi {brand},", "Hey there {brand},"],
    'professional': ["Hello {brand} team,", "Dear {brand} team,", "Greetings {brand} team,", "Hello {brand},", "Good day {brand} team,"],
    'casual': ["Hey {brand},", "Yo {brand},", "What's up {brand}?", "Hey {brand} team,"]
}

OPENERS_WITH_URL = {
    'friendly': [
        "Just had a quick look at {url} — spotted a few things.",
        "Went through {url} today and noticed a few issues.",
        "Spent a few minutes on {url} — here's what stood out.",
        "Checked out {url} and found some quick wins.",
        "Browsed {url} today and jotted down a few notes.",
        "Took a peek at {url} — found some easy fixes."
    ],
    'professional': [
        "I reviewed {url} and identified several areas for improvement.",
        "After analyzing {url}, I found a few notable issues.",
        "I ran a quick audit of {url} today and wanted to share the findings.",
        "Here are some observations from my review of {url}.",
        "I spent some time analyzing {url} — here's what I found."
    ],
    'casual': [
        "Just checked {url} — found a few things.",
        "Took a look at {url} and noticed some stuff.",
        "Was browsing {url} and saw a few issues.",
        "Had a look at {url} — here's what popped up.",
        "Quick peek at {url}, and I found some wins."
    ]
}

OPENERS_NO_URL = {
    'friendly': [
        "Just had a quick look at your store — spotted a few things.",
        "Went through your store today and noticed a few issues.",
        "Spent a few minutes on your store — here's what stood out."
    ],
    'professional': [
        "I reviewed your store and identified several areas for improvement.",
        "After analyzing your store, I found a few notable issues.",
        "I ran a quick audit of your store today and wanted to share the findings."
    ],
    'casual': [
        "Just checked your store — found a few things.",
        "Took a look at your store and noticed some stuff.",
        "Was browsing your store and saw a few issues."
    ]
}

ISSUES_INTROS = {
    'friendly': ["Top issues I found:", "Here's what I noticed:", "Quick list:", "What stood out:", "A few things off:"],
    'professional': ["Key findings:", "Issues identified:", "Summary of findings:", "The main issues I found:", "Notable findings:"],
    'casual': ["Here's what I found:", "Quick rundown:", "Stuff I noticed:", "What's off:", "Quick list:"]
}

CATALOGUE_INTROS = {
    'friendly': ["Also noticed in your catalogue:", "On the product side:", "One more thing:", "About your products:", "Also worth noting:"],
    'professional': ["Additionally, regarding your product catalogue:", "I also noted the following about your catalogue:", "On the product side:", "Regarding your inventory:", "Catalogue observations:"],
    'casual': ["Also saw this about your products:", "About your catalogue:", "One more thing:", "Also on the product side:"]
}

SCORE_LINES = [
    "Overall score: {score}/100 — most are 1-day fixes.",
    "Overall: {score}/100. Fixable in a day or two.",
    "Score: {score}/100. Easy wins."
]

CTAS = {
    'friendly': ["Want me to send a quick 2-min video?", "Want a short checklist?", "Should I send over the details?", "Want me to send a quick Loom?", "Interested in a quick fix list?", "Can I send a short walkthrough?"],
    'professional': ["Would a short walkthrough be useful?", "Shall I send over the detailed findings?", "Would you like me to send a brief video?", "Can I share a quick report on this?", "Would a 15-min call be worth scheduling?"],
    'casual': ["Want a quick video?", "Should I send the details?", "Want a checklist?", "Send over a Loom?", "Want a quick fix list?"]
}

SIGNOFF_LINES = {
    'friendly': ["No pitch — just thought it was worth sharing.", "No pressure either way.", "Just sharing in case it's useful.", "Not selling anything — just helping.", "Thought you'd want to know."],
    'professional': ["Happy to provide a detailed report if helpful.", "Let me know if you'd like the full breakdown.", "No obligation — just wanted to flag it.", "Feel free to reach out if this is useful."],
    'casual': ["No pitch — just sharing.", "No pressure.", "Just thought I'd share.", "No strings attached."]
}

SIGNOFFS = ["Best regards,", "Cheers,", "Best,", "Warmly,"]

def pick(pool):
    try: return random.choice(pool)
    except: return pool[0] if pool else ''

def generate_outreach_email(report, tone='friendly', sender_name='', email=''):
    tone = tone if tone in GREETINGS else 'friendly'
    domain = report.get('domain', '')
    is_email_as_domain = '@' in domain if domain else False

    if is_email_as_domain:
        brand = domain.split('@')[0]
        display_url = ''
    elif domain and domain.lower() in PUBLIC_EMAIL_DOMAINS:
        brand = email.split('@')[0] if email and '@' in email else 'there'
        display_url = ''
    else:
        brand = domain.split('.')[0].title() if domain else 'there'
        display_url = domain

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

    subj_target = display_url if display_url else 'your store'
    if overall < 50: subject = f"Found {len(issues)} issues on {subj_target}"
    elif overall < 75: subject = f"Quick idea for {subj_target}"
    else: subject = f"Nice store! One thing I noticed on {subj_target}"

    greeting = pick(GREETINGS[tone]).replace('{brand}', brand)
    opener = pick(OPENERS_WITH_URL[tone] if display_url else OPENERS_NO_URL[tone]).replace('{url}', display_url)
    issues_intro = pick(ISSUES_INTROS[tone])
    score_line = pick(SCORE_LINES).replace('{score}', str(overall))
    cta = pick(CTAS[tone])
    signoff_line = pick(SIGNOFF_LINES[tone])
    signoff = pick(SIGNOFFS)
    signature = sender_name.strip() if sender_name and sender_name.strip() else "[Your name]"

    body_parts = [greeting, "", opener, "", issues_intro, ""]
    for b in issue_bullets:
        body_parts.append(f"• {b}")
    body_parts.append("")

    cat = report.get('catalogue')
    if cat and (cat.get('product_count') or cat.get('categories')):
        cat_intro = pick(CATALOGUE_INTROS[tone])
        cat_lines = []
        pc = cat.get('product_count', 0)
        cats = cat.get('categories', [])[:3]
        if pc and cats:
            cat_lines.append(f"{pc} products — top categories: {', '.join(cats)}")
        elif pc:
            cat_lines.append(f"{pc} products live")
        sold = cat.get('sold_out_count', 0)
        if sold > 0:
            cat_lines.append(f"{sold} bestsellers currently sold out")
        if cat_lines:
            body_parts.append(cat_intro)
            for c in cat_lines:
                body_parts.append(f"• {c}")
            body_parts.append("")

    body_parts.append(score_line)
    body_parts.append("")
    body_parts.append(cta)
    body_parts.append("")
    body_parts.append(signoff_line)
    body_parts.append("")
    body_parts.append(signoff)
    body_parts.append(signature)

    body = "\n".join(body_parts)
    return {'subject': subject, 'body': body, 'tone': tone}

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
<span class="navbar-title">Zegseg Shopify Tools</span>
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
# HOME (Email Finder - Shopify)
# ==========================================
@app.route('/')
@login_required
def home():
    preload = request.args.get('url', '')
    body = '''<div style="max-width:700px;margin:20px auto;padding:20px">
<div style="background:white;padding:30px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1);margin-bottom:20px">
<h2 style="color:#333;margin-top:0">🔍 Email Finder</h2>
<p style="color:#666">Paste any number of store URLs (one per line). Search runs in background — you can close the browser. Jobs are auto-split into batches of 100.</p>
<textarea id="urls" style="width:100%;height:180px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;box-sizing:border-box" placeholder="deluxura.shop&#10;hipchik.com">''' + preload.replace('<','&lt;') + '''</textarea>
<button onclick="startBackgroundSearch()" style="background:#667eea;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">🚀 Search All URLs (Background)</button>
<button onclick="importFromDiscovery()" style="background:#8b5cf6;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin-bottom:10px">📥 Import from Discovery</button>
<div id="result" style="margin-top:20px;background:#f8f9fa;padding:15px;border-radius:8px;min-height:40px"></div>
</div>
<div style="background:white;padding:20px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
<h3 style="margin-top:0;color:#333">📋 Last 3 Jobs</h3>
<div id="jobsList">Loading...</div>
</div>
</div>
<script>
async function startBackgroundSearch(){
  const input=document.getElementById('urls').value;
  const result=document.getElementById('result');
  const stores=input.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(stores.length===0){alert('Enter URL');return}
  const batches = Math.ceil(stores.length / 100);
  result.innerHTML='<p style="color:#666">⏳ Starting background job for '+stores.length+' URLs in '+batches+' batch(es)...</p>';
  try{
    const res=await fetch('/start-email-finder-job',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls: stores})});
    const data=await res.json();
    if(data.success){
      result.innerHTML='<div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:12px;border-radius:5px;color:#166534"><b>✅ Job #'+data.job_id+' started!</b><br>Processing '+stores.length+' URLs in '+batches+' batch(es) of 100 in the background.<br><br><b>You can close the browser now.</b><br>Come back later to see results.</div>';
      document.getElementById('urls').value='';
      loadJobs();
    } else {
      result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(data.error||'Unknown')+'</div>';
    }
  }catch(e){result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e.message+'</div>'}
}

async function importFromDiscovery(){
  const result=document.getElementById('result');
  result.innerHTML='<p style="color:#666">⏳ Loading discovered stores...</p>';
  try{
    const res = await fetch('/get-discovered');
    const data = await res.json();
    if(!data.stores || data.stores.length === 0){
      result.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No discovered stores yet. Go to Store Discovery first.</div>';
      return;
    }
    const domains = data.stores.map(s=>s.domain);
    document.getElementById('urls').value = domains.join('\\n');
    result.innerHTML = '<div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:10px;border-radius:5px;color:#166534">✅ Loaded '+domains.length+' store URLs from Discovery. Click "Search All URLs (Background)" to find emails.</div>';
  }catch(e){
    result.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e.message+'</div>';
  }
}

async function loadJobs(){
  try{
    const res = await fetch('/get-email-finder-jobs');
    const data = await res.json();
    const c = document.getElementById('jobsList');
    if(!data.jobs || data.jobs.length === 0){ c.innerHTML = '<p style="color:#666">No jobs yet.</p>'; return; }
    let html = '';
    data.jobs.forEach(j => {
      let color = '#f59e0b';
      let icon = '🔄';
      if(j.status === 'completed'){ color = '#16a34a'; icon = '✅'; }
      else if(j.status === 'cancelled'){ color = '#ef4444'; icon = '⏹️'; }
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+color+'">';
      html += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">';
      html += '<div><b>'+icon+' Job #'+j.id+'</b> — '+j.emails+' emails from '+j.total+' stores<br><span style="font-size:12px;color:#666">'+j.created_at+'</span></div>';
      html += '<div style="display:flex;gap:6px;flex-wrap:wrap">';
      html += '<button onclick="viewJob('+j.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">View Results</button>';
      if(j.status === 'completed' && j.emails > 0){
        html += '<button onclick="sendJobToVerify('+j.id+')" style="background:#f59e0b;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">📨 Send to Verify</button>';
      }
      html += '</div></div>';
      html += '<div id="job-'+j.id+'" style="display:none;margin-top:10px"></div>';
      html += '</div>';
    });
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}

async function viewJob(id){
  const c = document.getElementById('job-'+id);
  if(c.style.display === 'block'){ c.style.display = 'none'; return; }
  c.innerHTML = '<p style="color:#666">Loading...</p>';
  c.style.display = 'block';
  try{
    const res = await fetch('/get-email-finder-job/'+id);
    const data = await res.json();
    if(!data.results || data.results.length === 0){
      c.innerHTML = '<p style="color:#666">No results yet. Job may still be running.</p>';
      return;
    }
    let html = '<div style="background:white;padding:10px;border-radius:6px;max-height:300px;overflow-y:auto;font-size:13px">';
    data.results.forEach(r => {
      html += '<div style="padding:8px 0;border-bottom:1px solid #eee"><div style="font-weight:bold;margin-bottom:4px">📦 <a href="https://'+r.store+'" target="_blank" style="color:#3b82f6">'+r.store+'</a></div>';
      (r.emails||[]).forEach(e => { html += '<div style="padding-left:16px;color:#333;word-break:break-all">📧 '+e+'</div>'; });
      html += '</div>';
    });
    html += '</div>';
    c.innerHTML = html;
  }catch(e){ c.innerHTML = '<p style="color:red">Error loading results</p>'; }
}

async function sendJobToVerify(id){
  try{
    const res = await fetch('/get-email-finder-job/'+id);
    const data = await res.json();
    if(!data.results) return;
    const pairs = [];
    data.results.forEach(r => {
      (r.emails||[]).forEach(e => pairs.push({email: e, store: r.store || ''}));
    });
    if(pairs.length === 0){ alert('No emails found in this job'); return; }
    await fetch('/store-emails', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pairs: pairs})});
    alert('✅ '+pairs.length+' emails saved. Go to Verify page and click "From Finder".');
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
        if row:
            threading.Thread(target=process_subjob, args=(row[0],), daemon=True).start()
    return jsonify({'success': True, 'job_id': master_id, 'total': len(urls)})

@app.route('/get-email-finder-jobs')
@login_required
def get_email_finder_jobs_route():
    user_email = session.get('user_id')
    return jsonify({'jobs': get_email_finder_masters(user_email)})

@app.route('/get-email-finder-job/<int:job_id>')
@login_required
def get_email_finder_job_route(job_id):
    user_email = session.get('user_id')
    detail = get_email_finder_master_detail(job_id, user_email)
    if not detail: return jsonify({'results': [], 'subjobs': []})
    return jsonify(detail)

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
            if e:
                items.append(f"{e}:::{s}" if s else e)
        if user_email: save_user_state(user_email, found_emails='|||'.join(items))
    else:
        emails = data.get('emails', [])
        if user_email: save_user_state(user_email, found_emails='|||'.join(emails))
    return jsonify({'success': True})

# ==========================================
# STORE DISCOVERY (Shopify)
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
<button onclick="sendAllToFinder()" style="background:#667eea;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;font-size:14px;margin-top:10px;margin-right:8px">📧 Send All to Email Finder</button>
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
      html += '<div style="display:flex;gap:6px;flex-wrap:wrap">';
      html += '<button id="hfbtn-'+h.id+'" onclick="toggleHFView('+h.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">View</button>';
      html += '<button onclick="sendImportToFinder('+h.id+')" style="background:#667eea;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">📧 Send to Finder</button>';
      html += '</div></div><div id="hf-'+h.id+'" style="display:none;margin-top:10px"></div></div>';
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

async function sendImportToFinder(id){
  const res = await fetch('/get-hf-import/'+id);
  const data = await res.json();
  if(!data.domains || data.domains.length === 0){ alert('No domains in this import'); return; }
  const text = data.domains.join('\\n');
  window.location.href = '/?url=' + encodeURIComponent(text);
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

async function sendAllToFinder(){
  const res = await fetch('/get-discovered');
  const data = await res.json();
  if(!data.stores || data.stores.length===0){ alert('No stores'); return; }
  const domains = data.stores.map(s=>s.domain);
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
# WIX STORE FINDER PAGE
# ==========================================
@app.route('/wix')
@login_required
def wix_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🔍 Wix Store Finder</h1>
<p style="margin:4px 0 0 0;font-size:14px;opacity:0.9">Warehouse · 500 fresh domains daily from Leadita</p>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">🚀 Automated Discovery</h3>
<p style="font-size:14px;color:#555;margin:5px 0">Queries 6 Common Crawl indexes × 3 store-specific patterns, then verifies each URL is a real Wix Store.</p>
<div style="background:#f3f4f6;padding:10px;border-radius:6px;margin:10px 0;font-size:13px;line-height:1.7">
  <b>How it works:</b><br>
  1️⃣ Query <code>/product-page/</code>, <code>/shop/</code>, <code>/store/</code> paths across 6 CC indexes<br>
  2️⃣ Verify each URL loads as a real Wix Store (has <code>wixstores</code>, cart widgets, etc.)<br>
  3️⃣ Filter out blogs, portfolios, and other non-store Wix sites<br>
  4️⃣ Detect country (US / UK / CA / AU / EU)
</div>
<button onclick="startWixDiscovery()" style="background:#0d9488;color:white;padding:14px 28px;border:none;border-radius:8px;cursor:pointer;font-size:16px;font-weight:bold;width:100%">🚀 Discover Wix Stores</button>
<div id="wixStatus" style="margin-top:12px"></div>
<div style="font-size:12px;color:#666;margin-top:8px;text-align:center">⚠️ Takes 10-20 minutes (Common Crawl queries are slow, but reliable)</div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">🏭 Warehouse (Daily Auto-Ingest)</h3>
<p style="font-size:14px;color:#555;margin:5px 0">Grows every day at 14:00 UTC. Pull any number when you're ready.</p>
<div id="warehouseStats" style="background:#f3f4f6;padding:12px;border-radius:6px;margin:10px 0;font-size:13px;line-height:1.7">Loading…</div>
<button onclick="ingestNow()" style="background:#7c3aed;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-size:15px;font-weight:bold;width:100%;margin-bottom:10px">📥 Ingest Today's Batch</button>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<input type="number" id="wixPullCount" value="500" min="1" max="5000" style="flex:1;min-width:100px;padding:10px;border:1px solid #ddd;border-radius:6px;font-size:14px;box-sizing:border-box">
<button onclick="pullFromWarehouse()" style="flex:2;background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-size:15px;font-weight:bold">📧 Send to Wix Finder</button>
</div>
<button onclick="resetWarehouse()" style="background:#6b7280;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;margin-top:8px">🔄 Reset pulled rows to pending</button>
<div id="ingestStatus" style="margin-top:10px"></div>
<div id="pullStatus" style="margin-top:10px"></div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📋 Last 3 Discovery Jobs</h3>
<div id="wixJobs">Loading...</div>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1)">
<h3 style="margin-top:0">📋 Discovered Wix Stores (<span id="wixCount">0</span>)</h3>
<div id="wixList">Loading...</div>
<button onclick="clearWixStores()" style="background:#ef4444;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;font-size:14px;margin-top:10px">🗑️ Clear</button>
</div>
</div>
<script>
async function startWixDiscovery(){
  const status = document.getElementById('wixStatus');
  status.innerHTML = '<p style="color:#666">⏳ Starting Wix discovery...<br>This takes 10-20 minutes. You can close the browser.</p>';
  try{
    const res = await fetch('/start-wix-discovery', {method:'POST'});
    const data = await res.json();
    if(data.success){
      status.innerHTML = '<div style="background:#f0fdf4;border-left:4px solid #16a34a;padding:12px;border-radius:5px;color:#166534"><b>✅ Job #'+data.job_id+' started!</b><br>You can close the browser now.</div>';
      loadWixJobs();
    } else {
      status.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(data.error||'Unknown')+'</div>';
    }
  }catch(e){ status.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e.message+'</div>'; }
}

async function loadWixJobs(){
  try{
    const res = await fetch('/get-wix-jobs');
    const data = await res.json();
    const c = document.getElementById('wixJobs');
    if(!data.jobs || data.jobs.length === 0){ c.innerHTML = '<p style="color:#666">No Wix discovery jobs yet.</p>'; return; }
    let html = '';
    data.jobs.forEach(j => {
      let color = '#f59e0b';
      let icon = '🔄';
      if(j.status === 'completed'){ color = '#16a34a'; icon = '✅'; }
      const pct = j.total > 0 ? Math.round((j.processed / j.total) * 100) : 0;
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+color+'">';
      html += '<div><b>'+icon+' Job #'+j.id+'</b> — '+j.saved+' real stores saved ('+j.processed+'/'+j.total+' verified)<br>';
      html += '<span style="font-size:12px;color:#666">'+j.created_at+' · found '+j.found+' candidates</span></div>';
      html += '<div style="margin-top:8px;background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+pct+'%;height:14px;background:'+color+'"></div></div>';
      html += '</div>';
    });
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}

async function loadWixStores(){
  try{
    const res = await fetch('/get-wix-stores');
    const data = await res.json();
    document.getElementById('wixCount').textContent = data.stores ? data.stores.length : 0;
    const c = document.getElementById('wixList');
    if(!data.stores || data.stores.length === 0){ c.innerHTML = '<p style="color:#666">No Wix stores discovered yet.</p>'; return; }
    let html = '';
    data.stores.slice(0, 50).forEach(s => {
      html += '<div style="background:#f9f9f9;padding:10px;border-radius:6px;margin:6px 0;border-left:4px solid #0d9488">';
      html += '<b><a href="https://'+s.domain+'" target="_blank" style="color:#3b82f6">'+s.domain+'</a></b>';
      if(s.country) html += ' <span style="font-size:11px;background:#e0f2fe;color:#0369a1;padding:2px 6px;border-radius:4px">'+s.country+'</span>';
      html += '</div>';
    });
    if(data.stores.length > 50){ html += '<p style="color:#666;font-size:13px">... and '+(data.stores.length - 50)+' more</p>'; }
    c.innerHTML = html;
  }catch(e){ console.error(e); }
}

async function clearWixStores(){
  if(!confirm('Delete all discovered Wix stores?')) return;
  await fetch('/clear-wix-stores', {method:'POST'});
  loadWixStores();
}

async function loadWarehouseStats(){
  try{
    const r = await fetch('/wix/warehouse');
    const d = await r.json();
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
window.onload = function(){ loadWixJobs(); loadWixStores(); loadWarehouseStats(); };
</script>'''
    return render_page("Wix Store Finder", body)

# ==========================================
# WIX EMAIL FINDER PAGE
# ==========================================
@app.route('/wix/finder')
@login_required
def wix_finder_page():
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">📧 Wix Email Finder</h1>
</div>
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

# ==========================================
# WIX VERIFY PAGE
# ==========================================
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

# ==========================================
# WIX SCOUT PAGE
# ==========================================
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

# ==========================================
# WIX AUDIT PAGE
# ==========================================
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

# ==========================================
# WIX API ROUTES
# ==========================================
@app.route('/start-wix-discovery', methods=['POST'])
@login_required
def start_wix_discovery():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'success': False, 'error': 'No DB'})
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO wix_discovery_jobs (user_email, category, total, status)
            VALUES (%s, %s, %s, 'running') RETURNING id""",
            (user_email, 'cc_multi', 1))
        job_id = cur.fetchone()[0]
        conn.commit(); cur.close()
    finally: release_db(conn)
    threading.Thread(target=background_wix_discovery, args=(job_id,), daemon=True).start()
    return jsonify({'success': True, 'job_id': job_id})

@app.route('/get-wix-jobs')
@login_required
def get_wix_jobs_route():
    user_email = session.get('user_id')
    return jsonify({'jobs': get_wix_discovery_jobs(user_email)})

@app.route('/get-wix-stores')
@login_required
def get_wix_stores_route():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'stores': []})
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain, source, country, discovered_at FROM wix_stores WHERE user_email = %s ORDER BY discovered_at DESC LIMIT 10000", (user_email,))
        rows = cur.fetchall(); cur.close()
        return jsonify({'stores': [{'domain': r[0], 'source': r[1], 'country': r[2] or '', 'discovered_at': str(r[3])[:16]} for r in rows]})
    except: return jsonify({'stores': []})
    finally: release_db(conn)

@app.route('/clear-wix-stores', methods=['POST'])
@login_required
def clear_wix_stores_route():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'success': False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM wix_stores WHERE user_email = %s", (user_email,))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    except: return jsonify({'success': False})
    finally: release_db(conn)

# ==========================================
# WIX WAREHOUSE ROUTES
# ==========================================
@app.route('/wix/ingest', methods=['GET', 'POST'])
def wix_ingest_route():
    header_secret = request.headers.get('X-Cron-Secret', '')
    cron_secret = os.environ.get('CRON_SECRET', '')
    valid_cron = bool(cron_secret) and header_secret == cron_secret
    valid_user = ('user_id' in session) and header_secret == 'MANUAL_FROM_UI'
    if not (valid_cron or valid_user):
        return jsonify({'status': 'error', 'error': 'forbidden'}), 403
    if valid_user and not valid_cron:
        try:
            import importlib
            import ingest_leadita
            importlib.reload(ingest_leadita)
            result = ingest_leadita.run(get_db, release_db)
            code = 200 if result.get('status') == 'ok' else 500
            return jsonify(result), code
        except Exception as e:
            return jsonify({'status': 'error', 'error': str(e)[:300]}), 500
    def _bg():
        try:
            import importlib, ingest_leadita
            importlib.reload(ingest_leadita)
            print(f"🕒 [cron] {ingest_leadita.run(get_db, release_db)}")
        except Exception as e:
            print(f"🕒 [cron] error: {e}")
    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({'status': 'accepted'}), 202

@app.route('/wix/warehouse')
@login_required
def wix_warehouse_status():
    conn = get_db()
    if not conn: return jsonify({'error': 'no db'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM wix_warehouse")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='pending'")
        pending = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='processing'")
        processing = cur.fetchone()[0]
        cur.execute("""SELECT DATE(created_at) AS d, COUNT(*) AS c FROM wix_warehouse
            GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC LIMIT 14""")
        daily = [{'date': str(r[0]), 'count': r[1]} for r in cur.fetchall()]
        cur.close()
        return jsonify({'total': total, 'pending': pending, 'processing': processing, 'daily_last_14': daily})
    except Exception as e:
        return jsonify({'error': str(e)[:200]}), 500
    finally: release_db(conn)

@app.route('/wix/request', methods=['POST'])
@login_required
def wix_request():
    data = request.get_json(silent=True) or {}
    n = int(data.get('count', 500)); n = max(1, min(n, 5000))
    conn = get_db()
    if not conn: return jsonify({'success': False, 'error': 'No DB'})
    try:
        cur = conn.cursor()
        cur.execute("""UPDATE wix_warehouse SET status='processing'
            WHERE id IN (SELECT id FROM wix_warehouse WHERE status='pending'
            ORDER BY created_at DESC LIMIT %s) RETURNING domain""", (n,))
        rows = cur.fetchall(); conn.commit(); cur.close()
        domains = [r[0] for r in rows]
        return jsonify({'success': True, 'pulled': len(domains), 'domains': domains})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)[:200]})
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
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)[:200]})
    finally: release_db(conn)

# ==========================================
# WIX EMAIL FINDER API
# ==========================================
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
    state = load_wix_state(session.get('user_id'))
    emails = []
    for item in state.get('wix_found_emails', []):
        if not item: continue
        emails.append(item.split(':::', 1)[0].strip() if ':::' in item else item.strip())
    return jsonify({'emails': [e for e in emails if e]})

# ==========================================
# WIX VERIFY API
# ==========================================
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
    state = load_wix_state(session.get('user_id'))
    return jsonify({'emails': [e.strip() for e in state.get('wix_verified_emails', []) if e.strip()]})

# ==========================================
# WIX AUDIT QUEUE API
# ==========================================
@app.route('/wix/import-to-queue', methods=['POST'])
@login_required
def wix_import_to_queue():
    user_email = session.get('user_id')
    source = request.json.get('source', '')
    pairs = []
    if source == 'finder':
        pairs = load_wix_found_pairs(user_email)
    elif source == 'verified':
        state = load_wix_state(user_email)
        emails = state.get('wix_verified_emails', [])
        fp = load_wix_found_pairs(user_email)
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
# STARTUP RESUME
# ==========================================
try:
    resume_unfinished_masters()
except Exception as e:
    print(f"⚠️ resume_unfinished_masters: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
