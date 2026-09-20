# wix_app.py — self-contained Wix pipeline. Independent from Shopify.
import os
import re
import json
import time
import threading
import random
import requests
from flask import Blueprint, request, jsonify, session, redirect
from concurrent.futures import ThreadPoolExecutor, as_completed

wix_bp = Blueprint('wix_bp', __name__)
DATABASE_URL = os.environ.get('DATABASE_URL')

import psycopg2

def wix_get_db():
    if not DATABASE_URL: return None
    try:
        return psycopg2.connect(DATABASE_URL, sslmode='require')
    except Exception as e:
        print(f"wix db err: {e}")
        return None

def wix_release(conn):
    if conn:
        try: conn.close()
        except: pass

_dns_cache = {}
def _resolve_mx(domain):
    if domain in _dns_cache: return _dns_cache[domain]
    try:
        import dns.resolver
        mx = dns.resolver.resolve(domain, 'MX')
        r = [str(x.exchange) for x in mx]
        _dns_cache[domain] = r
        return r
    except:
        _dns_cache[domain] = None
        return None

def wix_init_db():
    conn = wix_get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_warehouse (
            id BIGSERIAL PRIMARY KEY, url TEXT UNIQUE NOT NULL, domain TEXT NOT NULL,
            source TEXT, title TEXT, country TEXT, status TEXT DEFAULT 'pending',
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
        cur.execute("""CREATE TABLE IF NOT EXISTS wix_state (
            user_email VARCHAR(255) PRIMARY KEY,
            found_emails TEXT, verified_emails TEXT, scout_recipients TEXT,
            scout_subject TEXT, scout_message TEXT, session_sent_count INTEGER DEFAULT 0,
            send_limit INTEGER DEFAULT 70,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        try: cur.execute("ALTER TABLE wix_state ADD COLUMN IF NOT EXISTS send_limit INTEGER DEFAULT 70")
        except: pass
        conn.commit(); cur.close()
        print("✅ wix tables ready")
    except Exception as e:
        print(f"⚠️ wix init db: {e}")
    finally:
        wix_release(conn)

def wix_load_state(user_email):
    conn = wix_get_db()
    if not conn: return {}
    try:
        cur = conn.cursor()
        cur.execute("SELECT found_emails, verified_emails, scout_recipients, scout_subject, scout_message, session_sent_count, send_limit FROM wix_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone(); cur.close()
        if row:
            return {
                'found_emails': row[0].split('|||') if row[0] else [],
                'verified_emails': row[1].split('|||') if row[1] else [],
                'scout_recipients': row[2].split('|||') if row[2] else [],
                'scout_subject': row[3] or '',
                'scout_message': row[4] or '',
                'session_sent_count': row[5] or 0,
                'send_limit': row[6] or 70,
            }
        return {}
    except Exception as e:
        print(f"wix_load_state: {e}")
        return {}
    finally:
        wix_release(conn)

def wix_save_state(user_email, **kwargs):
    conn = wix_get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_state (user_email) VALUES (%s) ON CONFLICT (user_email) DO NOTHING", (user_email,))
        for k, v in kwargs.items():
            if v is not None:
                cur.execute(f"UPDATE wix_state SET {k}=%s, updated_at=NOW() WHERE user_email=%s", (v, user_email))
        conn.commit(); cur.close()
    except Exception as e:
        print(f"wix_save_state: {e}")
    finally:
        wix_release(conn)

def wix_get_send_limit(user_email):
    state = wix_load_state(user_email)
    val = state.get('send_limit', 70) or 70
    if val < 1: val = 70
    return val

def wix_counter_status(user_email):
    state = wix_load_state(user_email)
    count = state.get('session_sent_count', 0) or 0
    limit = wix_get_send_limit(user_email)
    at_milestone = (count > 0 and count % limit == 0)
    next_milestone = ((count // limit) + 1) * limit
    return {'count': count, 'limit': limit, 'next_milestone': next_milestone, 'at_milestone': at_milestone}

def wix_find_emails(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
    if not domain or '.' not in domain: return []
    emails = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for url in [f"https://{domain}/contact", f"https://{domain}/contact-us", f"https://{domain}/pages/contact", f"https://{domain}"]:
        try:
            r = requests.get(url, headers=headers, timeout=6)
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
    skip = ['wix','sentry','facebook.com','instagram.com','twitter.com','pinterest.com',
            'example.com','example.org','wixpress','cloudflare','sentry.io',
            '.jpg','.png','.jpeg','.gif','.svg','@2x','@3x']
    final = [e for e in set(emails) if len(e) > 5 and '.' in e and not any(x in e for x in skip)]
    return final

def wix_process_email_job(job_id):
    conn = wix_get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_urls, results, user_email FROM wix_email_jobs WHERE id=%s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        try: results = json.loads(row[1]) if row[1] else []
        except: results = []
        user_email = row[2]
    finally: wix_release(conn)

    conn = wix_get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_email_jobs SET status='running' WHERE id=%s", (job_id,))
            conn.commit(); cur.close()
        finally: wix_release(conn)

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
        conn = wix_get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            cur.execute("""UPDATE wix_email_jobs SET processed=%s, emails_found=%s, results=%s,
                remaining_urls=%s, status=%s WHERE id=%s""",
                (len(results), total, json.dumps(results), '|||'.join(remaining),
                 'running' if remaining else 'completed', job_id))
            conn.commit(); cur.close()
        finally: wix_release(conn)

    conn = wix_get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_email_jobs SET status='completed' WHERE id=%s", (job_id,))
            conn.commit(); cur.close()
        finally: wix_release(conn)

    if user_email:
        pairs = []
        for r in results:
            store = r.get('store', '')
            for e in r.get('emails', []):
                pairs.append(f"{e}:::{store}")
        if pairs:
            save_conn = wix_get_db()
            if save_conn:
                try:
                    cur = save_conn.cursor()
                    cur.execute("""INSERT INTO wix_state (user_email, found_emails)
                        VALUES (%s, %s)
                        ON CONFLICT (user_email) DO UPDATE SET
                        found_emails = EXCLUDED.found_emails, updated_at = NOW()""",
                        (user_email, '|||'.join(pairs)))
                    save_conn.commit(); cur.close()
                    print(f"✅ wix job {job_id}: saved {len(pairs)} pairs")
                except Exception as e:
                    print(f"❌ wix save: {e}")
                finally: wix_release(save_conn)

def wix_verify_email(email):
    try:
        import smtplib
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return email, False, "Invalid syntax"
        domain = email.split('@')[1]
        mx = _resolve_mx(domain)
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

def wix_verify_worker(job_id):
    conn = wix_get_db()
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
    finally: wix_release(conn)

    CHUNK = 100
    while remaining:
        chunk = remaining[:CHUNK]; remaining = remaining[CHUNK:]
        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = {ex.submit(wix_verify_email, e): e for e in chunk}
            for f in as_completed(futures):
                email, ok, reason = f.result()
                if ok: valid.append(email)
                else: invalid.append(email + " - " + reason)
        conn = wix_get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            new_status = 'completed' if not remaining else 'running'
            cur.execute("""UPDATE wix_verify_jobs SET processed=%s, valid_emails=%s, invalid_emails=%s,
                remaining_emails=%s, status=%s, updated_at=NOW() WHERE id=%s""",
                (len(valid)+len(invalid), '|||'.join(valid), '|||'.join(invalid),
                 '|||'.join(remaining), new_status, job_id))
            conn.commit(); cur.close()
        finally: wix_release(conn)

    if user_email and valid:
        wix_save_state(user_email, verified_emails='|||'.join(valid))

def extract_wix_products(html, base_url, max_products=3):
    products = []
    product_links = re.findall(r'href="(https?://[^"]*?/(?:product-page|shop|store|product)/[^"?#]+)"', html)
    product_links += re.findall(r'href="(/[^"]*?/(?:product-page|shop|store|product)/[^"?#]+)"', html)
    seen = set(); unique = []
    for l in product_links:
        if l.startswith('/'): l = base_url.rstrip('/') + l
        if l in seen: continue
        seen.add(l); unique.append(l)
        if len(unique) >= max_products: break
    try:
        sm = requests.get(f"{base_url.rstrip('/')}/store-products-sitemap.xml", timeout=8,
                          headers={"User-Agent": "Mozilla/5.0"})
        if sm.status_code == 200:
            for sl in re.findall(r'<loc>(.*?)</loc>', sm.text)[:max_products]:
                if sl not in seen:
                    unique.append(sl); seen.add(sl)
                    if len(unique) >= max_products: break
    except: pass
    for link in unique[:max_products]:
        try:
            pr = requests.get(link, timeout=8,
                              headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            if pr.status_code != 200: continue
            t = re.search(r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)', pr.text, re.I)
            p = re.search(r'<meta[^>]+property=["\'](?:og:price:amount|product:price:amount)["\'][^>]+content=["\']([^"\']+)', pr.text, re.I)
            if not t: t = re.search(r'<title[^>]*>(.*?)</title>', pr.text, re.I | re.S)
            title = (t.group(1).strip() if t else '')[:100]
            price = p.group(1).strip() if p else ''
            if title: products.append({'title': title, 'price': price, 'url': link})
        except: continue
        if len(products) >= max_products: break
    return products

def audit_store_wix(domain, case_id):
    from datetime import datetime
    raw = domain.strip().lower().replace("https://","").replace("http://","").replace("www.","").split("/")[0]
    report = {"domain": raw, "case_id": case_id, "platform": "Wix",
              "audited_at": datetime.now().isoformat(),
              "checks": {}, "scores": {}, "issues": [], "positives": [], "top_products": []}
    if not raw or '.' not in raw:
        report['error'] = "Invalid domain"; return report
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    base_url = f"https://{raw}"
    try:
        start = time.time()
        r = requests.get(base_url, headers=headers, timeout=12, allow_redirects=True)
        lt = round(time.time()-start, 2)
        html = r.text
        report["checks"]["http_status"] = r.status_code
        report["checks"]["load_time_seconds"] = lt
        report["checks"]["https"] = True
        if lt < 1.5: report["positives"].append(f"Fast load ({lt}s)")
        elif lt > 3: report["issues"].append({"title":"Slow Load Time","description":f"{lt}s","recommendation":"Optimize images","severity":"medium"})
    except Exception as e:
        report["checks"]["https"] = False
        report["error"] = f"Unreachable: {str(e)[:100]}"
        return report
    low = html.lower()
    is_wix = any(x in low for x in ['wix.com','wixstatic.com','wix-code','wixstores','parastorage.com'])
    report["checks"]["is_wix"] = is_wix
    if is_wix: report["positives"].append("Confirmed Wix site")
    try:
        products = extract_wix_products(html, base_url, 3)
        report["top_products"] = products
        if products: report["positives"].append(f"Detected {len(products)} products")
        else: report["issues"].append({"title":"No Products Detected","description":"Could not find product pages","recommendation":"Feature products on homepage","severity":"high"})
    except: pass
    hv = 'name="viewport"' in low
    report["checks"]["mobile_responsive"] = hv
    if hv: report["positives"].append("Mobile responsive")
    else: report["issues"].append({"title":"Not Mobile Responsive","description":"Missing viewport","recommendation":"Enable mobile in Wix","severity":"high"})
    he = bool(re.search(r'mailto:[^"\']+', html))
    hp = bool(re.search(r'tel:[^"\']+', html))
    report["checks"]["has_email_link"] = he
    report["checks"]["has_phone_link"] = hp
    if he or hp: report["positives"].append("Contact info present")
    else: report["issues"].append({"title":"No Contact Info","description":"No email/phone","recommendation":"Add Contact page","severity":"high"})
    socials = [p.split('.')[0] for p in ['facebook.com','instagram.com','twitter.com','tiktok.com','youtube.com','pinterest.com'] if p in low]
    report["checks"]["social_links"] = socials
    if len(socials) >= 2: report["positives"].append(f"{len(socials)} socials")
    elif not socials: report["issues"].append({"title":"No Social Media","description":"None found","recommendation":"Add social profiles","severity":"medium"})
    pf = 0
    for pol in ['/terms','/privacy','/shipping','/returns','/policies']:
        try:
            pr = requests.get(f"{base_url}{pol}", headers=headers, timeout=5)
            if pr.status_code == 200: pf += 1
        except: pass
    report["checks"]["policy_pages_found"] = f"{pf}/5"
    if pf >= 4: report["positives"].append("Policies present")
    elif pf < 2: report["issues"].append({"title":"Missing Policies","description":f"{pf}/5","recommendation":"Add terms, privacy, shipping","severity":"high"})
    payments = []
    for name, sigs in {"PayPal":["paypal.com","paypal"],"Stripe":["stripe.com","js.stripe"],"Apple Pay":["apple-pay","applepay"],"Google Pay":["google-pay","googlepay"]}.items():
        for s in sigs:
            if s in low: payments.append(name); break
    report["checks"]["payment_methods"] = payments
    if len(payments) >= 2: report["positives"].append(f"{len(payments)} payment options")
    else: report["issues"].append({"title":"Limited Payment Options","description":f"{len(payments)} detected","recommendation":"Add PayPal/Stripe","severity":"medium"})
    free_ship = any(x in low for x in ['free shipping','free delivery','shipping on us'])
    report["checks"]["free_shipping_advertised"] = free_ship
    if free_ship: report["positives"].append("Free shipping banner")
    else: report["issues"].append({"title":"No Free Shipping Banner","description":"Buyer priority","recommendation":"Add free shipping threshold","severity":"medium"})
    tm = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    dm = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.I | re.S)
    title = tm.group(1).strip() if tm else ''
    desc = dm.group(1).strip() if dm else ''
    report["checks"]["meta_title_length"] = len(title)
    report["checks"]["meta_description_length"] = len(desc)
    if not title: report["issues"].append({"title":"Missing Page Title","description":"No title","recommendation":"Add SEO title","severity":"high"})
    if not desc: report["issues"].append({"title":"Missing Meta Description","description":"None","recommendation":"Add 150-160 chars","severity":"medium"})
    trust = 0
    if he or hp: trust += 20
    trust += min(int((pf/5)*30), 30)
    if len(socials) >= 2: trust += 15
    elif socials: trust += 8
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
    if products: mkt += 20
    if len(socials) >= 3: mkt += 20
    elif socials: mkt += 10
    if free_ship: mkt += 10
    if len(payments) >= 3: mkt += 10
    report["scores"]["marketing_score"] = min(mkt, 100)
    report["scores"]["overall_score"] = int((report["scores"]["trust_score"] + report["scores"]["technical_score"] + report["scores"]["marketing_score"]) / 3)
    return report

# ==========================================
# WIX EMAIL GENERATOR — RANDOMIZED TONES
# ==========================================
WIX_GREETINGS = {
    'friendly': ["Hi {brand} team,", "Hey {brand} folks,", "Hello {brand},", "Hey {brand},", "Hi {brand},", "Hey there {brand},"],
    'professional': ["Hello {brand} team,", "Dear {brand} team,", "Greetings {brand} team,", "Hello {brand},", "Good day {brand} team,"],
    'casual': ["Hey {brand},", "Yo {brand},", "What's up {brand}?", "Hey {brand} team,"]
}
WIX_OPENERS_WITH_URL = {
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
WIX_OPENERS_NO_URL = {
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
WIX_ISSUES_INTROS = {
    'friendly': ["Top issues I found:", "Here's what I noticed:", "Quick list:", "What stood out:", "A few things off:"],
    'professional': ["Key findings:", "Issues identified:", "Summary of findings:", "The main issues I found:", "Notable findings:"],
    'casual': ["Here's what I found:", "Quick rundown:", "Stuff I noticed:", "What's off:", "Quick list:"]
}
WIX_PROD_INTROS = {
    'friendly': ["Also noticed in your catalogue:", "On the product side:", "One more thing:", "About your products:"],
    'professional': ["Additionally, regarding your product catalogue:", "I also noted the following about your catalogue:", "On the product side:", "Catalogue observations:"],
    'casual': ["Also saw this about your products:", "About your catalogue:", "One more thing:", "Also on the product side:"]
}
WIX_SCORE_LINES = [
    "Overall score: {score}/100 — most are 1-day fixes.",
    "Overall: {score}/100. Fixable in a day or two.",
    "Score: {score}/100. Easy wins."
]
WIX_CTAS = {
    'friendly': ["Want me to send a quick 2-min video?", "Want a short checklist?", "Should I send over the details?", "Want me to send a quick Loom?", "Interested in a quick fix list?", "Can I send a short walkthrough?"],
    'professional': ["Would a short walkthrough be useful?", "Shall I send over the detailed findings?", "Would you like me to send a brief video?", "Can I share a quick report on this?", "Would a 15-min call be worth scheduling?"],
    'casual': ["Want a quick video?", "Should I send the details?", "Want a checklist?", "Send over a Loom?", "Want a quick fix list?"]
}
WIX_SIGNOFF_LINES = {
    'friendly': ["No pitch — just thought it was worth sharing.", "No pressure either way.", "Just sharing in case it's useful.", "Not selling anything — just helping.", "Thought you'd want to know."],
    'professional': ["Happy to provide a detailed report if helpful.", "Let me know if you'd like the full breakdown.", "No obligation — just wanted to flag it.", "Feel free to reach out if this is useful."],
    'casual': ["No pitch — just sharing.", "No pressure.", "Just thought I'd share.", "No strings attached."]
}
WIX_SIGNOFFS = ["Best regards,", "Cheers,", "Best,", "Warmly,"]

# ==========================================
# WIX SUBJECT TEMPLATE POOLS
# ==========================================
WIX_SUBJECT_TEMPLATES = {
    'friendly': {
        'low_score': [
            "Quick note about {brand}",
            "Spotted something on {brand}",
            "A few things on {brand}",
            "{brand} — quick heads up",
            "Small things I noticed on {brand}",
            "Just checked {brand} — 3 quick wins",
            "Idea for {brand}",
            "Noticed a few things on {brand}",
            "One thing about {brand}",
            "Had a look at {brand}"
        ],
        'mid_score': [
            "Idea for {brand}",
            "Quick thought on {brand}",
            "Possible tweak for {brand}",
            "One thing for {brand}",
            "{brand} — small idea",
            "Spotted an opportunity on {brand}"
        ],
        'high_score': [
            "Nice store — {brand}",
            "Liked {brand} — one small thing",
            "{brand} is looking good",
            "One tweak for {brand}",
            "{brand} — great job"
        ]
    },
    'professional': {
        'low_score': [
            "Observations on {brand}'s online store",
            "Review notes: {brand}",
            "Findings from {brand} audit",
            "Brief review of {brand}",
            "{brand} — points for improvement",
            "Notes from reviewing {brand}",
            "Quick assessment of {brand}",
            "Areas to strengthen on {brand}",
            "Audit summary for {brand}",
            "Feedback on {brand}'s storefront"
        ],
        'mid_score': [
            "Consideration for {brand}",
            "A small refinement for {brand}",
            "Notes on {brand}",
            "Brief observation on {brand}",
            "One opportunity for {brand}"
        ],
        'high_score': [
            "Positive note on {brand}",
            "Small suggestion for {brand}",
            "{brand} — well done",
            "One observation on {brand}"
        ]
    },
    'casual': {
        'low_score': [
            "Yo {brand} — checked your site",
            "Quick look at {brand}",
            "{brand} — few things",
            "Poked around {brand}",
            "Saw a few things on {brand}",
            "Heads up on {brand}",
            "Just looked at {brand}",
            "{brand} — some easy fixes",
            "Peeked at {brand}",
            "Noticed some stuff on {brand}"
        ],
        'mid_score': [
            "Idea for {brand}",
            "One thing for {brand}",
            "{brand} — small tweak",
            "Quick thing on {brand}"
        ],
        'high_score': [
            "Cool store — {brand}",
            "{brand} looks solid",
            "Nice — {brand}",
            "One thing on {brand}"
        ]
    }
}

def _wix_pick(pool):
    try: return random.choice(pool)
    except: return pool[0] if pool else ''

def _wix_pick_subject(report, tone):
    tone = tone if tone in WIX_SUBJECT_TEMPLATES else 'friendly'
    dom = report.get('domain', '')
    brand = dom.split('.')[0].title() if dom and '.' in dom else 'there'
    overall = (report.get('scores') or {}).get('overall_score', 50)
    if overall < 50: tier = 'low_score'
    elif overall < 75: tier = 'mid_score'
    else: tier = 'high_score'
    pool = WIX_SUBJECT_TEMPLATES[tone].get(tier) or WIX_SUBJECT_TEMPLATES[tone]['mid_score']
    return random.choice(pool).replace('{brand}', brand)

def generate_wix_email(report, tone='friendly', sender_name='', email=''):
    tone = tone if tone in WIX_GREETINGS else 'friendly'
    dom = report.get('domain','')
    is_email_dom = '@' in dom if dom else False
    if is_email_dom:
        brand = dom.split('@')[0]; display_url = ''
    elif dom and dom.lower() in ('gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com'):
        brand = email.split('@')[0] if email and '@' in email else 'there'; display_url = ''
    else:
        brand = dom.split('.')[0].title() if dom else 'there'
        display_url = dom

    overall = (report.get('scores') or {}).get('overall_score', 0)
    issues = report.get('issues') or []
    prods = report.get('top_products') or []
    priority = {'high': 0, 'medium': 1, 'low': 2}
    sorted_issues = sorted(issues, key=lambda x: priority.get(x.get('severity','low'), 3))
    top_issues = sorted_issues[:3]
    issue_bullets = [i.get('title','') for i in top_issues]

    # Randomized subject
    subject = _wix_pick_subject(report, tone)

    greeting = _wix_pick(WIX_GREETINGS[tone]).replace('{brand}', brand)
    opener = _wix_pick(WIX_OPENERS_WITH_URL[tone] if display_url else WIX_OPENERS_NO_URL[tone]).replace('{url}', display_url)
    issues_intro = _wix_pick(WIX_ISSUES_INTROS[tone])
    score_line = _wix_pick(WIX_SCORE_LINES).replace('{score}', str(overall))
    cta = _wix_pick(WIX_CTAS[tone])
    signoff_line = _wix_pick(WIX_SIGNOFF_LINES[tone])
    signoff = _wix_pick(WIX_SIGNOFFS)
    signature = sender_name.strip() if sender_name and sender_name.strip() else "[Your name]"

    parts = [greeting, "", opener, ""]
    if prods:
        prod_names = [p.get('title','') for p in prods[:3] if p.get('title')]
        if prod_names:
            prod_intro = _wix_pick(WIX_PROD_INTROS[tone])
            parts.append(prod_intro)
            names = ", ".join([f'"{n[:40]}"' for n in prod_names[:2]])
            if len(prod_names) >= 3:
                names += f', and "{prod_names[2][:40]}"'
            parts.append(f"• {names}")
            parts.append("")

    parts.append(issues_intro)
    parts.append("")
    for b in issue_bullets:
        parts.append(f"• {b}")
    parts.append("")
    parts.append(score_line)
    parts.append("")
    parts.append(cta)
    parts.append("")
    parts.append(signoff_line)
    parts.append("")
    parts.append(signoff)
    parts.append(signature)
    return {'subject': subject, 'body': "\n".join(parts), 'tone': tone}

def run_wix_ingest():
    try:
        import importlib, ingest_leadita
        importlib.reload(ingest_leadita)
        return ingest_leadita.run(wix_get_db, wix_release)
    except Exception as e:
        return {'status': 'error', 'error': f'{e}'}

@wix_bp.route('/wix/recover-job/<int:job_id>', methods=['GET', 'POST'])
def wix_recover_job(job_id):
    if 'user_id' not in session: return jsonify({'success': False, 'error': 'auth'}), 401
    user_email = session.get('user_id')
    conn = wix_get_db()
    if not conn: return jsonify({'success': False, 'error': 'db'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT results FROM wix_email_jobs WHERE id=%s AND user_email=%s", (job_id, user_email))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'success': False, 'error': 'job not found'}), 404
        try: results = json.loads(row[0]) if row[0] else []
        except: results = []
        pairs = []
        for r in results:
            store = r.get('store', '')
            for e in r.get('emails', []):
                pairs.append(f"{e}:::{store}")
        if not pairs: return jsonify({'success': False, 'error': 'no emails found in job'}), 400
        cur = conn.cursor()
        cur.execute("""INSERT INTO wix_state (user_email, found_emails) VALUES (%s, %s)
            ON CONFLICT (user_email) DO UPDATE SET
            found_emails = EXCLUDED.found_emails, updated_at = NOW()""",
            (user_email, '|||'.join(pairs)))
        conn.commit(); cur.close()
        return jsonify({'success': True, 'recovered': len(pairs)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)[:200]}), 500
    finally: wix_release(conn)

def _navbar():
    return '''
<style>
.navbar{position:fixed;top:0;left:0;right:0;height:56px;background:#1f2937;color:white;display:flex;align-items:center;padding:0 16px;z-index:9999}
.navbar-title{font-size:18px;font-weight:bold;margin-left:12px}
.hamburger{background:none;border:none;color:white;font-size:24px;cursor:pointer;padding:4px 10px}
.drawer{position:fixed;top:0;left:-280px;width:280px;height:100vh;background:#111827;color:white;transition:left .3s;z-index:10000;padding-top:20px;overflow-y:auto}
.drawer.open{left:0}
.drawer-header{padding:16px 20px;font-size:18px;font-weight:bold;border-bottom:1px solid #374151;display:flex;justify-content:space-between;align-items:center}
.drawer-close{background:none;border:none;color:white;font-size:24px;cursor:pointer}
.drawer a{display:block;padding:14px 20px;color:white;text-decoration:none;border-bottom:1px solid #1f2937;font-size:15px}
.drawer a:hover{background:#1f2937}
.drawer-section{padding:12px 20px 6px;font-size:12px;font-weight:bold;color:#9ca3af;letter-spacing:1px;text-transform:uppercase;background:#0f172a}
.drawer-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:9998;display:none}
.drawer-overlay.show{display:block}
.page-content{padding-top:70px}
</style>
<div class="navbar">
<button class="hamburger" onclick="toggleDrawer()">☰</button>
<span class="navbar-title">Wix Tools</span>
</div>
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
<div class="drawer-header"><span>📧 Menu</span><button class="drawer-close" onclick="toggleDrawer()">×</button></div>
<div class="drawer-section">🎨 Wix</div>
<a href="/wix" onclick="closeDrawer()">🔍 Wix Store Finder</a>
<a href="/wix/finder" onclick="closeDrawer()">📧 Wix Email Finder</a>
<a href="/wix/verify" onclick="closeDrawer()">✅ Wix Verify</a>
<a href="/wix/scout" onclick="closeDrawer()">📨 Wix Scout</a>
<a href="/wix/audit" onclick="closeDrawer()">🚀 Wix Analyze & Send</a>
<div class="drawer-section">🛍️ Shopify</div>
<a href="/" onclick="closeDrawer()">🔍 Email Finder</a>
<a href="/discover" onclick="closeDrawer()">🎯 Store Discovery</a>
<a href="/verify" onclick="closeDrawer()">✅ Verify Emails</a>
<a href="/scout" onclick="closeDrawer()">📨 Email Scout</a>
<a href="/audit" onclick="closeDrawer()">🚀 Analyze & Send</a>
<div class="drawer-section">⚙️ Account</div>
<a href="/settings" onclick="closeDrawer()">⚙️ Settings</a>
<a href="/logout" onclick="closeDrawer()" style="color:#ef4444">🚪 Logout</a>
</div>
<script>
function toggleDrawer(){document.getElementById('drawer').classList.toggle('open');document.getElementById('drawerOverlay').classList.toggle('show')}
function closeDrawer(){document.getElementById('drawer').classList.remove('open');document.getElementById('drawerOverlay').classList.remove('show')}
</script>
'''

def _page(title, body):
    return f'<!DOCTYPE html><html><head><title>{title}</title><meta name="viewport" content="width=device-width,initial-scale=1">{_navbar()}</head><body style="margin:0;font-family:Arial"><div class="page-content">{body}</div></body></html>'

@wix_bp.route('/wix')
def wix_home():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🔍 Wix Store Finder</h1>
<p style="margin:4px 0 0 0;font-size:14px;opacity:0.9">Warehouse · 500 domains daily from Leadita</p>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🏭 Warehouse</h3>
<div id="warehouseStats" style="background:#f3f4f6;padding:12px;border-radius:6px;margin:10px 0;font-size:13px">Loading…</div>
<button onclick="ingestNow()" style="background:#7c3aed;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;width:100%;margin-bottom:10px">📥 Ingest Today's Batch</button>
<div style="display:flex;gap:8px">
<input type="number" id="wixPullCount" value="500" min="1" max="5000" style="flex:1;padding:10px;border:1px solid #ddd;border-radius:6px;box-sizing:border-box">
<button onclick="pullFromWarehouse()" style="flex:2;background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold">📧 Send to Wix Finder</button>
</div>
<button onclick="resetWarehouse()" style="background:#6b7280;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;margin-top:8px">🔄 Reset pulled rows</button>
<div id="ingestStatus" style="margin-top:10px"></div>
<div id="pullStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">🎯 Wix Pipeline</h3>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/wix/finder" style="flex:1;min-width:120px;background:#0d9488;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">📧 Finder</a>
<a href="/wix/verify" style="flex:1;min-width:120px;background:#f59e0b;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">✅ Verify</a>
<a href="/wix/scout" style="flex:1;min-width:120px;background:#8b5cf6;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">📨 Scout</a>
<a href="/wix/audit" style="flex:1;min-width:120px;background:#65a30d;color:white;padding:14px;border-radius:8px;text-decoration:none;text-align:center;font-weight:bold">🚀 Audit</a>
</div>
</div>
</div>
<script>
async function loadStats(){
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
    const r = await fetch('/wix/ingest', {method:'POST'});
    const d = await r.json();
    if(d.status === 'ok'){ s.innerHTML = '<div style="color:#166534;background:#f0fdf4;padding:10px;border-radius:5px"><b>✅ +'+d.new+' new</b> (skipped '+d.duplicates_skipped+')</div>'; loadStats(); }
    else { s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(d.error||'Unknown')+'</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">'+e.message+'</div>'; }
}
async function pullFromWarehouse(){
  const s = document.getElementById('pullStatus');
  const n = parseInt(document.getElementById('wixPullCount').value) || 500;
  s.innerHTML = '<p style="color:#666">⏳ Pulling…</p>';
  try{
    const r = await fetch('/wix/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({count:n})});
    const d = await r.json();
    if(d.success && d.pulled > 0){ sessionStorage.setItem('wix_pending_domains', d.domains.join('\\n')); window.location.href='/wix/finder'; }
    else { s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No pending rows</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">'+e.message+'</div>'; }
}
async function resetWarehouse(){ if(!confirm('Reset?')) return; const r = await fetch('/wix/warehouse/reset',{method:'POST'}); const d = await r.json(); if(d.success) { alert('✅ Reset '+d.reset); loadStats(); } }
window.onload = loadStats;
</script>'''
    return _page("Wix Store Finder", body)

@wix_bp.route('/wix/finder')
def wix_finder():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#0d9488,#0891b2);color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📧 Wix Email Finder</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<textarea id="urls" style="width:100%;height:200px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:13px;font-family:monospace;box-sizing:border-box" placeholder="example.wixsite.com"></textarea>
<button onclick="startFinder()" style="background:#0d9488;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">🚀 Find Emails (Background)</button>
<div id="result"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">📋 Last Jobs</h3>
<div id="jobs">Loading…</div>
</div>
</div>
<script>
window.onload = function(){ const c = sessionStorage.getItem('wix_pending_domains'); if(c){ document.getElementById('urls').value = c; sessionStorage.removeItem('wix_pending_domains'); } loadJobs(); setInterval(loadJobs, 5000); };
async function startFinder(){
  const s = document.getElementById('urls').value.split('\\n').map(x=>x.trim()).filter(x=>x);
  if(!s.length){ alert('Enter URLs'); return; }
  const r = await fetch('/wix/start-email-finder-job', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({urls:s})});
  const d = await r.json();
  document.getElementById('result').innerHTML = d.success ? '<div style="color:#166534;background:#f0fdf4;padding:12px;border-radius:5px"><b>✅ Job #'+d.job_id+' started</b></div>' : '<div style="color:red">'+d.error+'</div>';
  document.getElementById('urls').value = '';
  loadJobs();
}
async function loadJobs(){
  try{
    const r = await fetch('/wix/get-email-finder-jobs'); const d = await r.json();
    const c = document.getElementById('jobs');
    if(!d.jobs || !d.jobs.length){ c.innerHTML='<p style="color:#666">None yet.</p>'; return; }
    let html='';
    d.jobs.forEach(j => {
      const color = j.status==='completed'?'#16a34a':'#f59e0b';
      html += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+color+'">';
      html += '<b>Job #'+j.id+'</b> — '+j.emails+' emails from '+j.total+' stores';
      html += '<div style="display:flex;gap:6px;margin-top:8px">';
      html += '<button onclick="viewJob('+j.id+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">View</button>';
      if(j.status === 'completed' && j.emails > 0){
        html += '<button onclick="sendToVerify('+j.id+')" style="background:#f59e0b;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">📨 Send to Verify</button>';
      }
      html += '</div>';
      html += '<div id="job-'+j.id+'" style="display:none;margin-top:10px"></div>';
      html += '</div>';
    });
    c.innerHTML=html;
  }catch(e){}
}
async function viewJob(id){
  const c = document.getElementById('job-'+id);
  if(c.style.display === 'block'){ c.style.display = 'none'; return; }
  c.innerHTML = '<p style="color:#666">Loading…</p>';
  c.style.display = 'block';
  try{
    const r = await fetch('/wix/get-email-finder-job/'+id); const d = await r.json();
    if(!d.results || !d.results.length){ c.innerHTML = '<p style="color:#666">No results yet.</p>'; return; }
    let html = '<div style="background:white;padding:10px;border-radius:6px;max-height:300px;overflow-y:auto;font-size:13px">';
    d.results.forEach(r => {
      html += '<div style="padding:8px 0;border-bottom:1px solid #eee"><b>📦 '+r.store+'</b>';
      (r.emails||[]).forEach(e => { html += '<div style="padding-left:14px;color:#333">📧 '+e+'</div>'; });
      html += '</div>';
    });
    c.innerHTML = html + '</div>';
  }catch(e){ c.innerHTML = '<p style="color:red">Error</p>'; }
}
async function sendToVerify(id){
  try{
    const r = await fetch('/wix/get-email-finder-job/'+id); const d = await r.json();
    if(!d.results) return;
    const pairs = [];
    d.results.forEach(r => { (r.emails||[]).forEach(e => pairs.push({email:e, store:r.store||''})); });
    if(!pairs.length){ alert('No emails'); return; }
    await fetch('/wix/store-emails', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({pairs:pairs})});
    alert('✅ '+pairs.length+' emails saved. Go to Wix Verify → From Finder.');
  }catch(e){ alert('Error: '+e.message); }
}
</script>'''
    return _page("Wix Email Finder", body)

@wix_bp.route('/wix/verify')
def wix_verify_page():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">✅ Wix Verify</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📋 Jobs</h3>
<div id="jobs">Loading…</div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<textarea id="emailsInput" style="width:100%;height:180px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="fromFinder()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin:8px 8px 0 0">📥 From Finder</button>
<button onclick="start()" style="background:#f59e0b;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-top:8px">▶️ Start Verify</button>
<div id="msg" style="margin-top:10px"></div>
</div>
</div>
<script>
async function fromFinder(){ const r = await fetch('/wix/get-wix-emails'); const d = await r.json(); if(d.emails && d.emails.length){ document.getElementById('emailsInput').value = d.emails.join('\\n'); alert('Loaded '+d.emails.length); } else alert('No Wix emails yet'); }
async function start(){ const e = document.getElementById('emailsInput').value.split('\\n').map(x=>x.trim()).filter(x=>x); if(!e.length){ alert('Enter emails'); return; } const name = 'Wix Job '+new Date().toLocaleString(); const r = await fetch('/wix/verify-async', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({emails:e, name:name})}); const d = await r.json(); document.getElementById('msg').innerHTML = d.success ? '<p style="color:green">✅ Job #'+d.job_id+' started</p>' : '<p style="color:red">'+d.error+'</p>'; refresh(); }
async function refresh(){ const r = await fetch('/wix/verify-jobs'); const d = await r.json(); const c = document.getElementById('jobs'); if(!d.jobs || !d.jobs.length){ c.innerHTML='<p style="color:#666">None yet.</p>'; return; } let h=''; d.jobs.forEach(j => { const pct = j.total>0?Math.round(j.processed/j.total*100):0; const sc = j.status==='completed'?'#0d9488':(j.status==='running'?'#f59e0b':'#ef4444'); h += '<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+sc+'"><b>'+j.name+'</b><div style="background:#e0e0e0;border-radius:8px;overflow:hidden;margin-top:8px"><div style="width:'+pct+'%;height:16px;background:'+sc+';color:white;text-align:center;font-size:11px;line-height:16px">'+pct+'%</div></div><div style="font-size:13px;margin-top:6px">'+j.processed+'/'+j.total+' | ✅ '+j.valid+' | ❌ '+j.invalid+'</div></div>'; }); c.innerHTML=h; }
window.onload = function(){ refresh(); setInterval(refresh, 10000); };
</script>'''
    return _page("Wix Verify", body)

@wix_bp.route('/wix/scout')
def wix_scout_page():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#8b5cf6;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📨 Wix Scout</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<button onclick="fromVerified()" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin-bottom:10px">✅ From Wix Verified</button>
<textarea id="emailsInput" style="width:100%;height:160px;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<div id="count" style="margin-top:10px;font-weight:bold">0 recipients</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<input type="text" id="subjectLine" placeholder="Subject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box">
<textarea id="messageBody" rows="5" placeholder="Message" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box"></textarea>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<button onclick="start()" style="background:#8b5cf6;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">▶️ Start</button>
<button onclick="stop()" style="background:#ef4444;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">⏹️ Stop</button>
</div>
</div>
<script>
let recipients=[], i=0, running=false;
async function fromVerified(){ const r = await fetch('/wix/get-wix-verified-emails'); const d = await r.json(); if(d.emails && d.emails.length){ document.getElementById('emailsInput').value = d.emails.join('\\n'); recipients = d.emails; document.getElementById('count').textContent = recipients.length+' recipients'; } else alert('No verified Wix emails'); }
function start(){ const v = document.getElementById('emailsInput').value; recipients = v.split('\\n').map(x=>x.trim()).filter(x=>x); if(!recipients.length){ alert('None'); return; } running=true; i=0; next(); }
function stop(){ running=false; }
function next(){ if(!running || i>=recipients.length){ running=false; return; } const e = recipients[i]; const s = document.getElementById('subjectLine').value; const b = document.getElementById('messageBody').value; window.location.href='mailto:'+e+'?subject='+encodeURIComponent(s)+'&body='+encodeURIComponent(b); i++; }
document.addEventListener('visibilitychange', function(){ if(document.visibilityState==='visible' && running) setTimeout(next, 2000); });
</script>'''
    return _page("Wix Scout", body)

@wix_bp.route('/wix/audit')
def wix_audit_page():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:#65a30d;color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🚀 Wix Analyze & Send</h1>
<p style="margin:4px 0 0 0;font-size:14px">Extracts top products from HTML</p>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Import Wix Emails</h3>
<button onclick="imp('finder')" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px">🔍 From Finder</button>
<button onclick="imp('verified')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;margin:4px">✅ From Verified</button>
<div id="impStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📋 Queue (<span id="qc">0</span>)</h3>
<div id="queue" style="margin-top:12px">Loading…</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🚀 Start Processing</h3>
<label style="font-weight:bold;font-size:13px">Your name:</label>
<input type="text" id="senderName" placeholder="e.g. Daniel Phillips" style="width:100%;padding:8px;border:1px solid #ddd;border-radius:5px;margin:5px 0 15px 0;box-sizing:border-box">
<div style="background:linear-gradient(135deg,#1f2937,#374151);color:white;padding:16px;border-radius:10px;margin-bottom:15px">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
<span style="font-size:15px;font-weight:bold">📧 Sent this session</span>
<span id="counterText" style="font-size:20px;font-weight:bold">0 / 70</span>
</div>
<div style="background:#111827;border-radius:8px;overflow:hidden;height:14px">
<div id="counterBar" style="width:0%;height:100%;background:linear-gradient(90deg,#22c55e,#16a34a)"></div>
</div>
<div id="counterHint" style="font-size:12px;margin-top:8px;opacity:0.85">Auto mode pauses at every milestone.</div>
<div style="margin-top:12px;padding-top:12px;border-top:1px solid #4b5563">
<label style="font-size:13px;font-weight:bold;display:block;margin-bottom:6px">⚙️ Pause every N emails:</label>
<div style="display:flex;gap:8px;align-items:center">
<input type="number" id="limitInput" value="70" min="1" max="10000" style="flex:1;padding:8px;border:1px solid #4b5563;border-radius:6px;background:#111827;color:white;font-size:14px;box-sizing:border-box">
<button onclick="saveLimit()" style="background:#0d9488;color:white;padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-weight:bold">Save</button>
</div>
<div id="limitMsg" style="font-size:12px;color:#86efac;margin-top:4px"></div>
</div>
<div style="display:flex;gap:8px;margin-top:12px">
<button id="continueBtn" onclick="continueAuto()" style="display:none;flex:1;background:#0d9488;color:white;padding:10px;border:none;border-radius:6px;cursor:pointer;font-weight:bold">▶️ Continue</button>
<button onclick="resetCounter()" style="background:#dc2626;color:white;padding:10px 16px;border:none;border-radius:6px;cursor:pointer">🔄 Reset</button>
</div>
</div>
<div id="pipelineBox" style="background:#eff6ff;border-left:4px solid #3b82f6;padding:10px 14px;border-radius:8px;margin-bottom:15px;font-size:13px;color:#1e40af;display:none"><span id="pipelineText"></span></div>
<button onclick="startManual()" style="background:#3b82f6;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;margin-right:10px;margin-bottom:10px">▶️ Start Manual</button>
<button onclick="startAutoMode()" style="background:#0d9488;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;margin-bottom:10px">⚡ Start Auto</button>
<button onclick="stopAutoMode()" id="stopBtn" style="background:#ef4444;color:white;padding:14px 24px;border:none;border-radius:8px;cursor:pointer;font-size:16px;display:none;margin-left:10px">⏹️ Stop Auto</button>
<div id="modeStatus" style="margin-top:10px"></div>
</div>
<div id="auditBox" style="display:none">
<div id="label" style="background:#65a30d;color:white;padding:10px;border-radius:8px;font-weight:bold;margin-bottom:15px"></div>
<div id="result"></div>
<div id="outreach" style="display:none;background:white;padding:20px;border-radius:10px;margin-top:20px">
<h3 style="margin-top:0">✉️ Email</h3>
<div style="margin-bottom:10px">
<button onclick="regen('friendly')" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px;margin-right:5px">😊 Friendly</button>
<button onclick="regen('professional')" style="background:#3b82f6;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px;margin-right:5px">💼 Professional</button>
<button onclick="regen('casual')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer;font-size:13px">😎 Casual</button>
</div>
<label style="font-weight:bold;font-size:13px">Subject:</label>
<input type="text" id="genSubject" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin:5px 0 10px 0;box-sizing:border-box">
<label style="font-weight:bold;font-size:13px">Message:</label>
<textarea id="genBody" rows="10" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="sendIt()" style="background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px;margin-right:8px">📨 Send & Open Gmail</button>
<button onclick="skipCurrent()" style="background:#6b7280;color:white;padding:12px 24px;border:none;border-radius:6px;cursor:pointer;font-size:15px;margin-top:12px">⏭️ Skip</button>
</div>
</div>
</div>

<div id="toneModal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.6);z-index:10000;align-items:center;justify-content:center">
  <div style="background:white;padding:24px;border-radius:12px;max-width:340px;width:90%;text-align:center">
    <h3 style="margin:0 0 16px 0">Choose Email Tone</h3>
    <button onclick="pickTone('friendly')" style="display:block;width:100%;background:#0d9488;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:15px;margin-bottom:8px">😊 Friendly</button>
    <button onclick="pickTone('professional')" style="display:block;width:100%;background:#3b82f6;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:15px;margin-bottom:8px">💼 Professional</button>
    <button onclick="pickTone('casual')" style="display:block;width:100%;background:#f59e0b;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:15px">😎 Casual</button>
    <button onclick="closeToneModal()" style="display:block;width:100%;background:#e5e7eb;color:#374151;padding:10px;border:none;border-radius:8px;cursor:pointer;font-size:14px;margin-top:12px">Cancel</button>
  </div>
</div>

<script>
let currentItem = null, currentReport = null, autoMode = false, autoTone = 'friendly', pendingAction = false;
let SEND_LIMIT = 70;
const MAX_PARALLEL = 3;
let readyBuffer = [], preparingSet = new Set(), refilling = false;

function updatePipelineUI(){
  const box = document.getElementById('pipelineBox');
  const txt = document.getElementById('pipelineText');
  if(autoMode){ box.style.display='block'; txt.textContent = '⚡ Pipeline: '+readyBuffer.length+' ready · '+preparingSet.size+' preparing'; }
  else { box.style.display='none'; }
}

async function loadCounter(){
  try{ const r = await fetch('/wix/get-counter'); const d = await r.json(); SEND_LIMIT = d.limit; updateCounterUI(d.count, d.next_milestone, d.at_milestone); document.getElementById('limitInput').value = d.limit; }catch(e){}
}

function updateCounterUI(count, next, at){
  document.getElementById('counterText').textContent = count + ' / ' + next;
  const within = count % SEND_LIMIT;
  const pct = count > 0 && within === 0 ? 100 : Math.round((within / SEND_LIMIT) * 100);
  const bar = document.getElementById('counterBar');
  bar.style.width = pct + '%';
  const hint = document.getElementById('counterHint');
  const contBtn = document.getElementById('continueBtn');
  if(at){ bar.style.background='linear-gradient(90deg,#ef4444,#dc2626)'; hint.innerHTML='🛑 Milestone reached ('+count+' sent). Paused.'; hint.style.color='#fca5a5'; contBtn.style.display='block'; }
  else { bar.style.background='linear-gradient(90deg,#22c55e,#16a34a)'; hint.innerHTML='Next pause at '+next+' emails.'; hint.style.color=''; contBtn.style.display='none'; }
}

async function saveLimit(){
  const v = parseInt(document.getElementById('limitInput').value);
  if(!v || v < 1){ alert('Enter >= 1'); return; }
  const r = await fetch('/wix/set-limit', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({limit:v})});
  const d = await r.json();
  if(d.success){ SEND_LIMIT = d.limit; document.getElementById('limitMsg').textContent = '✅ Pause every '+d.limit; setTimeout(()=>{document.getElementById('limitMsg').textContent='';}, 2500); loadCounter(); }
}

async function resetCounter(){ if(!confirm('Reset counter?')) return; autoMode=false; readyBuffer=[]; updatePipelineUI(); await fetch('/wix/reset-counter', {method:'POST'}); await loadCounter(); document.getElementById('modeStatus').innerHTML='<p style="color:red">🔄 Reset.</p>'; document.getElementById('stopBtn').style.display='none'; }

async function continueAuto(){ await loadCounter(); autoMode=true; pendingAction=false; document.getElementById('modeStatus').innerHTML='<p style="color:green">▶️ Continuing...</p>'; document.getElementById('stopBtn').style.display='inline-block'; refillPipeline(); nextAuto(); }

function playAlarm(){
  try{ const ctx = new (window.AudioContext||window.webkitAudioContext)(); const osc = ctx.createOscillator(); const g = ctx.createGain(); osc.connect(g); g.connect(ctx.destination); osc.type='square'; osc.frequency.value=880; g.gain.value=0.15; osc.start(); const t = ctx.currentTime; for(let i=0;i<3;i++){ g.gain.setValueAtTime(0.15, t+i*0.4); g.gain.setValueAtTime(0, t+i*0.4+0.2); } osc.stop(t+1.4); }catch(e){}
}

async function imp(src){ const s = document.getElementById('impStatus'); s.innerHTML='⏳'; const r = await fetch('/wix/import-to-queue', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({source:src})}); const d = await r.json(); s.innerHTML = d.success ? '<span style="color:green">✅ Added '+d.added+' (skipped '+d.skipped+')</span>' : '<span style="color:red">'+d.error+'</span>'; loadQueue(); }

async function loadQueue(){
  const r = await fetch('/wix/get-audit-queue'); const d = await r.json();
  document.getElementById('qc').textContent = d.items.length;
  const c = document.getElementById('queue');
  if(!d.items.length){ c.innerHTML='<p style="color:#666">Empty.</p>'; return; }
  let h='';
  d.items.forEach(i => {
    const col = i.status==='done'?'#16a34a':(i.status==='current'?'#3b82f6':(i.status==='skipped'?'#6b7280':'#f59e0b'));
    h += '<div style="padding:10px;border-radius:6px;margin:6px 0;background:#f9f9f9;border-left:4px solid '+col+'"><b>'+i.email+'</b><br><span style="font-size:12px;color:#666">'+i.domain+'</span></div>';
  });
  c.innerHTML=h;
}

async function prepareItem(id){
  try{
    const r = await fetch('/wix/analyze-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:id})});
    const d = await r.json();
    if(!d.success || !d.item) return null;
    const item = d.item;
    const name = document.getElementById('senderName').value.trim();
    const er = await fetch('/wix/generate-email', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({report:item.report, tone:autoTone, sender_name:name, email:item.email})});
    const ed = await er.json();
    return {id:item.id, email:item.email, domain:item.domain, report:item.report, subject: ed.success ? ed.subject : '', message: ed.success ? ed.body : ''};
  }catch(e){ return null; }
}

async function refillPipeline(){
  if(refilling) return;
  refilling = true;
  try{
    while(autoMode && (readyBuffer.length + preparingSet.size) < MAX_PARALLEL){
      let nr; try{ nr = await fetch('/wix/get-next-pending'); }catch(e){ break; }
      const nd = await nr.json();
      if(!nd.item) break;
      const id = nd.item.id;
      try{ await fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:id, status:'current'})}); }catch(e){ break; }
      preparingSet.add(id);
      loadQueue(); updatePipelineUI();
      (async () => { const item = await prepareItem(id); preparingSet.delete(id); if(item) readyBuffer.push(item); updatePipelineUI(); loadQueue(); refillPipeline(); })();
      await new Promise(r => setTimeout(r, 100));
    }
  } finally { refilling = false; updatePipelineUI(); }
}

async function safeGetNextPending(retries=5){
  for(let i=0;i<retries;i++){ try{ const r = await fetch('/wix/get-next-pending'); if(r.ok){ const d = await r.json(); return {ok:true, item:d.item||null}; } }catch(e){} await new Promise(r => setTimeout(r, 1000)); }
  return {ok:false, item:null};
}

async function showNextReady(){
  if(!autoMode) return;
  while(autoMode && readyBuffer.length === 0){
    document.getElementById('auditBox').style.display='block';
    document.getElementById('label').textContent = '⏳ Preparing...';
    document.getElementById('result').innerHTML = '<p style="color:#666;padding:20px;text-align:center">⚡ Running ('+preparingSet.size+' preparing, '+readyBuffer.length+' ready)...</p>';
    document.getElementById('outreach').style.display='none';
    updatePipelineUI();
    await new Promise(r => setTimeout(r, 500));
    refillPipeline();
    if(preparingSet.size === 0 && readyBuffer.length === 0){
      const chk = await safeGetNextPending(5);
      if(chk.ok && !chk.item) break;
    }
  }
  if(!autoMode) return;
  if(readyBuffer.length === 0){ autoMode=false; updatePipelineUI(); document.getElementById('modeStatus').innerHTML='<p style="color:blue">🎉 Complete!</p>'; document.getElementById('stopBtn').style.display='none'; return; }
  const item = readyBuffer.shift();
  currentItem = {id:item.id, email:item.email, domain:item.domain, report:item.report};
  currentReport = item.report;
  document.getElementById('auditBox').style.display='block';
  document.getElementById('label').textContent = '📧 '+item.email+' → '+item.domain+' (buffer: '+readyBuffer.length+', preparing: '+preparingSet.size+')';
  renderReport(item.report);
  document.getElementById('outreach').style.display='block';
  document.getElementById('genSubject').value = item.subject;
  document.getElementById('genBody').value = item.message;
  updatePipelineUI(); loadQueue(); refillPipeline();
  if(autoMode && !pendingAction){ pendingAction=true; setTimeout(async()=>{ pendingAction=false; await autoSend(); }, 150); }
}

async function nextAuto(){
  if(!autoMode) return;
  try{
    const r = await fetch('/wix/get-counter'); const d = await r.json();
    SEND_LIMIT = d.limit;
    updateCounterUI(d.count, d.next_milestone, d.at_milestone);
    if(d.at_milestone){ autoMode=false; pendingAction=false; playAlarm(); document.getElementById('modeStatus').innerHTML='<p style="color:red;font-weight:bold">🛑 Milestone ('+d.count+'). Paused.</p>'; document.getElementById('stopBtn').style.display='none'; return; }
  }catch(e){}
  await showNextReady();
}

async function autoSend(){
  if(!autoMode) return;
  if(!currentItem){ nextAuto(); return; }
  const subj = document.getElementById('genSubject').value;
  const body = document.getElementById('genBody').value;
  if(!subj || !body){ await fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:currentItem.id, status:'skipped'})}); nextAuto(); return; }
  const id = currentItem.id, em = currentItem.email;
  await fetch('/wix/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:em})});
  await fetch('/wix/delete-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:id})});
  try{ const ir = await fetch('/wix/increment-counter', {method:'POST'}); const idt = await ir.json(); SEND_LIMIT = idt.limit; updateCounterUI(idt.count, idt.next_milestone, idt.at_milestone); }catch(e){}
  loadQueue();
  localStorage.setItem('wix_last_sent_id', id.toString());
  window.location.href = 'mailto:'+em+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body);
}

document.addEventListener('visibilitychange', function(){
  if(document.visibilityState === 'visible' && autoMode){
    const last = localStorage.getItem('wix_last_sent_id');
    if(last){ localStorage.removeItem('wix_last_sent_id'); currentItem = null; setTimeout(nextAuto, 200); }
  }
});

async function startManual(){
  autoMode = false; pendingAction = false;
  document.getElementById('modeStatus').innerHTML='<p style="color:blue">▶️ Manual mode: click Analyze Next</p>';
  document.getElementById('stopBtn').style.display='none';
  updatePipelineUI();
}

function showToneModal(){ document.getElementById('toneModal').style.display='flex'; }
function closeToneModal(){ document.getElementById('toneModal').style.display='none'; }

function pickTone(tone){
  closeToneModal();
  autoTone = tone;
  autoMode = true;
  pendingAction = false;
  readyBuffer = []; preparingSet.clear();
  document.getElementById('modeStatus').innerHTML='<p style="color:green">⚡ Auto mode ON ('+tone+')</p>';
  document.getElementById('stopBtn').style.display='inline-block';
  refillPipeline();
  nextAuto();
}

async function startAutoMode(){ await fetch('/wix/reset-counter', {method:'POST'}); await loadCounter(); showToneModal(); }

function stopAutoMode(){
  autoMode=false; pendingAction=false;
  for(const it of readyBuffer){ fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:it.id, status:'pending'})}); }
  readyBuffer = [];
  updatePipelineUI();
  document.getElementById('modeStatus').innerHTML='<p style="color:red">⏹️ Stopped</p>';
  document.getElementById('stopBtn').style.display='none';
}

async function analyzeNext(){
  autoMode = false;
  const r = await fetch('/wix/get-next-pending'); const d = await r.json();
  if(!d.item){ alert('Queue empty'); return; }
  currentItem = d.item;
  document.getElementById('auditBox').style.display='block';
  document.getElementById('result').innerHTML='<p style="color:#666;padding:20px;text-align:center">⏳ Analyzing…</p>';
  document.getElementById('outreach').style.display='none';
  await fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:currentItem.id, status:'current'})});
  const rr = await fetch('/wix/analyze-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:currentItem.id})});
  const dd = await rr.json();
  if(dd.success){
    currentReport = dd.item.report;
    document.getElementById('label').textContent = '📧 '+dd.item.email+' → '+dd.item.domain;
    renderReport(dd.item.report);
    document.getElementById('outreach').style.display='block';
    await genEmail();
    loadQueue();
  }
}

async function genEmail(){
  const r = await fetch('/wix/generate-email', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({report:currentReport, tone:autoTone, sender_name:document.getElementById('senderName').value, email:currentItem?currentItem.email:''})});
  const d = await r.json();
  if(d.success){ document.getElementById('genSubject').value = d.subject; document.getElementById('genBody').value = d.body; }
}
function regen(tone){ autoTone = tone; genEmail(); }

function renderReport(r){
  const sc=r.scores||{}, iss=r.issues||[], prods=r.top_products||[];
  let h='<div style="background:white;padding:20px;border-radius:10px;margin-bottom:15px"><h3>Scores</h3>';
  ['overall_score','trust_score','technical_score','marketing_score'].forEach(k => {
    const v = sc[k]||0;
    const c = v>=75?'#16a34a':(v>=50?'#f59e0b':'#ef4444');
    h += '<div style="margin:10px 0"><b>'+k.replace('_score','')+'</b> <span style="color:'+c+'">'+v+'%</span><div style="background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+v+'%;height:12px;background:'+c+'"></div></div></div>';
  });
  h+='</div>';
  if(prods.length){ h += '<div style="background:white;padding:20px;border-radius:10px;margin-bottom:15px"><h3>🛍️ Top Products</h3>'; prods.forEach(p => { h += '<div style="padding:8px 0;border-bottom:1px solid #eee"><b>'+p.title+'</b>'+(p.price?' — '+p.price:'')+'</div>'; }); h+='</div>'; }
  if(iss.length){ h += '<div style="background:white;padding:20px;border-radius:10px"><h3 style="color:#991b1b">⚠️ Issues</h3>'; iss.forEach(i => { h += '<div style="background:#fef2f2;border-left:4px solid #ef4444;padding:10px;border-radius:6px;margin:8px 0"><b>'+i.title+'</b><div style="font-size:13px">'+i.description+'</div></div>'; }); h+='</div>'; }
  document.getElementById('result').innerHTML = h;
}

async function sendIt(){
  if(!currentItem) return;
  await fetch('/wix/mark-sent', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email:currentItem.email})});
  await fetch('/wix/delete-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:currentItem.id})});
  await fetch('/wix/increment-counter', {method:'POST'});
  await loadCounter(); loadQueue();
  window.location.href = 'mailto:'+currentItem.email+'?subject='+encodeURIComponent(document.getElementById('genSubject').value)+'&body='+encodeURIComponent(document.getElementById('genBody').value);
}

async function skipCurrent(){
  if(!currentItem) return;
  await fetch('/wix/update-queue-item', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:currentItem.id, status:'skipped'})});
  document.getElementById('auditBox').style.display='none';
  currentItem = null;
  loadQueue();
  if(autoMode) nextAuto();
}

window.onload = function(){ loadQueue(); loadCounter(); };
</script>'''
    return _page("Wix Analyze & Send", body)

# ==========================================
# WIX COUNTER ROUTES
# ==========================================
@wix_bp.route('/wix/get-counter')
def wix_get_counter():
    if 'user_id' not in session: return jsonify({'count':0,'limit':70,'next_milestone':70,'at_milestone':False}), 401
    return jsonify(wix_counter_status(session.get('user_id')))

@wix_bp.route('/wix/increment-counter', methods=['POST'])
def wix_increment_counter():
    if 'user_id' not in session: return jsonify({'count':0,'limit':70,'next_milestone':70,'at_milestone':False}), 401
    user_email = session.get('user_id')
    conn = wix_get_db()
    if not conn: return jsonify(wix_counter_status(user_email))
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_state (user_email, session_sent_count) VALUES (%s, 0) ON CONFLICT (user_email) DO NOTHING", (user_email,))
        cur.execute("UPDATE wix_state SET session_sent_count = COALESCE(session_sent_count,0) + 1, updated_at=NOW() WHERE user_email=%s", (user_email,))
        conn.commit(); cur.close()
    except Exception as e:
        print(f"increment: {e}")
    finally: wix_release(conn)
    return jsonify(wix_counter_status(user_email))

@wix_bp.route('/wix/reset-counter', methods=['POST'])
def wix_reset_counter():
    if 'user_id' not in session: return jsonify(wix_counter_status(''))
    user_email = session.get('user_id')
    conn = wix_get_db()
    if not conn: return jsonify(wix_counter_status(user_email))
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_state (user_email, session_sent_count) VALUES (%s, 0) ON CONFLICT (user_email) DO NOTHING", (user_email,))
        cur.execute("UPDATE wix_state SET session_sent_count = 0, updated_at=NOW() WHERE user_email=%s", (user_email,))
        conn.commit(); cur.close()
    except: pass
    finally: wix_release(conn)
    return jsonify(wix_counter_status(user_email))

@wix_bp.route('/wix/set-limit', methods=['POST'])
def wix_set_limit():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    user_email = session.get('user_id')
    try: limit = int(request.json.get('limit', 70))
    except: limit = 70
    if limit < 1: limit = 1
    if limit > 10000: limit = 10000
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_state (user_email, send_limit) VALUES (%s, %s) ON CONFLICT (user_email) DO UPDATE SET send_limit=EXCLUDED.send_limit, updated_at=NOW()", (user_email, limit))
        conn.commit(); cur.close()
    except: pass
    finally: wix_release(conn)
    return jsonify({'success':True, 'limit':limit})

# ==========================================
# WAREHOUSE / FINDER / VERIFY / QUEUE API
# ==========================================
@wix_bp.route('/wix/ingest', methods=['GET','POST'])
def wix_ingest():
    header_secret = request.headers.get('X-Cron-Secret', '')
    cron_secret = os.environ.get('CRON_SECRET', '')
    valid_cron = bool(cron_secret) and header_secret == cron_secret
    valid_user = ('user_id' in session) and (header_secret == 'MANUAL_FROM_UI' or (request.method == 'POST' and not header_secret))
    if not (valid_cron or valid_user):
        return jsonify({'status': 'error', 'error': 'forbidden'}), 403
    if valid_user and not valid_cron:
        result = run_wix_ingest()
        return jsonify(result), (200 if result.get('status') == 'ok' else 500)
    def _bg():
        try: print(f"🕒 [wix cron] {run_wix_ingest()}")
        except Exception as e: print(f"🕒 [wix cron] error: {e}")
    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({'status': 'accepted'}), 202

@wix_bp.route('/wix/warehouse')
def wix_warehouse():
    if 'user_id' not in session: return jsonify({'error':'auth'}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'error':'db'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM wix_warehouse"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='pending'"); pending = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM wix_warehouse WHERE status='processing'"); processing = cur.fetchone()[0]
        cur.execute("SELECT DATE(created_at) d, COUNT(*) c FROM wix_warehouse GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC LIMIT 14")
        daily = [{'date':str(r[0]),'count':r[1]} for r in cur.fetchall()]
        cur.close()
        return jsonify({'total':total,'pending':pending,'processing':processing,'daily_last_14':daily})
    except Exception as e: return jsonify({'error':str(e)[:200]}), 500
    finally: wix_release(conn)

@wix_bp.route('/wix/request', methods=['POST'])
def wix_request():
    if 'user_id' not in session: return jsonify({'success':False,'error':'auth'}), 401
    n = int((request.get_json(silent=True) or {}).get('count', 500)); n = max(1, min(n, 5000))
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("UPDATE wix_warehouse SET status='processing' WHERE id IN (SELECT id FROM wix_warehouse WHERE status='pending' ORDER BY created_at DESC LIMIT %s) RETURNING domain", (n,))
        rows = cur.fetchall(); conn.commit(); cur.close()
        return jsonify({'success':True, 'pulled': len(rows), 'domains': [r[0] for r in rows]})
    except Exception as e: return jsonify({'success':False,'error':str(e)[:200]})
    finally: wix_release(conn)

@wix_bp.route('/wix/warehouse/reset', methods=['POST'])
def wix_reset():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("UPDATE wix_warehouse SET status='pending' WHERE status='processing'")
        n = cur.rowcount; conn.commit(); cur.close()
        return jsonify({'success':True,'reset':n})
    except: return jsonify({'success':False})
    finally: wix_release(conn)

@wix_bp.route('/wix/start-email-finder-job', methods=['POST'])
def wix_start_finder():
    if 'user_id' not in session: return jsonify({'success':False,'error':'auth'}), 401
    user_email = session.get('user_id')
    urls = request.json.get('urls', [])
    if not urls: return jsonify({'success':False,'error':'No URLs'})
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_email_jobs (user_email, total, remaining_urls, results, status) VALUES (%s,%s,%s,'[]','pending') RETURNING id", (user_email, len(urls), '|||'.join(urls)))
        job_id = cur.fetchone()[0]; conn.commit(); cur.close()
    finally: wix_release(conn)
    threading.Thread(target=wix_process_email_job, args=(job_id,), daemon=True).start()
    return jsonify({'success':True,'job_id':job_id,'total':len(urls)})

@wix_bp.route('/wix/get-email-finder-jobs')
def wix_get_finder_jobs():
    if 'user_id' not in session: return jsonify({'jobs':[]}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'jobs':[]})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, total, emails_found, status, created_at FROM wix_email_jobs WHERE user_email=%s ORDER BY created_at DESC LIMIT 5", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'jobs':[{'id':r[0],'total':r[1],'emails':r[2],'status':r[3],'created_at':str(r[4])[:16]} for r in rows]})
    except: return jsonify({'jobs':[]})
    finally: wix_release(conn)

@wix_bp.route('/wix/get-email-finder-job/<int:jid>')
def wix_get_finder_job(jid):
    if 'user_id' not in session: return jsonify({'results':[]}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'results':[]})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, total, results, status FROM wix_email_jobs WHERE id=%s AND user_email=%s", (jid, session.get('user_id')))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'results':[]})
        try: results = json.loads(row[2]) if row[2] else []
        except: results = []
        return jsonify({'id':row[0],'total':row[1],'results':results,'status':row[3]})
    except: return jsonify({'results':[]})
    finally: wix_release(conn)

@wix_bp.route('/wix/store-emails', methods=['POST'])
def wix_store_emails():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    pairs = request.json.get('pairs', [])
    items = []
    for p in pairs:
        e = p.get('email','').strip().lower()
        s = (p.get('store','') or '').strip().lower()
        if e: items.append(f"{e}:::{s}" if s else e)
    if items: wix_save_state(session.get('user_id'), found_emails='|||'.join(items))
    return jsonify({'success':True})

@wix_bp.route('/wix/get-wix-emails')
def wix_get_emails():
    if 'user_id' not in session: return jsonify({'emails':[]}), 401
    state = wix_load_state(session.get('user_id'))
    emails = []
    for item in state.get('found_emails', []):
        if not item: continue
        emails.append(item.split(':::',1)[0].strip() if ':::' in item else item.strip())
    return jsonify({'emails':[e for e in emails if e]})

@wix_bp.route('/wix/verify-async', methods=['POST'])
def wix_verify_async():
    if 'user_id' not in session: return jsonify({'error':'auth'}), 401
    user_email = session.get('user_id')
    d = request.json; emails = d.get('emails', [])
    name = d.get('name', f"Wix Job {int(time.time())}")
    if not emails: return jsonify({'error':'No emails'}), 400
    conn = wix_get_db()
    if not conn: return jsonify({'error':'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_verify_jobs (user_email, job_name, total, remaining_emails, valid_emails, invalid_emails, status) VALUES (%s,%s,%s,%s,'','','pending') RETURNING id", (user_email, name, len(emails), '|||'.join(emails)))
        job_id = cur.fetchone()[0]; conn.commit(); cur.close()
    finally: wix_release(conn)
    threading.Thread(target=wix_verify_worker, args=(job_id,), daemon=True).start()
    return jsonify({'success':True,'job_id':job_id,'total':len(emails)})

@wix_bp.route('/wix/verify-jobs')
def wix_verify_jobs():
    if 'user_id' not in session: return jsonify({'jobs':[]}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'jobs':[]})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, job_name, total, processed, status, created_at, valid_emails, invalid_emails FROM wix_verify_jobs WHERE user_email=%s ORDER BY created_at DESC LIMIT 5", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'jobs':[{'id':r[0],'name':r[1],'total':r[2],'processed':r[3],'status':r[4],'created_at':str(r[5]),'valid':len(r[6].split('|||')) if r[6] else 0,'invalid':len(r[7].split('|||')) if r[7] else 0} for r in rows]})
    except: return jsonify({'jobs':[]})
    finally: wix_release(conn)

@wix_bp.route('/wix/get-wix-verified-emails')
def wix_get_verified():
    if 'user_id' not in session: return jsonify({'emails':[]}), 401
    state = wix_load_state(session.get('user_id'))
    return jsonify({'emails':[e.strip() for e in state.get('verified_emails', []) if e.strip()]})

@wix_bp.route('/wix/import-to-queue', methods=['POST'])
def wix_import_to_queue():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    user_email = session.get('user_id')
    source = request.json.get('source','')
    state = wix_load_state(user_email)
    pairs = []
    if source == 'finder':
        for item in state.get('found_emails', []):
            if ':::' in item: pairs.append(item.split(':::',1))
            elif item: pairs.append([item, item])
    elif source == 'verified':
        fp = {}
        for item in state.get('found_emails', []):
            if ':::' in item:
                parts = item.split(':::',1); fp[parts[0]] = parts[1]
        for e in state.get('verified_emails', []):
            if e: pairs.append([e, fp.get(e, '')])
    if not pairs: return jsonify({'success':False,'error':'No emails'})
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    added = skipped = 0
    try:
        cur = conn.cursor()
        for email, store in pairs:
            email = email.strip().lower()
            if not email or '@' not in email: continue
            store = (store or email).strip().lower()
            try:
                cur.execute("INSERT INTO wix_audit_queue (user_email,email,domain,status) VALUES (%s,%s,%s,'pending') ON CONFLICT (user_email, email) DO NOTHING", (user_email, email, store))
                if cur.rowcount > 0: added += 1
                else: skipped += 1
            except: pass
        conn.commit(); cur.close()
    except: pass
    finally: wix_release(conn)
    return jsonify({'success':True,'added':added,'skipped':skipped})

@wix_bp.route('/wix/get-audit-queue')
def wix_get_queue():
    if 'user_id' not in session: return jsonify({'items':[]}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'items':[]})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id,email,domain,status FROM wix_audit_queue WHERE user_email=%s ORDER BY CASE status WHEN 'pending' THEN 1 WHEN 'current' THEN 2 ELSE 3 END, added_at ASC", (session.get('user_id'),))
        rows = cur.fetchall(); cur.close()
        return jsonify({'items':[{'id':r[0],'email':r[1],'domain':r[2],'status':r[3]} for r in rows]})
    finally: wix_release(conn)

@wix_bp.route('/wix/update-queue-item', methods=['POST'])
def wix_update_queue():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    d = request.json; item_id = d.pop('id', None)
    if not item_id: return jsonify({'success':False})
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        for k,v in d.items():
            if v is not None:
                cur.execute(f"UPDATE wix_audit_queue SET {k}=%s, updated_at=NOW() WHERE id=%s AND user_email=%s", (v, item_id, session.get('user_id')))
        conn.commit(); cur.close()
        return jsonify({'success':True})
    except: return jsonify({'success':False})
    finally: wix_release(conn)

@wix_bp.route('/wix/delete-queue-item', methods=['POST'])
def wix_delete_queue():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM wix_audit_queue WHERE id=%s AND user_email=%s", (request.json.get('id'), session.get('user_id')))
        conn.commit(); cur.close()
        return jsonify({'success':True})
    except: return jsonify({'success':False})
    finally: wix_release(conn)

@wix_bp.route('/wix/get-next-pending')
def wix_next_pending():
    if 'user_id' not in session: return jsonify({'item':None}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'item':None})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id,email,domain FROM wix_audit_queue WHERE user_email=%s AND status='pending' ORDER BY added_at ASC LIMIT 1", (session.get('user_id'),))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'item':None})
        return jsonify({'item':{'id':row[0],'email':row[1],'domain':row[2]}})
    finally: wix_release(conn)

@wix_bp.route('/wix/analyze-queue-item', methods=['POST'])
def wix_analyze_item():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    item_id = request.json.get('id')
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("SELECT id,email,domain,report FROM wix_audit_queue WHERE id=%s AND user_email=%s", (item_id, session.get('user_id')))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'success':False,'error':'Not found'})
        item_id, email, domain, rep = row
        if rep:
            try: report = json.loads(rep) if isinstance(rep,str) else rep
            except: report = None
            if report: return jsonify({'success':True,'item':{'id':item_id,'email':email,'domain':domain,'report':report}})
    finally: wix_release(conn)
    report = audit_store_wix(domain, "WIX"+str(int(time.time())))
    conn = wix_get_db()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("UPDATE wix_audit_queue SET report=%s, status='current', updated_at=NOW() WHERE id=%s", (json.dumps(report), item_id))
            cur.execute("INSERT INTO wix_audit_history (user_email,domain,report) VALUES (%s,%s,%s)", (session.get('user_id'), domain, json.dumps(report)))
            conn.commit(); cur.close()
        finally: wix_release(conn)
    return jsonify({'success':True,'item':{'id':item_id,'email':email,'domain':domain,'report':report}})

@wix_bp.route('/wix/generate-email', methods=['POST'])
def wix_generate_email():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    d = request.json
    report = d.get('report', {})
    tone = d.get('tone','friendly')
    name = d.get('sender_name','').strip() or ''
    email = d.get('email','').strip()
    if not report: return jsonify({'success':False})
    try:
        r = generate_wix_email(report, tone, name, email)
        return jsonify({'success':True,'subject':r['subject'],'body':r['body']})
    except Exception as e: return jsonify({'success':False,'error':str(e)})

@wix_bp.route('/wix/mark-sent', methods=['POST'])
def wix_mark_sent():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    conn = wix_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO wix_sent_log (user_email,email) VALUES (%s,%s) ON CONFLICT DO NOTHING", (session.get('user_id'), request.json.get('email','')))
        conn.commit(); cur.close()
        return jsonify({'success':True})
    except: return jsonify({'success':False})
    finally: wix_release(conn)

def attach(app):
    wix_init_db()
    app.register_blueprint(wix_bp)
    print("✅ wix_routes attached")
