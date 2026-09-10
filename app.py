from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import requests
import re
import os
import dns.resolver
import smtplib
import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import psycopg2
from psycopg2 import pool

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345_change_this'
DATABASE_URL = os.environ.get('DATABASE_URL')

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

# ==========================================
# DNS CACHE
# ==========================================
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

# ==========================================
# DB INIT
# ==========================================
def init_db():
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS scraped_stores (
            id SERIAL PRIMARY KEY, domain VARCHAR(255) UNIQUE NOT NULL,
            emails TEXT, scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS user_state (
            id SERIAL PRIMARY KEY, user_email VARCHAR(255) UNIQUE NOT NULL,
            found_emails TEXT, verified_emails TEXT, scout_recipients TEXT,
            scout_subject TEXT, scout_message TEXT, scout_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        # NEW: Verify jobs table
        cur.execute("""CREATE TABLE IF NOT EXISTS verify_jobs (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255) NOT NULL,
            job_name VARCHAR(255),
            total INTEGER DEFAULT 0,
            processed INTEGER DEFAULT 0,
            valid_emails TEXT,
            invalid_emails TEXT,
            remaining_emails TEXT,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.commit(); cur.close()
        print("✅ DB ready")
    except Exception as e: print(f"❌ DB: {e}")
    finally: release_db(conn)

try:
    init_pool(); init_db()
except: pass

# ==========================================
# HELPERS
# ==========================================
def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session: return redirect('/login')
        return f(*args, **kwargs)
    return decorated

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

# ==========================================
# BACKGROUND VERIFY WORKER
# ==========================================
def background_verify_worker(job_id):
    """Runs in background thread. Processes emails in chunks, saves to DB."""
    print(f"🔄 Job {job_id} started")
    conn = get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("SELECT remaining_emails, valid_emails, invalid_emails FROM verify_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone()
        cur.close()
        if not row: return
        remaining = row[0].split('|||') if row[0] else []
        valid = row[1].split('|||') if row[1] else []
        invalid = row[2].split('|||') if row[2] else []
    finally:
        release_db(conn)

    CHUNK_SIZE = 100

    while remaining:
        # Check if cancelled
        conn = get_db()
        if not conn: break
        try:
            cur = conn.cursor()
            cur.execute("SELECT status FROM verify_jobs WHERE id = %s", (job_id,))
            status_row = cur.fetchone()
            cur.close()
            if not status_row or status_row[0] == 'cancelled':
                print(f"⏹️ Job {job_id} cancelled")
                return
        finally:
            release_db(conn)

        chunk = remaining[:CHUNK_SIZE]
        remaining = remaining[CHUNK_SIZE:]

        # Verify chunk
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(verify_email, e): e for e in chunk}
            for f in as_completed(futures):
                email, ok, reason = f.result()
                if ok: valid.append(email)
                else: invalid.append(email + " - " + reason)

        # Save progress after each chunk
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
        finally:
            release_db(conn)

    print(f"✅ Job {job_id} complete")

# ==========================================
# START BACKGROUND VERIFY
# ==========================================
@app.route('/verify-async', methods=['POST'])
@login_required
def verify_async():
    user_email = session.get('user_id')
    data = request.json
    emails = data.get('emails', [])
    job_name = data.get('name', f"Job {int(time.time())}")
    
    if not emails:
        return jsonify({'error': 'No emails'}), 400
    
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO verify_jobs (user_email, job_name, total, remaining_emails, valid_emails, invalid_emails, status)
            VALUES (%s, %s, %s, %s, '', '', 'pending') RETURNING id""",
            (user_email, job_name, len(emails), '|||'.join(emails)))
        job_id = cur.fetchone()[0]
        conn.commit(); cur.close()
    finally:
        release_db(conn)
    
    # Start background thread
    thread = threading.Thread(target=background_verify_worker, args=(job_id,), daemon=True)
    thread.start()
    
    return jsonify({'success': True, 'job_id': job_id, 'total': len(emails)})

# ==========================================
# GET JOB STATUS
# ==========================================
@app.route('/verify-status/<int:job_id>')
@login_required
def verify_status(job_id):
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, job_name, total, processed, status, valid_emails, invalid_emails, created_at
            FROM verify_jobs WHERE id = %s""", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'error': 'Not found'}), 404
        valid_count = len(row[5].split('|||')) if row[5] else 0
        invalid_count = len(row[6].split('|||')) if row[6] else 0
        return jsonify({
            'id': row[0], 'name': row[1], 'total': row[2], 'processed': row[3],
            'status': row[4], 'valid': valid_count, 'invalid': invalid_count,
            'created_at': str(row[7])
        })
    finally:
        release_db(conn)

# ==========================================
# GET JOB RESULTS
# ==========================================
@app.route('/verify-results/<int:job_id>')
@login_required
def verify_results(job_id):
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT valid_emails, invalid_emails FROM verify_jobs WHERE id = %s", (job_id,))
        row = cur.fetchone(); cur.close()
        if not row: return jsonify({'error': 'Not found'}), 404
        return jsonify({
            'valid': row[0].split('|||') if row[0] else [],
            'invalid': row[1].split('|||') if row[1] else []
        })
    finally:
        release_db(conn)

# ==========================================
# LIST LAST 3 JOBS
# ==========================================
@app.route('/verify-jobs')
@login_required
def verify_jobs_list():
    user_email = session.get('user_id')
    conn = get_db()
    if not conn: return jsonify({'jobs': []})
    try:
        cur = conn.cursor()
        cur.execute("""SELECT id, job_name, total, processed, status, created_at,
            valid_emails, invalid_emails
            FROM verify_jobs WHERE user_email = %s
            ORDER BY created_at DESC LIMIT 3""", (user_email,))
        rows = cur.fetchall(); cur.close()
        jobs = []
        for r in rows:
            valid_count = len(r[6].split('|||')) if r[6] else 0
            invalid_count = len(r[7].split('|||')) if r[7] else 0
            jobs.append({
                'id': r[0], 'name': r[1], 'total': r[2], 'processed': r[3],
                'status': r[4], 'created_at': str(r[5]),
                'valid': valid_count, 'invalid': invalid_count
            })
        return jsonify({'jobs': jobs})
    finally:
        release_db(conn)

# ==========================================
# CANCEL JOB
# ==========================================
@app.route('/verify-cancel/<int:job_id>', methods=['POST'])
@login_required
def verify_cancel(job_id):
    conn = get_db()
    if not conn: return jsonify({'error': 'No DB'}), 500
    try:
        cur = conn.cursor()
        cur.execute("UPDATE verify_jobs SET status='cancelled' WHERE id=%s AND user_email=%s", (job_id, session.get('user_id')))
        conn.commit(); cur.close()
        return jsonify({'success': True})
    finally:
        release_db(conn)

# ==========================================
# FINDER
# ==========================================
def find_emails(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "")
    domain = domain.split("/")[0]
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
<span class="navbar-title">📧 Shopify Tools</span>
</div>
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
<div class="drawer-header"><span>📧 Menu</span><button class="drawer-close" onclick="toggleDrawer()">×</button></div>
<a href="/" onclick="closeDrawer()">🔍 Email Finder</a>
<a href="/verify" onclick="closeDrawer()">✅ Verify Emails</a>
<a href="/scout" onclick="closeDrawer()">📨 Email Scout</a>
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
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password (min 6)" required minlength="6"><button>Sign Up</button></form>
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
        if not email or not password:
            return render_template_string(SIGNUP_HTML, error="Fill all fields")
        conn = get_db()
        if not conn: return render_template_string(SIGNUP_HTML, error="DB not available")
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hash_password(password)))
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

# ==========================================
# HOME
# ==========================================
@app.route('/')
@login_required
def home():
    body = '''<div style="max-width:700px;margin:20px auto;padding:20px">
<div style="background:white;padding:30px;border-radius:15px;box-shadow:0 4px 12px rgba(0,0,0,0.1)">
<h2 style="color:#333;margin-top:0">🔍 Email Finder</h2>
<p style="color:#666">Paste up to <b>100 store URLs</b> (one per line).</p>
<textarea id="urls" style="width:100%;height:180px;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;box-sizing:border-box" placeholder="deluxura.shop&#10;hipchik.com"></textarea>
<button onclick="findBulkEmails()" style="background:#667eea;color:white;padding:12px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin:10px 0">Search All URLs</button>
<div id="result" style="margin-top:20px;background:#f8f9fa;padding:15px;border-radius:8px;min-height:40px"></div>
</div></div>
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
        html+='<div style="font-weight:bold;margin-top:15px">📦 '+item.store+':</div>';
        item.emails.forEach(e=>{html+='<div style="background:white;padding:8px;margin:5px 0;border-radius:5px;border-left:4px solid #667eea;font-weight:bold;word-break:break-all">'+e+'</div>'});
      });
      result.innerHTML=html;
    } else { result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No emails found</div>'; }
  }catch(e){result.innerHTML='<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+e+'</div>'}
}
</script>'''
    return render_page("Finder", body)

# ==========================================
# VERIFY
# ==========================================
@app.route('/verify')
@login_required
def verify_page():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">✅ Verify Emails (Background)</h1>
<p style="margin:5px 0 0 0">Drop emails, close browser, come back later</p>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">📋 Last 3 Jobs</h3>
<div id="jobsList" style="margin-bottom:15px">Loading...</div>
<button onclick="refreshJobs()" style="background:#3b82f6;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;font-size:14px">🔄 Refresh</button>
</div>

<div style="background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);margin-bottom:20px">
<h3 style="margin-top:0">🆕 New Verification</h3>
<textarea id="emailsInput" style="width:100%;height:180px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box" placeholder="email1@example.com&#10;email2@example.com"></textarea>
<div style="border:2px dashed #ddd;padding:15px;text-align:center;margin:10px 0">
<input type="file" id="emailFile" accept=".csv,.txt">
<button onclick="readFile()" style="background:#f59e0b;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin-left:10px">Upload</button>
</div>
<button onclick="loadFromFinder()" style="background:#f59e0b;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px;margin-bottom:8px">📥 From Finder</button>
<button onclick="startBackgroundVerify()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-bottom:8px">▶️ Start Background Verify</button>
<div id="startMsg" style="margin-top:10px"></div>
</div>
</div>
<script>
async function loadFromFinder(){
  const res=await fetch('/get-stored-emails');const data=await res.json();
  if(data.emails&&data.emails.length>0){document.getElementById('emailsInput').value=data.emails.join('\\n');alert('Loaded '+data.emails.length)}
}
function readFile(){
  const f=document.getElementById('emailFile').files[0];if(!f){alert('Select file');return}
  const r=new FileReader();
  r.onload=function(e){
    const lines=e.target.result.split('\\n');const emails=[];
    lines.forEach(l=>{l=l.trim();if(l.includes(','))l=l.split(',')[0].trim();if(l.includes('@'))emails.push(l)});
    document.getElementById('emailsInput').value=emails.join('\\n');
    alert('Loaded '+emails.length+' emails');
  };r.readAsText(f);
}
async function startBackgroundVerify(){
  const emails=document.getElementById('emailsInput').value.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(emails.length===0){alert('Enter emails');return}
  const name=prompt('Name this job (optional):','Job '+new Date().toLocaleString());
  document.getElementById('startMsg').innerHTML='<p style="color:#666">Starting background job...</p>';
  try{
    const res=await fetch('/verify-async',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails:emails,name:name||'Untitled'})});
    const data=await res.json();
    if(data.success){
      document.getElementById('startMsg').innerHTML='<p style="color:green">✅ Job #'+data.job_id+' started! You can close this page.</p>';
      document.getElementById('emailsInput').value='';
      refreshJobs();
    }
  }catch(e){document.getElementById('startMsg').innerHTML='<p style="color:red">Error: '+e+'</p>'}
}
async function refreshJobs(){
  const res=await fetch('/verify-jobs');
  const data=await res.json();
  const container=document.getElementById('jobsList');
  if(!data.jobs||data.jobs.length===0){container.innerHTML='<p style="color:#666">No jobs yet.</p>';return}
  let html='';
  data.jobs.forEach(job=>{
    const percent=job.total>0?Math.round((job.processed/job.total)*100):0;
    const statusColor=job.status==='completed'?'#0d9488':(job.status==='running'?'#f59e0b':'#ef4444');
    const statusIcon=job.status==='completed'?'✅':(job.status==='running'?'🔄':'⏹️');
    html+='<div style="background:#f9f9f9;padding:12px;border-radius:8px;margin:8px 0;border-left:4px solid '+statusColor+'">';
    html+='<div style="font-weight:bold">'+statusIcon+' '+job.name+' <span style="color:#666;font-weight:normal;font-size:13px">#'+job.id+'</span></div>';
    html+='<div style="font-size:13px;color:#666;margin-top:4px">'+job.created_at+'</div>';
    html+='<div style="margin-top:8px;background:#e0e0e0;border-radius:8px;overflow:hidden"><div style="width:'+percent+'%;height:16px;background:'+statusColor+';text-align:center;color:white;font-size:11px;line-height:16px">'+percent+'%</div></div>';
    html+='<div style="font-size:13px;margin-top:6px">Processed: '+job.processed+' / '+job.total+' | ✅ '+job.valid+' | ❌ '+job.invalid+'</div>';
    html+='<div style="margin-top:8px">';
    html+='<button onclick="loadResults('+job.id+')" style="background:#3b82f6;color:white;padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-right:5px">View Results</button>';
    if(job.status==='running'){html+='<button onclick="cancelJob('+job.id+')" style="background:#ef4444;color:white;padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-size:13px">Cancel</button>'}
    html+='</div>';
    html+='<div id="result-'+job.id+'" style="margin-top:10px"></div>';
    html+='</div>';
  });
  container.innerHTML=html;
}
async function loadResults(jobId){
  const res=await fetch('/verify-results/'+jobId);
  const data=await res.json();
  const container=document.getElementById('result-'+jobId);
  if(!data.valid&&!data.invalid){container.innerHTML='<p>No results yet.</p>';return}
  let html='<h4 style="margin:8px 0 4px 0">✅ Valid: '+data.valid.length+'</h4>';
  html+='<div style="max-height:150px;overflow-y:auto;background:white;padding:8px;border-radius:5px;font-size:12px;word-break:break-all">';
  data.valid.slice(0,50).forEach(e=>{html+='<div style="color:#155724">'+e+'</div>'});
  if(data.valid.length>50)html+='<div style="color:#666">... +'+(data.valid.length-50)+' more</div>';
  html+='</div>';
  html+='<h4 style="margin:8px 0 4px 0">❌ Invalid: '+data.invalid.length+'</h4>';
  html+='<div style="max-height:100px;overflow-y:auto;background:white;padding:8px;border-radius:5px;font-size:12px;word-break:break-all">';
  data.invalid.slice(0,30).forEach(e=>{html+='<div style="color:#721c24">'+e+'</div>'});
  if(data.invalid.length>30)html+='<div style="color:#666">... +'+(data.invalid.length-30)+' more</div>';
  html+='</div>';
  html+='<div style="margin-top:10px"><button onclick="downloadJob('+jobId+')" style="background:#0d9488;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin-right:5px">⬇️ Download Valid</button>';
  html+='<button onclick="sendJobToScout('+jobId+')" style="background:#3b82f6;color:white;padding:6px 14px;border:none;border-radius:4px;cursor:pointer;font-size:13px">📨 Send to Scout</button></div>';
  container.innerHTML=html;
}
async function downloadJob(jobId){
  const res=await fetch('/verify-results/'+jobId);
  const data=await res.json();
  const csv='Email\\n'+data.valid.join('\\n');
  const b=new Blob([csv],{type:'text/csv'});const u=URL.createObjectURL(b);
  const a=document.createElement('a');a.href=u;a.download='valid_job_'+jobId+'.csv';a.click();
}
async function sendJobToScout(jobId){
  const res=await fetch('/verify-results/'+jobId);
  const data=await res.json();
  await fetch('/save-scout-recipients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients:data.valid})});
  window.location.href='/scout';
}
async function cancelJob(jobId){
  if(!confirm('Cancel this job?'))return;
  await fetch('/verify-cancel/'+jobId,{method:'POST'});
  refreshJobs();
}
window.onload=function(){
  refreshJobs();
  setInterval(refreshJobs,10000);
};
</script>'''
    return render_page("Verify", body)

# ==========================================
# SCOUT (unchanged)
# ==========================================
@app.route('/scout')
@login_required
def scout():
    body = '''<div style="max-width:800px;margin:20px auto;padding:20px">
<div style="background:#0d9488;color:white;padding:20px;border-radius:10px;margin-bottom:20px"><h1 style="margin:0">📨 Email Scout</h1></div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Recipients</h3>
<textarea id="emailsInput" style="width:100%;height:160px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box"></textarea>
<button onclick="loadFromFinder()" style="background:#0d9488;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin:8px 4px 0 0">From Finder</button>
<button onclick="loadFromVerified()" style="background:#f59e0b;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin:8px 4px 0 0">From Verified</button>
<button onclick="clearAll()" style="background:#ef4444;color:white;padding:8px 16px;border:none;border-radius:5px;cursor:pointer;margin:8px 4px 0 0">Clear</button>
<div id="emailCount" style="margin-top:10px;font-weight:bold">0 recipients</div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">✍️ Template</h3>
<label>Subject</label>
<input type="text" id="subjectLine" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box">
<label>Message</label>
<textarea id="messageBody" rows="5" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box"></textarea>
<button onclick="insertPh('{name}')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer">{name}</button>
<button onclick="insertPh('{email}')" style="background:#f59e0b;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer">{email}</button>
<button onclick="generatePreview()" style="background:#0d9488;color:white;padding:8px 14px;border:none;border-radius:5px;cursor:pointer">👁️ Preview</button>
<div id="preview" style="margin-top:10px;background:#f9f9f9;padding:10px;border-radius:5px;display:none;font-size:13px"></div>
</div>
<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px">
<div style="background:white;padding:15px;text-align:center;border-radius:10px"><div id="totalScouted" style="font-size:22px;font-weight:bold;color:#0d9488">0</div><div>Total</div></div>
<div style="background:white;padding:15px;text-align:center;border-radius:10px"><div id="todayScouted" style="font-size:22px;font-weight:bold;color:#0d9488">0</div><div>Today</div></div>
<div style="background:white;padding:15px;text-align:center;border-radius:10px"><div id="workingRate" style="font-size:22px;font-weight:bold;color:#0d9488">0%</div><div>Rate</div></div>
<div style="background:white;padding:15px;text-align:center;border-radius:10px"><div id="autoClickStatus" style="font-size:22px;font-weight:bold;color:#0d9488">Off</div><div>Auto</div></div>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">🚀 Launch</h3>
<button onclick="startCampaign()" style="background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px;margin-bottom:8px">▶️ Start</button>
<button onclick="stopCampaign()" style="background:#ef4444;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:8px;margin-bottom:8px">⏹️ Stop</button>
<button onclick="openBulk()" style="background:#3b82f6;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer">📤 Open Next 10</button>
<div id="launchStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">📊 Log</h3>
<div id="log" style="max-height:150px;overflow-y:auto;background:#f9f9f9;padding:10px;border-radius:5px;font-size:13px"></div>
</div></div>
<script>
let recipients=[],scoutedEmails=0,isRunning=false;
window.onload=async function(){
  try{
    const res=await fetch('/load-scout-state');const data=await res.json();
    if(data.recipients&&data.recipients.length>0){recipients=data.recipients;document.getElementById('emailsInput').value=recipients.join('\\n')}
    if(data.subject)document.getElementById('subjectLine').value=data.subject;
    if(data.message)document.getElementById('messageBody').value=data.message;
    if(data.count)scoutedEmails=data.count;
  }catch(e){}
  updateUI();
};
function updateUI(){
  document.getElementById('emailCount').textContent=recipients.length+' recipients';
  document.getElementById('totalScouted').textContent=scoutedEmails;
  document.getElementById('todayScouted').textContent=scoutedEmails;
  document.getElementById('workingRate').textContent=(recipients.length>0?Math.round((scoutedEmails/recipients.length)*100):0)+'%';
}
async function saveState(){
  try{await fetch('/save-scout-state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients:recipients,subject:document.getElementById('subjectLine').value,message:document.getElementById('messageBody').value,count:scoutedEmails})})}catch(e){}
}
async function loadFromFinder(){
  const res=await fetch('/get-stored-emails');const data=await res.json();
  if(data.emails&&data.emails.length>0){recipients=data.emails;document.getElementById('emailsInput').value=recipients.join('\\n');updateUI();saveState()}
}
async function loadFromVerified(){
  const res=await fetch('/get-verified-emails');const data=await res.json();
  if(data.valid&&data.valid.length>0){recipients=data.valid;document.getElementById('emailsInput').value=recipients.join('\\n');updateUI();saveState()}
}
function clearAll(){recipients=[];scoutedEmails=0;document.getElementById('emailsInput').value='';document.getElementById('subjectLine').value='';document.getElementById('messageBody').value='';updateUI();saveState();isRunning=false;document.getElementById('autoClickStatus').textContent='Off'}
function insertPh(t){document.getElementById('messageBody').value+=t;saveState()}
function generatePreview(){const s=document.getElementById('subjectLine').value;const m=document.getElementById('messageBody').value;const p=document.getElementById('preview');p.innerHTML='<b>Subject:</b> '+s+'<br><br><b>Message:</b><br>'+m.replace('{name}','John Doe').replace('{email}','john@store.com');p.style.display='block'}
function startCampaign(){if(recipients.length===0){alert('Add recipients');return}isRunning=true;document.getElementById('autoClickStatus').textContent='On';document.getElementById('launchStatus').innerHTML='<p style="color:green">🚀 Started</p>';openNextEmail()}
function stopCampaign(){isRunning=false;document.getElementById('autoClickStatus').textContent='Off';document.getElementById('launchStatus').innerHTML='<p style="color:red">⏹️ Stopped</p>';saveState()}
function openNextEmail(){
  if(!isRunning)return;
  if(scoutedEmails>=recipients.length){isRunning=false;document.getElementById('autoClickStatus').textContent='Off';document.getElementById('launchStatus').innerHTML='<p style="color:blue">🎉 Complete</p>';saveState();return}
  const email=recipients[scoutedEmails];const subj=document.getElementById('subjectLine').value;const msg=document.getElementById('messageBody').value;
  const body=msg.replace('{name}','Store Owner').replace('{email}',email);
  window.location.href='mailto:'+email+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body);
  const log=document.getElementById('log');log.innerHTML+='<div>📨 '+email+'</div>';log.scrollTop=log.scrollHeight;
  scoutedEmails++;updateUI();saveState();
}
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='visible'&&isRunning)setTimeout(openNextEmail,2000)});
document.addEventListener('click',function(e){if(isRunning&&scoutedEmails<recipients.length&&!e.target.closest('button'))setTimeout(openNextEmail,2000)});
function openBulk(){
  const subj=document.getElementById('subjectLine').value;const msg=document.getElementById('messageBody').value;
  for(let i=0;i<Math.min(10,recipients.length-scoutedEmails);i++){
    const email=recipients[scoutedEmails+i];
    const body=msg.replace('{name}','Store Owner').replace('{email}',email);
    window.open('mailto:'+email+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body),'_blank');
  }
  scoutedEmails+=Math.min(10,recipients.length-scoutedEmails);updateUI();saveState();
}
</script>'''
    return render_page("Scout", body)

# ==========================================
# API
# ==========================================
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
    if user_email and all_found:
        save_user_state(user_email, found_emails='|||'.join(all_found))
    return jsonify({'success': bool(results), 'results': results})

@app.route('/store-emails', methods=['POST'])
@login_required
def store_emails():
    emails = request.json.get('emails', [])
    user_email = session.get('user_id')
    if user_email: save_user_state(user_email, found_emails='|||'.join(emails))
    return jsonify({'success': True})

@app.route('/get-stored-emails')
@login_required
def get_stored_emails():
    user_email = session.get('user_id')
    state = load_user_state(user_email) if user_email else {}
    return jsonify({'emails': state.get('found_emails', [])})

@app.route('/get-verified-emails')
@login_required
def get_verified_emails():
    user_email = session.get('user_id')
    state = load_user_state(user_email) if user_email else {}
    return jsonify({'valid': state.get('verified_emails', [])})

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
    return jsonify({
        'recipients': state.get('scout_recipients', []),
        'subject': state.get('scout_subject', ''),
        'message': state.get('scout_message', ''),
        'count': state.get('scout_count', 0)
    })

@app.route('/save-scout-state', methods=['POST'])
@login_required
def save_scout_state_route():
    user_email = session.get('user_id')
    data = request.json
    if user_email:
        save_user_state(user_email,
            scout_recipients='|||'.join(data.get('recipients', [])),
            scout_subject=data.get('subject', ''),
            scout_message=data.get('message', ''),
            scout_count=data.get('count', 0))
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
