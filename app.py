from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import requests
import re
import os
import dns.resolver
import smtplib
import traceback
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from datetime import datetime

# Database
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345_change_this_in_production'

# ==========================================
# DATABASE SETUP
# ==========================================
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db():
    """Get database connection"""
    if not DATABASE_URL:
        return None
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    return conn

def init_db():
    """Create tables if they don't exist"""
    conn = get_db()
    if not conn:
        print("⚠️  No DATABASE_URL found. Running in memory-only mode.")
        return
    try:
        cur = conn.cursor()
        
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scraped emails cache (avoid re-scraping)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scraped_stores (
                id SERIAL PRIMARY KEY,
                domain VARCHAR(255) UNIQUE NOT NULL,
                emails TEXT,
                scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scouting progress
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scouting_progress (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                email VARCHAR(255) NOT NULL,
                subject TEXT,
                body TEXT,
                status VARCHAR(20) DEFAULT 'pending',
                sent_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        cur.close()
        print("✅ Database initialized")
    except Exception as e:
        print(f"❌ DB init error: {e}")
    finally:
        conn.close()

# Try to init DB on startup
try:
    init_db()
except:
    pass

# ==========================================
# AUTH HELPERS
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

# ==========================================
# CACHE HELPERS
# ==========================================
def get_cached_emails(domain):
    """Check if we already scraped this domain recently"""
    conn = get_db()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT emails FROM scraped_stores WHERE domain = %s AND scraped_at > NOW() - INTERVAL '7 days'",
            (domain,)
        )
        row = cur.fetchone()
        cur.close()
        if row:
            return row[0].split(',') if row[0] else []
        return None
    except:
        return None
    finally:
        conn.close()

def cache_emails(domain, emails):
    """Save scraped emails to cache"""
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scraped_stores (domain, emails)
            VALUES (%s, %s)
            ON CONFLICT (domain) DO UPDATE SET emails = %s, scraped_at = NOW()
        """, (domain, ','.join(emails), ','.join(emails)))
        conn.commit()
        cur.close()
    except:
        pass
    finally:
        conn.close()

# ==========================================
# EMAIL VERIFICATION (unchanged)
# ==========================================
def verify_email(email):
    try:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            return email, False, "Invalid syntax"
        domain = email.split('@')[1]
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            if len(mx_records) == 0:
                return email, False, "No mail server"
        except dns.resolver.NXDOMAIN:
            return email, False, "Domain doesn't exist"
        except dns.resolver.NoAnswer:
            return email, False, "No MX records"
        except Exception:
            return email, False, "Cannot resolve domain"
        try:
            mx_host = str(mx_records[0].exchange)
            server = smtplib.SMTP(mx_host, timeout=5)
            server.set_debuglevel(0)
            server.ehlo()
            response = server.verify(email)
            server.quit()
            if response[0] == 250:
                return email, True, "Valid & Active"
            else:
                return email, False, "Mailbox may not exist"
        except smtplib.SMTPConnectError:
            return email, False, "Cannot connect to mail server"
        except smtplib.SMTPRecipientsRefused:
            return email, False, "Mailbox refused"
        except Exception:
            return email, True, "Valid (Domain-based)"
    except Exception:
        return email, False, "Unknown error"

# ==========================================
# FAST EMAIL FINDER (SPEED-OPTIMIZED)
# ==========================================
def find_emails(domain):
    """
    FAST scraping: checks cache first, then 4 key pages with aggressive timeout
    """
    # CLEAN URL
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    
    # CHECK CACHE FIRST
    cached = get_cached_emails(domain)
    if cached is not None:
        return cached  # Instant return from cache
    
    emails = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate"
    }
    
    # ONLY 4 PAGES for speed
    pages_to_check = [
        f"https://{domain}/pages/contact",
        f"https://{domain}/pages/contact-us",
        f"https://{domain}/contact",
        f"https://{domain}",
    ]
    
    for page_url in pages_to_check:
        try:
            r = requests.get(page_url, headers=headers, timeout=6)
            if r.status_code == 200:
                html = r.text
                
                # Strip scripts and styles quickly
                clean = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL)
                clean = re.sub(r'<style[^>]*>.*?</style>', ' ', clean, flags=re.DOTALL)
                clean = re.sub(r'<[^>]+>', ' ', clean)
                
                # Find all emails
                found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean)
                for email in found:
                    emails.append(email.lower())
                
                # Cloudflare decode
                cf_emails = re.findall(r'data-cfemail="([a-f0-9]+)"', html)
                for cf in cf_emails:
                    try:
                        key = int(cf[:2], 16)
                        decoded = ''.join([chr(int(cf[i:i+2], 16) ^ key) for i in range(2, len(cf), 2)])
                        if '@' in decoded and '.' in decoded:
                            emails.append(decoded.lower())
                    except:
                        pass
                
                # mailto
                mailtos = re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', html)
                for email in mailtos:
                    emails.append(email.lower())
                
                # Stop if we already found 3 emails
                if len(set(emails)) >= 3:
                    break
        except:
            continue
    
    # Filter junk
    skip_words = [
        '.jpg', '.png', '.jpeg', '.gif', '.svg', '2x', '3x', 'wix', 'sentry',
        'godaddy', 'namecheap', 'markmonitor', 'tucows', 'domainabuse', 'abuse@',
        'whoisproxy', 'whoisrequest', 'contactprivacy', 'withheldforprivacy',
        'example.com', 'example.org', 'example.net', 'wixpress',
        'cloudflare', 'xinnet', 'wildwest', 'dnai', 'web.com', 'domainmarket',
        'no-reply@registrar', 'protect@', 'shopify.com', 'myshopify.com',
        'you@email.com', 'your@email.com', 'email@email.com', 'test@test.com',
        'user@email.com', 'name@email.com', 'service@domainmarket',
        'interested@', 'sentry.io', 'facebook.com', 'instagram.com',
        'twitter.com', 'pinterest.com', 'cdn.shopify', '@2x', '@3x'
    ]
    
    unique = list(set(emails))
    final_emails = []
    for email in unique:
        if len(email) > 5 and '.' in email and not any(x in email for x in skip_words):
            final_emails.append(email)
    
    # SAVE TO CACHE
    cache_emails(domain, final_emails)
    
    return final_emails

# ==========================================
# LOGIN / SIGNUP PAGES
# ==========================================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        if not email or not password:
            return render_template_string(SIGNUP_HTML, error="Please fill all fields")
        
        conn = get_db()
        if not conn:
            return render_template_string(SIGNUP_HTML, error="Database not available")
        
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                (email, hash_password(password))
            )
            conn.commit()
            cur.close()
            session['user_id'] = email
            return redirect('/')
        except psycopg2.errors.UniqueViolation:
            return render_template_string(SIGNUP_HTML, error="Email already registered")
        except Exception as e:
            return render_template_string(SIGNUP_HTML, error=f"Error: {e}")
        finally:
            conn.close()
    
    return render_template_string(SIGNUP_HTML, error=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        conn = get_db()
        if not conn:
            return render_template_string(LOGIN_HTML, error="Database not available")
        
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT password_hash FROM users WHERE email = %s",
                (email,)
            )
            row = cur.fetchone()
            cur.close()
            
            if row and row[0] == hash_password(password):
                session['user_id'] = email
                return redirect('/')
            else:
                return render_template_string(LOGIN_HTML, error="Invalid email or password")
        except Exception as e:
            return render_template_string(LOGIN_HTML, error=f"Error: {e}")
        finally:
            conn.close()
    
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ==========================================
# HOME PAGE (with login required)
# ==========================================
@app.route('/')
@login_required
def home():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Shopify Bulk Email Finder</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: 'Arial', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: flex-start; }
                .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 90%; max-width: 600px; }
                h2 { color: #333; margin-bottom: 10px; }
                .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
                .logout { background: #ef4444; color: white; padding: 8px 16px; border-radius: 5px; text-decoration: none; font-size: 14px; }
                textarea { width: 100%; height: 200px; padding: 12px; margin: 15px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 14px; font-family: monospace; box-sizing: border-box; }
                button { background: #667eea; color: white; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; margin-bottom: 10px; }
                button:hover { background: #5a67d8; }
                .btn-scout { background: #0d9488; }
                .btn-verify { background: #f59e0b; }
                #result { margin-top: 20px; background: #f8f9fa; padding: 15px; border-radius: 8px; }
                .email-item { background: white; padding: 8px; margin: 5px 0; border-radius: 5px; border-left: 4px solid #667eea; font-weight: bold; }
                .store-header { font-weight: bold; color: #333; margin-top: 15px; }
                .error { color: #721c24; background: #f8d7da; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="top-bar">
                    <h2>📧 Shopify Email Finder</h2>
                    <a href="/logout" class="logout">Logout</a>
                </div>
                <p>Paste up to <b>100 store URLs</b> (one per line).</p>
                <textarea id="urls" placeholder="deluxura.shop&#10;hipchik.com&#10;ohhappyday.com"></textarea>
                <button onclick="findBulkEmails()">Search All URLs</button>
                <button class="btn-verify" onclick="window.location.href='/verify'">✅ Verify Emails</button>
                <button class="btn-scout" onclick="window.location.href='/scout'">📨 Go to Email Scout</button>
                <div id="result"></div>
            </div>
            <script>
                async function findBulkEmails() {
                    const input = document.getElementById('urls').value;
                    const result = document.getElementById('result');
                    const stores = input.split('\\n').map(s => s.trim()).filter(s => s.length > 0);
                    if (stores.length === 0) { alert('Please enter at least one store URL'); return; }
                    result.innerHTML = `<p style="color: #666;">Searching ${stores.length} stores... (cached results are instant)</p>`;
                    try {
                        const res = await fetch('/bulk-email', {
                            method: 'POST', headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ stores: stores })
                        });
                        const data = await res.json();
                        if (data.success) {
                            let html = '<h4 style="color: #155724;">✅ Found emails for ' + data.results.length + ' stores:</h4>';
                            data.results.forEach(item => {
                                html += '<div class="store-header">📦 ' + item.store + ':</div>';
                                item.emails.forEach(email => { html += '<div class="email-item">' + email + '</div>'; });
                            });
                            result.innerHTML = html;
                            const allEmails = [];
                            data.results.forEach(item => item.emails.forEach(e => allEmails.push(e)));
                            fetch('/store-emails', {
                                method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ emails: allEmails })
                            });
                        } else { result.innerHTML = '<div class="error">No emails found for any store.</div>'; }
                    } catch (e) { result.innerHTML = '<div class="error">Server error.</div>'; }
                }
            </script>
        </body>
        </html>
    ''')

# ==========================================
# SIGNUP / LOGIN TEMPLATES
# ==========================================
SIGNUP_HTML = '''
<!DOCTYPE html>
<html><head><title>Sign Up</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: Arial; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; padding: 20px; }
.box { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
h2 { color: #333; text-align: center; margin-bottom: 30px; }
input { width: 100%; padding: 12px; margin: 8px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; box-sizing: border-box; }
button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 10px; }
button:hover { background: #5a67d8; }
.error { color: #721c24; background: #f8d7da; padding: 10px; border-radius: 5px; margin-bottom: 15px; }
.link { text-align: center; margin-top: 15px; color: #666; }
.link a { color: #667eea; text-decoration: none; }
</style></head><body>
<div class="box">
<h2>📧 Create Account</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required minlength="6">
<button type="submit">Sign Up</button>
</form>
<div class="link">Already have an account? <a href="/login">Log in</a></div>
</div></body></html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html><head><title>Login</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: Arial; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; display: flex; justify-content: center; align-items: center; margin: 0; padding: 20px; }
.box { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
h2 { color: #333; text-align: center; margin-bottom: 30px; }
input { width: 100%; padding: 12px; margin: 8px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; box-sizing: border-box; }
button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 10px; }
button:hover { background: #5a67d8; }
.error { color: #721c24; background: #f8d7da; padding: 10px; border-radius: 5px; margin-bottom: 15px; }
.link { text-align: center; margin-top: 15px; color: #666; }
.link a { color: #667eea; text-decoration: none; }
</style></head><body>
<div class="box">
<h2>📧 Login</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Log In</button>
</form>
<div class="link">Don't have an account? <a href="/signup">Sign up</a></div>
</div></body></html>
'''

# ==========================================
# VERIFY PAGE (unchanged, login required)
# ==========================================
@app.route('/verify')
@login_required
def verify_page():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: 'Arial', sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .header { background: #f59e0b; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .recipients { width: 100%; height: 250px; border: 1px solid #ddd; border-radius: 5px; padding: 10px; font-family: monospace; box-sizing: border-box; }
                .btn { background: #f59e0b; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; font-size: 16px; }
                .btn-green { background: #0d9488; }
                .btn-blue { background: #3b82f6; }
                .valid-item { background: #d4edda; padding: 8px; border-radius: 5px; margin: 5px 0; color: #155724; }
                .invalid-item { background: #f8d7da; padding: 8px; border-radius: 5px; margin: 5px 0; color: #721c24; }
                .file-upload { border: 2px dashed #ddd; padding: 20px; text-align: center; margin: 10px 0; }
                .progress-container { width: 100%; background: #e0e0e0; border-radius: 10px; margin: 20px 0; display: none; }
                .progress-bar { width: 0%; height: 20px; background: linear-gradient(90deg, #4ade80, #22c55e); border-radius: 10px; transition: width 0.3s ease; text-align: center; color: white; font-size: 12px; line-height: 20px; }
                .progress-text { font-size: 16px; font-weight: bold; color: #333; margin-top: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>✅ Email Verification</h1>
                    <p>Verify via paste, CSV, or TXT upload</p>
                </div>
                <div class="card">
                    <textarea id="emailsInput" class="recipients" placeholder="email1@example.com&#10;email2@example.com"></textarea>
                    <div class="file-upload">
                        <h4>OR Upload File</h4>
                        <input type="file" id="emailFile" accept=".csv,.txt">
                        <button class="btn" onclick="readFile()">Upload & Load</button>
                    </div>
                    <br>
                    <button class="btn" onclick="loadFromFinder()">📥 Load from Email Extracted</button>
                    <button class="btn" onclick="verifyEmails()">🔍 Verify Emails</button>
                    <div class="progress-container" id="progressContainer">
                        <div class="progress-bar" id="progressBar">0%</div>
                        <div class="progress-text" id="progressText">Starting...</div>
                    </div>
                    <div id="verificationStatus" style="margin-top: 10px;"></div>
                </div>
                <div class="card">
                    <h3>📊 Results</h3>
                    <div id="result"></div>
                    <br>
                    <button class="btn btn-green" onclick="downloadValid()">⬇️ Download Valid</button>
                    <button class="btn btn-blue" onclick="sendValidToScout()">📨 Send to Scout</button>
                </div>
            </div>
            <script>
                let validEmails = [], invalidEmails = [], isVerifying = false;
                
                async function loadFromFinder() {
                    const res = await fetch('/get-stored-emails');
                    const data = await res.json();
                    if (data.emails && data.emails.length > 0) {
                        document.getElementById('emailsInput').value = data.emails.join('\\n');
                        document.getElementById('verificationStatus').innerHTML = '<p style="color: green;">✅ Loaded ' + data.emails.length + ' emails</p>';
                    }
                }
                
                function readFile() {
                    const file = document.getElementById('emailFile').files[0];
                    if (!file) { alert('Select a file first'); return; }
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const lines = e.target.result.split('\\n');
                        const emails = [];
                        lines.forEach(line => {
                            line = line.trim();
                            if (line.includes(',')) line = line.split(',')[0].trim();
                            if (line.includes('@')) emails.push(line);
                        });
                        document.getElementById('emailsInput').value = emails.join('\\n');
                        document.getElementById('verificationStatus').innerHTML = '<p style="color: green;">✅ Loaded ' + emails.length + ' emails</p>';
                    };
                    reader.readAsText(file);
                }
                
                async function verifyEmails() {
                    if (isVerifying) { alert('Already verifying'); return; }
                    const input = document.getElementById('emailsInput').value;
                    const allEmails = input.split('\\n').map(s => s.trim()).filter(s => s.length > 0);
                    if (allEmails.length === 0) { alert('Enter emails'); return; }
                    validEmails = []; invalidEmails = []; isVerifying = true;
                    document.getElementById('progressContainer').style.display = 'block';
                    const batchSize = Math.ceil(allEmails.length / 4);
                    for (let i = 0; i < 4; i++) {
                        const batch = allEmails.slice(i * batchSize, (i + 1) * batchSize);
                        if (batch.length === 0) break;
                        document.getElementById('progressText').textContent = 'Batch ' + (i+1) + ' of 4...';
                        try {
                            const res = await fetch('/verify-batch', {
                                method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ emails: batch })
                            });
                            const data = await res.json();
                            if (data.success) {
                                validEmails = validEmails.concat(data.valid);
                                invalidEmails = invalidEmails.concat(data.invalid);
                                const percent = Math.round(((i+1)/4)*100);
                                document.getElementById('progressBar').style.width = percent + '%';
                                document.getElementById('progressBar').textContent = percent + '%';
                            }
                        } catch (e) { break; }
                        await new Promise(r => setTimeout(r, 300));
                    }
                    isVerifying = false;
                    let html = '<p style="color: green;">✅ Valid: ' + validEmails.length + '</p>';
                    html += '<p style="color: red;">❌ Invalid: ' + invalidEmails.length + '</p>';
                    html += '<h4>Valid:</h4>';
                    validEmails.forEach(e => html += '<div class="valid-item">✅ ' + e + '</div>');
                    document.getElementById('result').innerHTML = html;
                    fetch('/store-verified', {
                        method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ valid: validEmails, invalid: invalidEmails })
                    });
                }
                
                function downloadValid() {
                    if (validEmails.length === 0) { alert('No valid emails'); return; }
                    let csv = "Email\\n" + validEmails.join("\\n");
                    const blob = new Blob([csv], { type: 'text/csv' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url; a.download = 'valid_emails.csv'; a.click();
                }
                
                function sendValidToScout() {
                    if (validEmails.length === 0) { alert('No valid emails'); return; }
                    localStorage.setItem('scoutRecipients', JSON.stringify(validEmails));
                    window.location.href = '/scout';
                }
            </script>
        </body>
        </html>
    ''')

# ==========================================
# SCOUT PAGE (with server-side save)
# ==========================================
@app.route('/scout')
@login_required
def scout():
    return render_template_string('''
        <!DOCTYPE html>
        <html><head><title>Email Scout</title><meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: 'Arial', sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .header { background: #0d9488; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
            .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .recipients { width: 100%; height: 200px; border: 1px solid #ddd; border-radius: 5px; padding: 10px; font-family: monospace; box-sizing: border-box; }
            .btn { background: #0d9488; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; font-size: 16px; }
            .btn-orange { background: #f59e0b; }
            .btn-red { background: #ef4444; }
            .btn-blue { background: #3b82f6; }
            input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px; box-sizing: border-box; }
            .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
            .stat-box { background: white; padding: 20px; text-align: center; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .stat-value { font-size: 24px; font-weight: bold; color: #0d9488; }
            .email-list { max-height: 200px; overflow-y: auto; background: #f9f9f9; padding: 10px; border-radius: 5px; }
            .email-row { padding: 8px; border-bottom: 1px solid #eee; }
        </style></head><body>
        <div class="container">
            <div class="header">
                <h1>📧 Email Scout</h1>
                <p>Send emails — progress is saved on the server</p>
            </div>
            <div class="card">
                <h3>📥 Recipients</h3>
                <textarea id="emailsInput" class="recipients"></textarea>
                <br>
                <button class="btn" onclick="loadFromFinder()">📥 From Finder</button>
                <button class="btn btn-orange" onclick="loadFromVerified()">✅ From Verified</button>
                <button class="btn btn-red" onclick="clearEmails()">Clear</button>
                <div id="emailCount" style="margin-top: 10px;">0 recipients</div>
            </div>
            <div class="card">
                <h3>✍️ Template</h3>
                <label>Subject</label>
                <input type="text" id="subjectLine">
                <label>Message</label>
                <textarea id="messageBody" rows="6"></textarea>
                <div style="margin-top: 10px;">
                    <button class="btn btn-orange" onclick="insertPlaceholder('{name}')">{name}</button>
                    <button class="btn btn-orange" onclick="insertPlaceholder('{email}')">{email}</button>
                </div>
            </div>
            <div class="stat-grid">
                <div class="stat-box"><div class="stat-value" id="totalScouted">0</div><div>Total</div></div>
                <div class="stat-box"><div class="stat-value" id="todayScouted">0</div><div>Today</div></div>
                <div class="stat-box"><div class="stat-value" id="workingRate">0%</div><div>Rate</div></div>
                <div class="stat-box"><div class="stat-value" id="autoClickStatus">Off</div><div>Auto</div></div>
            </div>
            <div class="card">
                <h3>🚀 Launch</h3>
                <button class="btn" onclick="sendEmails()">Start</button>
                <button class="btn btn-red" onclick="stopCampaign()">Stop</button>
                <button class="btn btn-blue" onclick="openBulkGmail()">Open Next 10</button>
                <div id="launchStatus" style="margin-top: 10px;"></div>
            </div>
            <div class="card">
                <h3>📊 Log</h3>
                <div id="log" class="email-list"></div>
            </div>
        </div>
        <script>
            let recipients = [], scoutedEmails = 0, isRunning = false;
            
            window.onload = function() {
                const savedRecipients = localStorage.getItem('scoutRecipients');
                if (savedRecipients) {
                    recipients = JSON.parse(savedRecipients);
                    document.getElementById('emailsInput').value = recipients.join('\\n');
                }
                const savedSubject = localStorage.getItem('scoutSubject');
                if (savedSubject) document.getElementById('subjectLine').value = savedSubject;
                const savedMessage = localStorage.getItem('scoutMessage');
                if (savedMessage) document.getElementById('messageBody').value = savedMessage;
                const savedCount = localStorage.getItem('scoutCount');
                if (savedCount) scoutedEmails = parseInt(savedCount);
                updateUI();
            };
            
            function saveData() {
                localStorage.setItem('scoutRecipients', JSON.stringify(recipients));
                localStorage.setItem('scoutSubject', document.getElementById('subjectLine').value);
                localStorage.setItem('scoutMessage', document.getElementById('messageBody').value);
                localStorage.setItem('scoutCount', scoutedEmails.toString());
                // ALSO save to server
                fetch('/save-scout', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        recipients: recipients,
                        subject: document.getElementById('subjectLine').value,
                        message: document.getElementById('messageBody').value,
                        count: scoutedEmails
                    })
                }).catch(() => {});
            }
            
            async function loadFromFinder() {
                const res = await fetch('/get-stored-emails');
                const data = await res.json();
                if (data.emails && data.emails.length > 0) {
                    recipients = data.emails;
                    document.getElementById('emailsInput').value = recipients.join('\\n');
                    updateUI(); saveData();
                }
            }
            
            async function loadFromVerified() {
                const res = await fetch('/get-verified-emails');
                const data = await res.json();
                if (data.valid && data.valid.length > 0) {
                    recipients = data.valid;
                    document.getElementById('emailsInput').value = recipients.join('\\n');
                    updateUI(); saveData();
                }
            }
            
            function clearEmails() {
                recipients = []; scoutedEmails = 0;
                document.getElementById('emailsInput').value = '';
                document.getElementById('subjectLine').value = '';
                document.getElementById('messageBody').value = '';
                localStorage.clear();
                updateUI(); isRunning = false;
            }
            
            function updateUI() {
                document.getElementById('emailCount').textContent = recipients.length + ' recipients';
                document.getElementById('totalScouted').textContent = scoutedEmails;
                document.getElementById('todayScouted').textContent = scoutedEmails;
                document.getElementById('workingRate').textContent = (recipients.length > 0 ? Math.round((scoutedEmails / recipients.length) * 100) : 0) + '%';
            }
            
            function insertPlaceholder(text) {
                document.getElementById('messageBody').value += text;
                saveData();
            }
            
            function sendEmails() {
                if (recipients.length === 0) { alert('Add recipients'); return; }
                isRunning = true;
                document.getElementById('autoClickStatus').textContent = 'On';
                document.getElementById('launchStatus').innerHTML = '<p style="color: green;">🚀 Started!</p>';
                openNextEmail();
            }
            
            function stopCampaign() {
                isRunning = false;
                document.getElementById('autoClickStatus').textContent = 'Off';
                saveData();
            }
            
            function openNextEmail() {
                if (!isRunning) return;
                if (scoutedEmails >= recipients.length) {
                    isRunning = false;
                    document.getElementById('autoClickStatus').textContent = 'Off';
                    saveData();
                    return;
                }
                const subject = document.getElementById('subjectLine').value;
                const message = document.getElementById('messageBody').value;
                const email = recipients[scoutedEmails];
                const body = message.replace('{name}', 'Store Owner').replace('{email}', email);
                const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
                window.location.href = mailtoLink;
                const log = document.getElementById('log');
                log.innerHTML += '<div class="email-row">📨 Opened: ' + email + '</div>';
                scoutedEmails++; updateUI(); saveData();
            }
            
            document.addEventListener('visibilitychange', function() {
                if (document.visibilityState === 'visible' && isRunning) setTimeout(openNextEmail, 2000);
            });
            
            function openBulkGmail() {
                const subject = document.getElementById('subjectLine').value;
                const message = document.getElementById('messageBody').value;
                for (let i = 0; i < Math.min(10, recipients.length - scoutedEmails); i++) {
                    const email = recipients[scoutedEmails + i];
                    const body = message.replace('{name}', 'Store Owner').replace('{email}', email);
                    const link = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
                    window.open(link, '_blank');
                }
                scoutedEmails += Math.min(10, recipients.length - scoutedEmails);
                updateUI(); saveData();
            }
        </script>
        </body></html>
    ''')

# ==========================================
# SERVER-SIDE SCOUT SAVE
# ==========================================
@app.route('/save-scout', methods=['POST'])
@login_required
def save_scout():
    """Save scouting progress to database"""
    data = request.json
    user_email = session.get('user_id')
    
    conn = get_db()
    if not conn:
        return jsonify({'success': False, 'message': 'No database'})
    
    try:
        cur = conn.cursor()
        # Save each recipient as pending
        for email in data.get('recipients', []):
            cur.execute("""
                INSERT INTO scouting_progress (user_id, email, subject, body, status)
                VALUES ((SELECT id FROM users WHERE email = %s), %s, %s, %s, 'pending')
                ON CONFLICT DO NOTHING
            """, (user_email, email, data.get('subject', ''), data.get('message', '')))
        conn.commit()
        cur.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
    finally:
        conn.close()

# ==========================================
# API ROUTES
# ==========================================
@app.route('/verify-batch', methods=['POST'])
@login_required
def verify_batch():
    data = request.json
    emails = data.get('emails', [])
    if not emails: return jsonify({'success': False}), 400
    valid, invalid = [], []
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            email, is_valid, reason = f.result()
            if is_valid: valid.append(email)
            else: invalid.append(email + " - " + reason)
    return jsonify({'success': True, 'valid': valid, 'invalid': invalid})

@app.route('/store-emails', methods=['POST'])
@login_required
def store_emails():
    global found_emails_store
    found_emails_store = request.json.get('emails', [])
    return jsonify({'success': True})

@app.route('/get-stored-emails')
@login_required
def get_stored_emails():
    return jsonify({'emails': found_emails_store})

@app.route('/store-verified', methods=['POST'])
@login_required
def store_verified():
    global verified_emails_store
    verified_emails_store = request.json.get('valid', [])
    return jsonify({'success': True})

@app.route('/get-verified-emails')
@login_required
def get_verified_emails():
    return jsonify({'valid': verified_emails_store})

@app.route('/bulk-email', methods=['POST'])
@login_required
def bulk_email():
    data = request.json
    stores = data.get('stores', [])[:100]
    results, total = [], 0
    
    # SPEED: 20 workers instead of 10
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(find_emails, s.strip()): s for s in stores if '.' in s}
        for f in as_completed(futures):
            store = futures[f]
            try:
                emails = f.result()
                if emails:
                    total += len(emails)
                    results.append({'store': store, 'emails': emails})
            except: continue
    
    if results:
        return jsonify({'success': True, 'results': results, 'total_emails': total})
    return jsonify({'success': False})

@app.route('/debug/<path:domain>')
def debug(domain):
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(f"https://{domain}/pages/contact", headers=headers, timeout=15)
        return jsonify({
            "status": r.status_code,
            "length": len(r.text),
            "emails": re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', r.text)[:10]
        })
    except Exception as e:
        return jsonify({"error": str(e)})

# Global stores
found_emails_store = []
verified_emails_store = []

# ==========================================
# STARTUP
# ==========================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
