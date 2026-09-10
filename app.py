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
import psycopg2

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345_change_this'

DATABASE_URL = os.environ.get('DATABASE_URL')

# ==========================================
# DATABASE
# ==========================================
def get_db():
    if not DATABASE_URL:
        return None
    try:
        return psycopg2.connect(DATABASE_URL, sslmode='require')
    except:
        return None

def init_db():
    conn = get_db()
    if not conn:
        print("⚠️  No DATABASE_URL — memory mode only")
        return
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS scraped_stores (
            id SERIAL PRIMARY KEY,
            domain VARCHAR(255) UNIQUE NOT NULL,
            emails TEXT,
            scraped_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS user_state (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255) UNIQUE NOT NULL,
            found_emails TEXT,
            verified_emails TEXT,
            scout_recipients TEXT,
            scout_subject TEXT,
            scout_message TEXT,
            scout_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
        conn.commit()
        cur.close()
        print("✅ Database ready")
    except Exception as e:
        print(f"❌ DB init error: {e}")
    finally:
        conn.close()

try:
    init_db()
except:
    pass

# ==========================================
# HELPERS
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def get_cached_emails(domain):
    conn = get_db()
    if not conn:
        return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT emails FROM scraped_stores WHERE domain = %s AND scraped_at > NOW() - INTERVAL '7 days'", (domain,))
        row = cur.fetchone()
        cur.close()
        return row[0].split(',') if row and row[0] else None
    except:
        return None
    finally:
        conn.close()

def cache_emails(domain, emails):
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""INSERT INTO scraped_stores (domain, emails) VALUES (%s, %s)
            ON CONFLICT (domain) DO UPDATE SET emails = %s, scraped_at = NOW()""",
            (domain, ','.join(emails), ','.join(emails)))
        conn.commit()
        cur.close()
    except:
        pass
    finally:
        conn.close()

def save_user_state(user_email, **kwargs):
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM user_state WHERE user_email = %s", (user_email,))
        exists = cur.fetchone()
        if exists:
            for key, val in kwargs.items():
                if val is not None:
                    cur.execute(f"UPDATE user_state SET {key}=%s, updated_at=NOW() WHERE user_email=%s", (val, user_email))
        else:
            cur.execute("""INSERT INTO user_state (user_email, found_emails, verified_emails, scout_recipients, scout_subject, scout_message, scout_count)
                VALUES (%s, '', '', '', '', '', 0)""", (user_email,))
            for key, val in kwargs.items():
                if val is not None:
                    cur.execute(f"UPDATE user_state SET {key}=%s, updated_at=NOW() WHERE user_email=%s", (val, user_email))
        conn.commit()
        cur.close()
    except Exception as e:
        print(f"save_user_state error: {e}")
    finally:
        conn.close()

def load_user_state(user_email):
    conn = get_db()
    if not conn:
        return {}
    try:
        cur = conn.cursor()
        cur.execute("SELECT found_emails, verified_emails, scout_recipients, scout_subject, scout_message, scout_count FROM user_state WHERE user_email = %s", (user_email,))
        row = cur.fetchone()
        cur.close()
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
    except:
        return {}
    finally:
        conn.close()

# ==========================================
# EMAIL VERIFICATION
# ==========================================
def verify_email(email):
    try:
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return email, False, "Invalid syntax"
        domain = email.split('@')[1]
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            if len(mx) == 0:
                return email, False, "No mail server"
        except dns.resolver.NXDOMAIN:
            return email, False, "Domain doesn't exist"
        except dns.resolver.NoAnswer:
            return email, False, "No MX records"
        except:
            return email, False, "Cannot resolve"
        try:
            server = smtplib.SMTP(str(mx[0].exchange), timeout=5)
            server.ehlo()
            resp = server.verify(email)
            server.quit()
            return (email, True, "Valid & Active") if resp[0] == 250 else (email, False, "Mailbox may not exist")
        except:
            return email, True, "Valid (Domain-based)"
    except:
        return email, False, "Unknown error"

# ==========================================
# EMAIL FINDER
# ==========================================
def find_emails(domain):
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "")
    domain = domain.split("/")[0]
    if not domain or '.' not in domain:
        return []
    cached = get_cached_emails(domain)
    if cached is not None:
        return cached
    emails = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for page_url in [f"https://{domain}/pages/contact", f"https://{domain}/pages/contact-us", f"https://{domain}/contact", f"https://{domain}"]:
        try:
            r = requests.get(page_url, headers=headers, timeout=8)
            if r.status_code == 200:
                clean = re.sub(r'<script[^>]*>.*?</script>', ' ', r.text, flags=re.DOTALL)
                clean = re.sub(r'<[^>]+>', ' ', clean)
                for e in re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean):
                    emails.append(e.lower())
                for cf in re.findall(r'data-cfemail="([a-f0-9]+)"', r.text):
                    try:
                        key = int(cf[:2], 16)
                        d = ''.join([chr(int(cf[i:i+2], 16) ^ key) for i in range(2, len(cf), 2)])
                        if '@' in d and '.' in d:
                            emails.append(d.lower())
                    except:
                        pass
                for e in re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text):
                    emails.append(e.lower())
                if len(set(emails)) >= 3:
                    break
        except:
            continue
    skip = ['.jpg', '.png', '.jpeg', '.gif', '.svg', '2x', '3x', 'wix', 'sentry',
            'godaddy', 'namecheap', 'markmonitor', 'tucows', 'domainabuse', 'abuse@',
            'whoisproxy', 'whoisrequest', 'contactprivacy', 'withheldforprivacy',
            'example.com', 'example.org', 'wixpress', 'cloudflare', 'xinnet', 
            'wildwest', 'dnai', 'web.com', 'domainmarket', 'no-reply@registrar', 
            'protect@', 'shopify.com', 'myshopify.com', 'you@email.com', 'your@email.com',
            'email@email.com', 'test@test.com', 'user@email.com', 'name@email.com',
            'service@domainmarket', 'interested@', 'sentry.io', 'facebook.com',
            'instagram.com', 'twitter.com', 'pinterest.com', '@2x', '@3x']
    final = []
    for e in set(emails):
        if len(e) > 5 and '.' in e and not any(x in e for x in skip):
            final.append(e)
    cache_emails(domain, final)
    return final

# ==========================================
# AUTH PAGES
# ==========================================
SIGNUP_HTML = '''<!DOCTYPE html><html><head><title>Sign Up</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}.box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.3);width:100%;max-width:400px}h2{color:#333;text-align:center;margin-bottom:30px}input{width:100%;padding:12px;margin:8px 0;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box}button{width:100%;padding:12px;background:#667eea;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px}.error{color:#721c24;background:#f8d7da;padding:10px;border-radius:5px;margin-bottom:15px}.link{text-align:center;margin-top:15px;color:#666}.link a{color:#667eea;text-decoration:none}</style></head><body>
<div class="box"><h2>📧 Create Account</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password (min 6)" required minlength="6"><button type="submit">Sign Up</button></form>
<div class="link">Already have an account? <a href="/login">Log in</a></div></div></body></html>'''

LOGIN_HTML = '''<!DOCTYPE html><html><head><title>Login</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:20px}.box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.3);width:100%;max-width:400px}h2{color:#333;text-align:center;margin-bottom:30px}input{width:100%;padding:12px;margin:8px 0;border:2px solid #ddd;border-radius:8px;font-size:16px;box-sizing:border-box}button{width:100%;padding:12px;background:#667eea;color:white;border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px}.error{color:#721c24;background:#f8d7da;padding:10px;border-radius:5px;margin-bottom:15px}.link{text-align:center;margin-top:15px;color:#666}.link a{color:#667eea;text-decoration:none}</style></head><body>
<div class="box"><h2>📧 Login</h2>{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="POST"><input type="email" name="email" placeholder="Email" required><input type="password" name="password" placeholder="Password" required><button type="submit">Log In</button></form>
<div class="link">No account? <a href="/signup">Sign up</a></div></div></body></html>'''

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or not password:
            return render_template_string(SIGNUP_HTML, error="Fill all fields")
        conn = get_db()
        if not conn:
            return render_template_string(SIGNUP_HTML, error="Database not available")
        try:
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", (email, hash_password(password)))
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
            cur.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            cur.close()
            if row and row[0] == hash_password(password):
                session['user_id'] = email
                return redirect('/')
            return render_template_string(LOGIN_HTML, error="Invalid credentials")
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
# HOME
# ==========================================
@app.route('/')
@login_required
def home():
    return render_template_string('''<!DOCTYPE html><html><head><title>Shopify Email Finder</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;margin:0;padding:20px;display:flex;justify-content:center;align-items:flex-start}.container{background:white;padding:30px;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,0.3);width:100%;max-width:600px;box-sizing:border-box}.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}h2{color:#333;margin:0}.logout{background:#ef4444;color:white;padding:8px 16px;border-radius:5px;text-decoration:none;font-size:14px}textarea{width:100%;height:180px;padding:12px;margin:15px 0;border:2px solid #ddd;border-radius:8px;font-size:14px;font-family:monospace;box-sizing:border-box}button{background:#667eea;color:white;padding:12px 30px;border:none;border-radius:8px;cursor:pointer;font-size:16px;width:100%;margin-bottom:10px}.btn-verify{background:#f59e0b}.btn-scout{background:#0d9488}#result{margin-top:20px;background:#f8f9fa;padding:15px;border-radius:8px;min-height:40px}.email-item{background:white;padding:8px;margin:5px 0;border-radius:5px;border-left:4px solid #667eea;font-weight:bold;word-break:break-all}.store-header{font-weight:bold;color:#333;margin-top:15px}.error{color:#721c24;background:#f8d7da;padding:10px;border-radius:5px}</style></head><body>
<div class="container">
<div class="top"><h2>📧 Shopify Email Finder</h2><a href="/logout" class="logout">Logout</a></div>
<p>Paste up to <b>100 store URLs</b> (one per line).</p>
<textarea id="urls" placeholder="deluxura.shop&#10;hipchik.com&#10;ohhappyday.com"></textarea>
<button onclick="findBulkEmails()">Search All URLs</button>
<button class="btn-verify" onclick="window.location.href='/verify'">✅ Verify Emails</button>
<button class="btn-scout" onclick="window.location.href='/scout'">📨 Go to Email Scout</button>
<div id="result"></div>
</div>
<script>
async function findBulkEmails(){
  const input=document.getElementById('urls').value;
  const result=document.getElementById('result');
  const stores=input.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(stores.length===0){alert('Enter at least one URL');return}
  result.innerHTML='<p style="color:#666">Searching '+stores.length+' stores...</p>';
  try{
    const res=await fetch('/bulk-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stores:stores})});
    const data=await res.json();
    if(data.success){
      let html='<h4 style="color:#155724">✅ Found emails for '+data.results.length+' stores:</h4>';
      data.results.forEach(item=>{
        html+='<div class="store-header">📦 '+item.store+':</div>';
        item.emails.forEach(e=>{html+='<div class="email-item">'+e+'</div>'});
      });
      result.innerHTML=html;
    } else { result.innerHTML='<div class="error">No emails found.</div>'; }
  }catch(e){result.innerHTML='<div class="error">Server error: '+e+'</div>'}
}
</script></body></html>''')

# ==========================================
# VERIFY PAGE
# ==========================================
@app.route('/verify')
@login_required
def verify_page():
    return render_template_string('''<!DOCTYPE html><html><head><title>Verify Emails</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:#f4f4f4;margin:0;padding:20px}.container{max-width:800px;margin:0 auto}.header{background:#f59e0b;color:white;padding:20px;border-radius:10px;margin-bottom:20px}.card{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);margin-bottom:20px}.recipients{width:100%;height:250px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box}.btn{background:#f59e0b;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:10px;font-size:16px;margin-bottom:10px}.btn-green{background:#0d9488}.btn-blue{background:#3b82f6}.valid-item{background:#d4edda;padding:8px;border-radius:5px;margin:5px 0;color:#155724;word-break:break-all}.invalid-item{background:#f8d7da;padding:8px;border-radius:5px;margin:5px 0;color:#721c24;word-break:break-all}.file-upload{border:2px dashed #ddd;padding:20px;text-align:center;margin:10px 0}.progress-container{width:100%;background:#e0e0e0;border-radius:10px;margin:20px 0;display:none}.progress-bar{width:0%;height:20px;background:linear-gradient(90deg,#4ade80,#22c55e);border-radius:10px;transition:width 0.3s;text-align:center;color:white;font-size:12px;line-height:20px}.progress-text{font-size:14px;font-weight:bold;color:#333;margin-top:5px}</style></head><body>
<div class="container">
<div class="header"><h1>✅ Email Verification</h1><p>Paste, upload CSV/TXT, or load from finder</p></div>
<div class="card">
<textarea id="emailsInput" class="recipients" placeholder="email1@example.com&#10;email2@example.com"></textarea>
<div class="file-upload"><h4>OR Upload File</h4><input type="file" id="emailFile" accept=".csv,.txt"><button class="btn" onclick="readFile()">Upload & Load</button></div>
<button class="btn" onclick="loadFromFinder()">📥 Load from Email Extracted</button>
<button class="btn btn-green" onclick="verifyEmails()">🔍 Verify Emails</button>
<div class="progress-container" id="progressContainer"><div class="progress-bar" id="progressBar">0%</div><div class="progress-text" id="progressText">Starting...</div></div>
<div id="verificationStatus" style="margin-top:10px"></div>
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
let validEmails=[],invalidEmails=[],isVerifying=false;
async function loadFromFinder(){
  const res=await fetch('/get-stored-emails');
  const data=await res.json();
  if(data.emails&&data.emails.length>0){
    document.getElementById('emailsInput').value=data.emails.join('\\n');
    document.getElementById('verificationStatus').innerHTML='<p style="color:green">✅ Loaded '+data.emails.length+' emails</p>';
  } else {
    document.getElementById('verificationStatus').innerHTML='<p style="color:red">No emails found. Go to Finder first.</p>';
  }
}
function readFile(){
  const file=document.getElementById('emailFile').files[0];
  if(!file){alert('Select a file');return}
  const reader=new FileReader();
  reader.onload=function(e){
    const lines=e.target.result.split('\\n');
    const emails=[];
    lines.forEach(line=>{
      line=line.trim();
      if(line.includes(','))line=line.split(',')[0].trim();
      if(line.includes('@'))emails.push(line);
    });
    document.getElementById('emailsInput').value=emails.join('\\n');
    document.getElementById('verificationStatus').innerHTML='<p style="color:green">✅ Loaded '+emails.length+' emails</p>';
  };
  reader.readAsText(file);
}
async function verifyEmails(){
  if(isVerifying){alert('Already verifying');return}
  const input=document.getElementById('emailsInput').value;
  const allEmails=input.split('\\n').map(s=>s.trim()).filter(s=>s.length>0);
  if(allEmails.length===0){alert('Enter emails');return}
  validEmails=[];invalidEmails=[];isVerifying=true;
  document.getElementById('progressContainer').style.display='block';
  document.getElementById('progressBar').style.width='0%';
  document.getElementById('progressBar').textContent='0%';
  document.getElementById('progressText').textContent='Processing '+allEmails.length+' emails...';
  try{
    const res=await fetch('/verify-batch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({emails:allEmails})});
    const data=await res.json();
    if(data.success){
      validEmails=data.valid;
      invalidEmails=data.invalid;
      document.getElementById('progressBar').style.width='100%';
      document.getElementById('progressBar').textContent='100%';
      document.getElementById('progressText').textContent='✅ Done';
      let html='<p style="color:green">✅ Valid: '+validEmails.length+'</p>';
      html+='<p style="color:red">❌ Invalid: '+invalidEmails.length+'</p>';
      html+='<h4>Valid:</h4>';
      validEmails.forEach(e=>{html+='<div class="valid-item">✅ '+e+'</div>'});
      html+='<h4>Invalid:</h4>';
      invalidEmails.forEach(e=>{html+='<div class="invalid-item">❌ '+e+'</div>'});
      document.getElementById('result').innerHTML=html;
    }
  }catch(e){
    document.getElementById('verificationStatus').innerHTML='<p style="color:red">Error: '+e+'</p>';
  }
  isVerifying=false;
}
function downloadValid(){
  if(validEmails.length===0){alert('No valid emails');return}
  const csv='Email\\n'+validEmails.join('\\n');
  const blob=new Blob([csv],{type:'text/csv'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url;a.download='valid_emails.csv';a.click();
}
function sendValidToScout(){
  if(validEmails.length===0){alert('No valid emails');return}
  fetch('/save-scout-recipients',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipients:validEmails})}).then(()=>{window.location.href='/scout'});
}
</script></body></html>''')

# ==========================================
# SCOUT PAGE
# ==========================================
@app.route('/scout')
@login_required
def scout():
    return render_template_string('''<!DOCTYPE html><html><head><title>Email Scout</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:Arial;background:#f4f4f4;margin:0;padding:20px}.container{max-width:800px;margin:0 auto}.header{background:#0d9488;color:white;padding:20px;border-radius:10px;margin-bottom:20px}.card{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);margin-bottom:20px}.recipients{width:100%;height:180px;border:1px solid #ddd;border-radius:5px;padding:10px;font-family:monospace;box-sizing:border-box}.btn{background:#0d9488;color:white;padding:10px 20px;border:none;border-radius:5px;cursor:pointer;margin-right:10px;font-size:16px;margin-bottom:10px}.btn-orange{background:#f59e0b}.btn-red{background:#ef4444}.btn-blue{background:#3b82f6}input[type=text],textarea{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;margin-bottom:10px;box-sizing:border-box}.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}.stat-box{background:white;padding:15px;text-align:center;border-radius:10px;box-shadow:0 2px 5px rgba(0,0,0,0.1)}.stat-value{font-size:22px;font-weight:bold;color:#0d9488}.email-list{max-height:150px;overflow-y:auto;background:#f9f9f9;padding:10px;border-radius:5px}.email-row{padding:5px;border-bottom:1px solid #eee;font-size:13px;word-break:break-all}</style></head><body>
<div class="container">
<div class="header"><h1>📧 Email Scout</h1><p>Progress saved on server</p></div>
<div class="card">
<h3>📥 Recipients</h3>
<textarea id="emailsInput" class="recipients"></textarea>
<button class="btn" onclick="loadFromFinder()">📥 From Finder</button>
<button class="btn btn-orange" onclick="loadFromVerified()">✅ From Verified</button>
<button class="btn btn-red" onclick="clearAll()">Clear</button>
<div id="emailCount" style="margin-top:10px">0 recipients</div>
</div>
<div class="card">
<h3>✍️ Template</h3>
<label>Subject</label>
<input type="text" id="subjectLine">
<label>Message</label>
<textarea id="messageBody" rows="5"></textarea>
<button class="btn btn-orange" onclick="insertPh('{name}')">{name}</button>
<button class="btn btn-orange" onclick="insertPh('{email}')">{email}</button>
<button class="btn" onclick="generatePreview()">👁️ Generate Preview</button>
<div id="preview" style="margin-top:10px;background:#f9f9f9;padding:10px;border-radius:5px;display:none;font-size:13px"></div>
</div>
<div class="stat-grid">
<div class="stat-box"><div class="stat-value" id="totalScouted">0</div><div>Total</div></div>
<div class="stat-box"><div class="stat-value" id="todayScouted">0</div><div>Today</div></div>
<div class="stat-box"><div class="stat-value" id="workingRate">0%</div><div>Rate</div></div>
<div class="stat-box"><div class="stat-value" id="autoClickStatus">Off</div><div>Auto</div></div>
</div>
<div class="card">
<h3>🚀 Launch</h3>
<button class="btn" onclick="startCampaign()">Start Scouting</button>
<button class="btn btn-red" onclick="stopCampaign()">Stop</button>
<button class="btn btn-blue" onclick="openBulk()">Open Next 10</button>
<div id="launchStatus" style="margin-top:10px"></div>
</div>
<div class="card">
<h3>📊 Log</h3>
<div id="log" class="email-list"></div>
</div>
</div>
<script>
let recipients=[],scoutedEmails=0,isRunning=false;
window.onload=async function(){
  try{
    const res=await fetch('/load-scout-state');
    const data=await res.json();
    if(data.recipients&&data.recipients.length>0){
      recipients=data.recipients;
      document.getElementById('emailsInput').value=recipients.join('\\n');
    }
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
  try{
    await fetch('/save-scout-state',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      recipients:recipients,
      subject:document.getElementById('subjectLine').value,
      message:document.getElementById('messageBody').value,
      count:scoutedEmails
    })});
  }catch(e){}
}
async function loadFromFinder(){
  const res=await fetch('/get-stored-emails');
  const data=await res.json();
  if(data.emails&&data.emails.length>0){
    recipients=data.emails;
    document.getElementById('emailsInput').value=recipients.join('\\n');
    updateUI();saveState();
  }
}
async function loadFromVerified(){
  const res=await fetch('/get-verified-emails');
  const data=await res.json();
  if(data.valid&&data.valid.length>0){
    recipients=data.valid;
    document.getElementById('emailsInput').value=recipients.join('\\n');
    updateUI();saveState();
  }
}
function clearAll(){
  recipients=[];scoutedEmails=0;
  document.getElementById('emailsInput').value='';
  document.getElementById('subjectLine').value='';
  document.getElementById('messageBody').value='';
  updateUI();saveState();isRunning=false;
  document.getElementById('autoClickStatus').textContent='Off';
}
function insertPh(text){document.getElementById('messageBody').value+=text;saveState()}
function generatePreview(){
  const subj=document.getElementById('subjectLine').value;
  const msg=document.getElementById('messageBody').value;
  const p=document.getElementById('preview');
  p.innerHTML='<b>Subject:</b> '+subj+'<br><br><b>Message:</b><br>'+msg.replace('{name}','John Doe').replace('{email}','john@store.com');
  p.style.display='block';
}
function startCampaign(){
  if(recipients.length===0){alert('Add recipients first');return}
  isRunning=true;
  document.getElementById('autoClickStatus').textContent='On';
  document.getElementById('launchStatus').innerHTML='<p style="color:green">🚀 Campaign started!</p>';
  openNextEmail();
}
function stopCampaign(){
  isRunning=false;
  document.getElementById('autoClickStatus').textContent='Off';
  document.getElementById('launchStatus').innerHTML='<p style="color:red">⏹️ Stopped.</p>';
  saveState();
}
function openNextEmail(){
  if(!isRunning)return;
  if(scoutedEmails>=recipients.length){
    isRunning=false;
    document.getElementById('autoClickStatus').textContent='Off';
    document.getElementById('launchStatus').innerHTML='<p style="color:blue">🎉 Complete!</p>';
    saveState();return;
  }
  const email=recipients[scoutedEmails];
  const subj=document.getElementById('subjectLine').value;
  const msg=document.getElementById('messageBody').value;
  const body=msg.replace('{name}','Store Owner').replace('{email}',email);
  const link='mailto:'+email+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body);
  window.location.href=link;
  const log=document.getElementById('log');
  log.innerHTML+='<div class="email-row">📨 Opened: '+email+'</div>';
  log.scrollTop=log.scrollHeight;
  scoutedEmails++;updateUI();saveState();
}
document.addEventListener('visibilitychange',function(){
  if(document.visibilityState==='visible'&&isRunning)setTimeout(openNextEmail,2000);
});
document.addEventListener('click',function(){
  if(isRunning&&scoutedEmails<recipients.length&&!event.target.closest('button'))setTimeout(openNextEmail,2000);
});
function openBulk(){
  const subj=document.getElementById('subjectLine').value;
  const msg=document.getElementById('messageBody').value;
  for(let i=0;i<Math.min(10,recipients.length-scoutedEmails);i++){
    const email=recipients[scoutedEmails+i];
    const body=msg.replace('{name}','Store Owner').replace('{email}',email);
    window.open('mailto:'+email+'?subject='+encodeURIComponent(subj)+'&body='+encodeURIComponent(body),'_blank');
  }
  scoutedEmails+=Math.min(10,recipients.length-scoutedEmails);
  updateUI();saveState();
}
</script></body></html>''')

# ==========================================
# API ROUTES
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
                if emails:
                    results.append({'store': futures[f], 'emails': emails})
            except: continue
    user_email = session.get('user_id')
    all_found = []
    for r in results:
        all_found.extend(r['emails'])
    if user_email and all_found:
        save_user_state(user_email, found_emails='|||'.join(all_found))
    return jsonify({'success': bool(results), 'results': results})

@app.route('/verify-batch', methods=['POST'])
@login_required
def verify_batch():
    emails = request.json.get('emails', [])
    if not emails:
        return jsonify({'success': False})
    valid, invalid = [], []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            email, ok, reason = f.result()
            if ok: valid.append(email)
            else: invalid.append(email + " - " + reason)
    user_email = session.get('user_id')
    if user_email:
        save_user_state(user_email, verified_emails='|||'.join(valid))
    return jsonify({'success': True, 'valid': valid, 'invalid': invalid})

@app.route('/store-emails', methods=['POST'])
@login_required
def store_emails():
    emails = request.json.get('emails', [])
    user_email = session.get('user_id')
    if user_email:
        save_user_state(user_email, found_emails='|||'.join(emails))
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
    if user_email:
        save_user_state(user_email, scout_recipients='|||'.join(recipients))
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
