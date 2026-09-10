from flask import Flask, request, jsonify, render_template_string
import requests
import re
import time
import dns.resolver
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.secret_key = 'super_secret_key_12345'

found_emails_store = []
verified_emails_store = []

# ==========================================
# EMAIL VERIFICATION FUNCTION
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
# HOME PAGE (Email Finder)
# ==========================================
@app.route('/')
def home():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Shopify Bulk Email Finder</title>
            <style>
                body { font-family: 'Arial', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; margin: 0; padding: 20px; display: flex; justify-content: center; align-items: flex-start; }
                .container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); width: 600px; }
                h2 { color: #333; margin-bottom: 10px; }
                p { color: #666; }
                textarea { width: 100%; height: 200px; padding: 12px; margin: 15px 0; border: 2px solid #ddd; border-radius: 8px; font-size: 14px; font-family: monospace; }
                button { background: #667eea; color: white; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; width: 100%; margin-bottom: 10px; }
                button:hover { background: #5a67d8; }
                .btn-scout { background: #0d9488; }
                .btn-scout:hover { background: #0f766e; }
                .btn-verify { background: #f59e0b; }
                .btn-verify:hover { background: #d97706; }
                #result { margin-top: 20px; background: #f8f9fa; padding: 15px; border-radius: 8px; }
                .email-item { background: white; padding: 8px; margin: 5px 0; border-radius: 5px; border-left: 4px solid #667eea; font-weight: bold; }
                .store-header { font-weight: bold; color: #333; margin-top: 15px; }
                .error { color: #721c24; background: #f8d7da; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>📧 Shopify Bulk Email Finder</h2>
                <p>Paste up to <b>100 store URLs</b> (one per line) and get their emails instantly.</p>
                <textarea id="urls" placeholder="Enter store URLs here...&#10;deluxura.shop&#10;hipchik.com&#10;ohhappyday.com"></textarea>
                <button onclick="findBulkEmails()">Search All URLs</button>
                
                <button class="btn-verify" onclick="goToVerify()">✅ Verify Emails</button>
                <button class="btn-scout" onclick="goToScout()">📨 Go to Email Scout</button>
                
                <div id="result"></div>
            </div>
            <script>
                async function findBulkEmails() {
                    const input = document.getElementById('urls').value;
                    const result = document.getElementById('result');
                    const stores = input.split('\\n').map(s => s.trim()).filter(s => s.length > 0);
                    if (stores.length === 0) { alert('Please enter at least one store URL'); return; }
                    
                    result.innerHTML = `<p style="color: #666;">Searching ${stores.length} stores... This may take 1-2 minutes.</p>`;
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
                            data.results.forEach(item => {
                                item.emails.forEach(email => { allEmails.push(email); });
                            });
                            
                            fetch('/store-emails', {
                                method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ emails: allEmails })
                            });
                            
                        } else { result.innerHTML = '<div class="error">No emails found for any store.</div>'; }
                    } catch (error) { result.innerHTML = '<div class="error">Server error. Please try again.</div>'; }
                }
                
                function goToVerify() { window.location.href = '/verify'; }
                function goToScout() { window.location.href = '/scout'; }
            </script>
        </body>
        </html>
    ''')

# ==========================================
# VERIFY PAGE (4-Batch Progress)
# ==========================================
@app.route('/verify')
def verify_page():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Verification</title>
            <style>
                body { font-family: 'Arial', sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .header { background: #f59e0b; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .recipients { width: 100%; height: 250px; border: 1px solid #ddd; border-radius: 5px; padding: 10px; font-family: monospace; }
                .btn { background: #f59e0b; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; font-size: 16px; }
                .btn-green { background: #0d9488; }
                .btn-blue { background: #3b82f6; }
                #result { margin-top: 20px; }
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
                    <p>Verify emails via paste, CSV, or TXT upload</p>
                </div>
                
                <div class="card">
                    <h3>📥 Paste Your Emails</h3>
                    <textarea id="emailsInput" class="recipients" placeholder="email1@example.com&#10;email2@example.com"></textarea>
                    
                    <div class="file-upload">
                        <h4>OR Upload File</h4>
                        <input type="file" id="emailFile" accept=".csv,.txt">
                        <button class="btn" onclick="readFile()">Upload & Load Emails</button>
                    </div>
                    
                    <br>
                    <button class="btn" onclick="loadFromFinder()">📥 Load from Email Extracted</button>
                    <button class="btn" onclick="verifyEmails()">🔍 Verify Emails</button>
                    
                    <div class="progress-container" id="progressContainer">
                        <div class="progress-bar" id="progressBar">0%</div>
                        <div class="progress-text" id="progressText">Starting verification...</div>
                    </div>
                    
                    <div id="verificationStatus" style="margin-top: 10px;"></div>
                </div>
                
                <div class="card">
                    <h3>📊 Results</h3>
                    <div id="result"></div>
                    <br>
                    <button class="btn btn-green" onclick="downloadValid()">⬇️ Download Valid Emails</button>
                    <button class="btn btn-blue" onclick="sendValidToScout()">📨 Send Valid to Scout</button>
                </div>
            </div>

            <script>
                let allEmails = [];
                let validEmails = [];
                let invalidEmails = [];
                let isVerifying = false;
                
                async function loadFromFinder() {
                    const res = await fetch('/get-stored-emails');
                    const data = await res.json();
                    if (data.emails && data.emails.length > 0) {
                        document.getElementById('emailsInput').value = data.emails.join('\\n');
                        document.getElementById('verificationStatus').innerHTML = '<p style="color: green;">✅ Loaded ' + data.emails.length + ' emails from Email Finder!</p>';
                    } else {
                        document.getElementById('verificationStatus').innerHTML = '<p style="color: red;">No emails found. Go to Email Finder first.</p>';
                    }
                }
                
                function readFile() {
                    const fileInput = document.getElementById('emailFile');
                    const file = fileInput.files[0];
                    
                    if (!file) {
                        alert('Please select a file first!');
                        return;
                    }
                    
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        const content = e.target.result;
                        const lines = content.split('\\n');
                        const emails = [];
                        
                        lines.forEach(line => {
                            line = line.trim();
                            if (line) {
                                if (line.includes(',')) {
                                    line = line.split(',')[0].trim();
                                }
                                if (line.includes('@')) {
                                    emails.push(line);
                                }
                            }
                        });
                        
                        document.getElementById('emailsInput').value = emails.join('\\n');
                        document.getElementById('verificationStatus').innerHTML = '<p style="color: green;">✅ Loaded ' + emails.length + ' emails from file!</p>';
                    };
                    reader.readAsText(file);
                }
                
                async function verifyEmails() {
                    if (isVerifying) {
                        alert('Verification already in progress!');
                        return;
                    }
                    
                    const input = document.getElementById('emailsInput').value;
                    allEmails = input.split('\\n').map(s => s.trim()).filter(s => s.length > 0);
                    
                    if (allEmails.length === 0) {
                        alert('Please enter emails to verify');
                        return;
                    }
                    
                    validEmails = [];
                    invalidEmails = [];
                    isVerifying = true;
                    
                    document.getElementById('progressContainer').style.display = 'block';
                    document.getElementById('progressBar').style.width = '0%';
                    document.getElementById('progressBar').textContent = '0%';
                    document.getElementById('progressText').textContent = 'Starting verification of ' + allEmails.length + ' emails...';
                    
                    const batchSize = Math.ceil(allEmails.length / 4);
                    
                    for (let i = 0; i < 4; i++) {
                        const start = i * batchSize;
                        const end = Math.min(start + batchSize, allEmails.length);
                        
                        if (start >= allEmails.length) break;
                        
                        const batch = allEmails.slice(start, end);
                        
                        document.getElementById('progressText').textContent = 'Verifying batch ' + (i + 1) + ' of 4...';
                        
                        try {
                            const res = await fetch('/verify-batch', {
                                method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({ emails: batch })
                            });
                            
                            const data = await res.json();
                            
                            if (data.success) {
                                validEmails = validEmails.concat(data.valid);
                                invalidEmails = invalidEmails.concat(data.invalid);
                                
                                const percent = Math.round(((i + 1) / 4) * 100);
                                document.getElementById('progressBar').style.width = percent + '%';
                                document.getElementById('progressBar').textContent = percent + '%';
                                document.getElementById('progressText').textContent = 'Verified ' + validEmails.length + ' valid, ' + invalidEmails.length + ' invalid...';
                            }
                        } catch (error) {
                            document.getElementById('verificationStatus').innerHTML = '<p style="color: red;">Server error. Please try again.</p>';
                            isVerifying = false;
                            return;
                        }
                        
                        await new Promise(resolve => setTimeout(resolve, 500));
                    }
                    
                    isVerifying = false;
                    document.getElementById('progressBar').style.width = '100%';
                    document.getElementById('progressBar').textContent = '100%';
                    document.getElementById('progressText').textContent = '✅ Verification complete!';
                    
                    let html = '<h4>Results:</h4>';
                    html += '<p style="color: green;">✅ Valid: ' + validEmails.length + '</p>';
                    html += '<p style="color: red;">❌ Invalid: ' + invalidEmails.length + '</p>';
                    
                    html += '<h4>Valid Emails:</h4>';
                    validEmails.forEach(email => {
                        html += '<div class="valid-item">✅ ' + email + '</div>';
                    });
                    
                    html += '<h4>Invalid Emails:</h4>';
                    invalidEmails.forEach(email => {
                        html += '<div class="invalid-item">❌ ' + email + '</div>';
                    });
                    
                    document.getElementById('result').innerHTML = html;
                    document.getElementById('verificationStatus').innerHTML = '<p style="color: green;">✅ Verification complete!</p>';
                    
                    fetch('/store-verified', {
                        method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ valid: validEmails, invalid: invalidEmails })
                    });
                }
                
                function downloadValid() {
                    if (validEmails.length === 0) {
                        alert('No valid emails found yet!');
                        return;
                    }
                    
                    let csvContent = "Email\\n";
                    validEmails.forEach(email => {
                        csvContent += email + "\\n";
                    });
                    
                    const blob = new Blob([csvContent], { type: 'text/csv' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'valid_emails.csv';
                    a.click();
                }
                
                function sendValidToScout() {
                    if (validEmails.length === 0) {
                        alert('No valid emails found yet!');
                        return;
                    }
                    
                    localStorage.setItem('scoutRecipients', JSON.stringify(validEmails));
                    window.location.href = '/scout';
                }
            </script>
        </body>
        </html>
    ''')

# ==========================================
# VERIFY BATCH ROUTE
# ==========================================
@app.route('/verify-batch', methods=['POST'])
def verify_batch():
    data = request.json
    emails = data.get('emails', [])
    
    if not emails or len(emails) == 0:
        return jsonify({'success': False, 'message': 'No emails provided'}), 400
    
    valid = []
    invalid = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_email = {executor.submit(verify_email, email): email for email in emails}
        
        for future in as_completed(future_to_email):
            email, is_valid, reason = future.result()
            if is_valid:
                valid.append(email)
            else:
                invalid.append(email + " - " + reason)
    
    return jsonify({'success': True, 'valid': valid, 'invalid': invalid})

# ==========================================
# STORE VERIFIED EMAILS ROUTE
# ==========================================
@app.route('/store-verified', methods=['POST'])
def store_verified():
    global verified_emails_store
    data = request.json
    valid = data.get('valid', [])
    invalid = data.get('invalid', [])
    verified_emails_store = valid
    return jsonify({'success': True})

# ==========================================
# GET VERIFIED EMAILS ROUTE
# ==========================================
@app.route('/get-verified-emails')
def get_verified_emails():
    global verified_emails_store
    return jsonify({'valid': verified_emails_store})

# ==========================================
# STORE EMAILS ROUTE
# ==========================================
@app.route('/store-emails', methods=['POST'])
def store_emails():
    global found_emails_store
    data = request.json
    emails = data.get('emails', [])
    found_emails_store = emails
    return jsonify({'success': True})

# ==========================================
# GET STORED EMAILS ROUTE
# ==========================================
@app.route('/get-stored-emails')
def get_stored_emails():
    global found_emails_store
    return jsonify({'emails': found_emails_store})

# ==========================================
# SCOUT PAGE
# ==========================================
@app.route('/scout')
def scout():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Email Scout</title>
            <style>
                body { font-family: 'Arial', sans-serif; background: #f4f4f4; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; }
                .header { background: #0d9488; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
                .recipients { width: 100%; height: 200px; border: 1px solid #ddd; border-radius: 5px; padding: 10px; font-family: monospace; }
                .btn { background: #0d9488; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin-right: 10px; font-size: 16px; }
                .btn-orange { background: #f59e0b; }
                .btn-red { background: #ef4444; }
                .btn-blue { background: #3b82f6; }
                input[type="text"], textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; margin-bottom: 10px; }
                .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
                .stat-box { background: white; padding: 20px; text-align: center; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .stat-value { font-size: 24px; font-weight: bold; color: #0d9488; }
                .email-list { max-height: 200px; overflow-y: auto; background: #f9f9f9; padding: 10px; border-radius: 5px; }
                .email-row { padding: 8px; border-bottom: 1px solid #eee; }
                .email-row:last-child { border-bottom: none; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>📧 Email Scout</h1>
                    <p>Send personalized cold emails to Shopify store owners</p>
                </div>
                
                <div class="card">
                    <h3>📥 Recipients</h3>
                    <textarea id="emailsInput" class="recipients" placeholder="hello@example.com&#10;support@brand.com"></textarea>
                    <br>
                    <button class="btn" onclick="loadFromFinder()">📥 Load from Email Finder</button>
                    <button class="btn btn-orange" onclick="loadFromVerified()">✅ Load from Verified</button>
                    <button class="btn btn-red" onclick="clearEmails()">Clear</button>
                    <div id="emailCount" style="margin-top: 10px;">0 recipients</div>
                </div>

                <div class="card">
                    <h3>✍️ Message Template</h3>
                    <label>Subject Line</label>
                    <input type="text" id="subjectLine" placeholder="Special offer for your store...">
                    
                    <label>Message Body</label>
                    <textarea id="messageBody" rows="6" placeholder="Hi {{name}}, I found your store {{email}}..."></textarea>
                    
                    <div style="margin-top: 10px;">
                        <span style="font-size: 14px; color: #666;">Insert placeholders:</span>
                        <button class="btn btn-orange" onclick="insertPlaceholder('{name}')">{name}</button>
                        <button class="btn btn-orange" onclick="insertPlaceholder('{email}')">{email}</button>
                    </div>
                    
                    <button class="btn" style="margin-top: 20px;" onclick="generatePreview()">Generate Preview</button>
                    <div id="preview" style="margin-top: 15px; background: #f9f9f9; padding: 15px; border-radius: 5px; display: none;"></div>
                </div>

                <div class="stat-grid">
                    <div class="stat-box"><div class="stat-value" id="totalScouted">0</div><div>Total Scouted</div></div>
                    <div class="stat-box"><div class="stat-value" id="todayScouted">0</div><div>Today Scouted</div></div>
                    <div class="stat-box"><div class="stat-value" id="workingRate">0%</div><div>Working Rate</div></div>
                    <div class="stat-box"><div class="stat-value" id="autoClickStatus">Off</div><div>Auto Click</div></div>
                </div>

                <div class="card">
                    <h3>🚀 Launch Campaign</h3>
                    <button class="btn" onclick="sendEmails()">Start Scouting</button>
                    <button class="btn btn-red" onclick="stopCampaign()">Stop</button>
                    <button class="btn btn-blue" onclick="openBulkGmail()">Open Mail for Next 10</button>
                    <div id="launchStatus" style="margin-top: 10px;"></div>
                </div>
                
                <div class="card">
                    <h3>📊 Scouting Log</h3>
                    <div id="log" class="email-list"></div>
                </div>
            </div>

            <script>
                let recipients = [];
                let scoutedEmails = 0;
                let isRunning = false; 
                
                window.onload = function() {
                    const savedRecipients = localStorage.getItem('scoutRecipients');
                    if (savedRecipients) {
                        recipients = JSON.parse(savedRecipients);
                        document.getElementById('emailsInput').value = recipients.join('\\n');
                    }
                    
                    const savedSubject = localStorage.getItem('scoutSubject');
                    if (savedSubject) { document.getElementById('subjectLine').value = savedSubject; }
                    
                    const savedMessage = localStorage.getItem('scoutMessage');
                    if (savedMessage) { document.getElementById('messageBody').value = savedMessage; }
                    
                    const savedCount = localStorage.getItem('scoutCount');
                    if (savedCount) { scoutedEmails = parseInt(savedCount); }
                    
                    updateUI();
                };
                
                function saveData() {
                    localStorage.setItem('scoutRecipients', JSON.stringify(recipients));
                    localStorage.setItem('scoutSubject', document.getElementById('subjectLine').value);
                    localStorage.setItem('scoutMessage', document.getElementById('messageBody').value);
                    localStorage.setItem('scoutCount', scoutedEmails.toString());
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
                    recipients = [];
                    document.getElementById('emailsInput').value = '';
                    document.getElementById('subjectLine').value = '';
                    document.getElementById('messageBody').value = '';
                    scoutedEmails = 0;
                    
                    localStorage.removeItem('scoutRecipients');
                    localStorage.removeItem('scoutSubject');
                    localStorage.removeItem('scoutMessage');
                    localStorage.removeItem('scoutCount');
                    
                    updateUI(); isRunning = false;
                }
                
                function updateUI() {
                    document.getElementById('emailCount').textContent = recipients.length + ' recipients';
                    document.getElementById('totalScouted').textContent = scoutedEmails;
                    document.getElementById('todayScouted').textContent = scoutedEmails;
                    document.getElementById('workingRate').textContent = (recipients.length > 0 ? Math.round((scoutedEmails / recipients.length) * 100) : 0) + '%';
                }
                
                function insertPlaceholder(text) {
                    const textarea = document.getElementById('messageBody');
                    textarea.value += text;
                    saveData();
                }
                
                function generatePreview() {
                    const subject = document.getElementById('subjectLine').value;
                    const message = document.getElementById('messageBody').value;
                    const preview = document.getElementById('preview');
                    preview.innerHTML = `<h4>Preview:</h4><strong>Subject:</strong> ${subject}<br><br><strong>Message:</strong><br>${message.replace('{name}', 'John Doe').replace('{email}', 'john@store.com')}`;
                    preview.style.display = 'block';
                }
                
                function sendEmails() {
                    if (recipients.length === 0) { alert('Please add recipients first!'); return; }
                    isRunning = true;
                    document.getElementById('autoClickStatus').textContent = 'On';
                    document.getElementById('launchStatus').innerHTML = '<p style="color: green;">🚀 Campaign started! Open Gmail, send the email, then return to this tab.</p>';
                    openNextEmail();
                }
                
                function stopCampaign() {
                    isRunning = false;
                    document.getElementById('autoClickStatus').textContent = 'Off';
                    document.getElementById('launchStatus').innerHTML = '<p style="color: red;">⏹️ Campaign stopped.</p>';
                    saveData();
                }
                
                function openNextEmail() {
                    if (!isRunning) { return; }
                    if (scoutedEmails >= recipients.length) {
                        document.getElementById('launchStatus').innerHTML = '<p style="color: blue;">🎉 Campaign complete! All emails scouted.</p>';
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
                    log.innerHTML += `<div class="email-row">📨 Opened draft for: ${email}</div>`;
                    log.scrollTop = log.scrollHeight;
                    
                    scoutedEmails++;
                    updateUI(); saveData();
                    
                    document.getElementById('launchStatus').innerHTML = '<p style="color: green;">✅ Draft opened for ' + email + '. Send it in Gmail, then come back here.</p>';
                }
                
                document.addEventListener('visibilitychange', function() {
                    if (document.visibilityState === 'visible' && isRunning) {
                        setTimeout(openNextEmail, 2000);
                    }
                });
                
                document.addEventListener('click', function() {
                    if (isRunning && scoutedEmails < recipients.length) {
                        setTimeout(openNextEmail, 2000);
                    }
                });
                
                function openBulkGmail() {
                    const subject = document.getElementById('subjectLine').value;
                    const message = document.getElementById('messageBody').value;
                    
                    for (let i = 0; i < Math.min(10, recipients.length - scoutedEmails); i++) {
                        const email = recipients[scoutedEmails + i];
                        const body = message.replace('{name}', 'Store Owner').replace('{email}', email);
                        const mailtoLink = `mailto:${email}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
                        window.open(mailtoLink, '_blank');
                        const log = document.getElementById('log');
                        log.innerHTML += `<div class="email-row">📨 Prepared draft for: ${email}</div>`;
                    }
                    
                    scoutedEmails += Math.min(10, recipients.length - scoutedEmails);
                    updateUI(); saveData();
                    
                    document.getElementById('launchStatus').innerHTML = '<p style="color: green;">✅ Opened 10 drafts. Send them, then come back and click again.</p>';
                }
            </script>
        </body>
        </html>
    ''')

# ==========================================
# ADVANCED EMAIL FINDING FUNCTION (V4 - Bulletproof)
# ==========================================
def find_emails(domain):
    # CLEAN THE URL
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    
    emails = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }
    
    # METHOD 1: Fetch the contact pages and strip HTML
    pages_to_check = [
        f"https://{domain}/pages/contact",
        f"https://{domain}/pages/contact-us",
        f"https://{domain}/contact",
        f"https://{domain}/pages/about",
        f"https://{domain}/pages/customer-service",
        f"https://{domain}/pages/support",
        f"https://{domain}",
    ]
    
    for page_url in pages_to_check:
        try:
            r = requests.get(page_url, headers=headers, timeout=10)
            if r.status_code == 200:
                # Strip all HTML/JS/CSS
                clean = re.sub(r'<script[^>]*>.*?</script>', ' ', r.text, flags=re.DOTALL)
                clean = re.sub(r'<style[^>]*>.*?</style>', ' ', clean, flags=re.DOTALL)
                clean = re.sub(r'<[^>]+>', ' ', clean)
                
                # Search emails in clean text
                found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean)
                for email in found:
                    emails.append(email.lower())
                
                # Decode Cloudflare data-cfemail
                cf_emails = re.findall(r'data-cfemail="([a-f0-9]+)"', r.text)
                for cf in cf_emails:
                    try:
                        key = int(cf[:2], 16)
                        decoded = ''.join([chr(int(cf[i:i+2], 16) ^ key) for i in range(2, len(cf), 2)])
                        if '@' in decoded and '.' in decoded:
                            emails.append(decoded.lower())
                    except:
                        pass
                
                # Find mailto: links
                mailtos = re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text)
                for email in mailtos:
                    emails.append(email.lower())
        except:
            continue
    
    # METHOD 2: Fetch sitemap and check /pages/ URLs
    try:
        r = requests.get(f"https://{domain}/sitemap.xml", headers=headers, timeout=8)
        if r.status_code == 200:
            page_urls = re.findall(r'<loc>(https://[^<]*?/pages/[^<]+)</loc>', r.text)
            for page_url in page_urls[:5]:
                try:
                    r2 = requests.get(page_url, headers=headers, timeout=8)
                    if r2.status_code == 200:
                        clean = re.sub(r'<[^>]+>', ' ', r2.text)
                        found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', clean)
                        for email in found:
                            emails.append(email.lower())
                except:
                    continue
    except:
        pass
    
    # Filter out junk emails
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
    
    return final_emails

# ==========================================
# BULK EMAIL ROUTE
# ==========================================
@app.route('/bulk-email', methods=['POST'])
def bulk_email():
    data = request.json
    stores = data.get('stores', [])
    
    if not stores or len(stores) == 0:
        return jsonify({'success': False, 'message': 'No stores provided'}), 400
    
    stores = stores[:100]
    
    results = []
    total_emails = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_store = {executor.submit(find_emails, store.strip()): store for store in stores if '.' in store}
        
        for future in as_completed(future_to_store):
            store = future_to_store[future]
            try:
                emails = future.result()
                if emails:
                    total_emails += len(emails)
                    results.append({'store': store, 'emails': emails})
            except:
                continue
    
    if results:
        return jsonify({'success': True, 'results': results, 'total_emails': total_emails})
    else:
        return jsonify({'success': False, 'message': 'No emails found for any store'})

# ==========================================
# SINGLE EMAIL ROUTE
# ==========================================
@app.route('/get-email', methods=['POST'])
def get_email():
    data = request.json
    store_url = data.get('store_url', '').strip()
    
    if not store_url or '.' not in store_url:
        return jsonify({'error': 'Invalid store URL'}), 400
    
    emails = find_emails(store_url)
    
    if emails:
        return jsonify({'success': True, 'emails': emails})
    else:
        return jsonify({'success': False, 'message': 'No email found'})
