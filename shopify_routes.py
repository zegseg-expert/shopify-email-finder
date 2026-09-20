# shopify_routes.py — Leadita-fed Shopify warehouse + pipeline. Independent from app.py / wix_app.py.
import os
import json
import threading
import requests
from flask import Blueprint, request, jsonify, session, redirect

shopify_bp = Blueprint('shopify_bp', __name__)
DATABASE_URL = os.environ.get('DATABASE_URL')

import psycopg2

def sh_get_db():
    if not DATABASE_URL: return None
    try:
        return psycopg2.connect(DATABASE_URL, sslmode='require')
    except Exception as e:
        print(f"shopify db err: {e}")
        return None

def sh_release(conn):
    if conn:
        try: conn.close()
        except: pass

def sh_init_db():
    conn = sh_get_db()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS shopify_warehouse (
            id BIGSERIAL PRIMARY KEY, url TEXT UNIQUE NOT NULL, domain TEXT NOT NULL,
            source TEXT, title TEXT, country TEXT, status TEXT DEFAULT 'pending',
            created_at TIMESTAMPTZ DEFAULT NOW(), verified_at TIMESTAMPTZ,
            audited_at TIMESTAMPTZ, notes TEXT)""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_shopify_warehouse_status ON shopify_warehouse(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_shopify_warehouse_created ON shopify_warehouse(created_at DESC)")
        conn.commit(); cur.close()
        print("✅ shopify_warehouse ready")
    except Exception as e:
        print(f"⚠️ shopify init db: {e}")
    finally:
        sh_release(conn)

def _run_ingest():
    try:
        import importlib, ingest_leadita_shopify
        importlib.reload(ingest_leadita_shopify)
        return ingest_leadita_shopify.run(sh_get_db, sh_release)
    except Exception as e:
        return {'status': 'error', 'error': f'{e}'}

def _navbar():
    return '''
<style>
.navbar{position:fixed;top:0;left:0;right:0;height:56px;background:#065f46;color:white;display:flex;align-items:center;padding:0 16px;z-index:9999}
.navbar-title{font-size:18px;font-weight:bold;margin-left:12px}
.hamburger{background:none;border:none;color:white;font-size:24px;cursor:pointer;padding:4px 10px}
.drawer{position:fixed;top:0;left:-280px;width:280px;height:100vh;background:#064e3b;color:white;transition:left .3s;z-index:10000;padding-top:20px;overflow-y:auto}
.drawer.open{left:0}
.drawer-header{padding:16px 20px;font-size:18px;font-weight:bold;border-bottom:1px solid #374151;display:flex;justify-content:space-between;align-items:center}
.drawer-close{background:none;border:none;color:white;font-size:24px;cursor:pointer}
.drawer a{display:block;padding:14px 20px;color:white;text-decoration:none;border-bottom:1px solid #065f46;font-size:15px}
.drawer a:hover{background:#065f46}
.drawer-section{padding:12px 20px 6px;font-size:12px;font-weight:bold;color:#6ee7b7;letter-spacing:1px;text-transform:uppercase;background:#022c22}
.drawer-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.5);z-index:9998;display:none}
.drawer-overlay.show{display:block}
.page-content{padding-top:70px}
</style>
<div class="navbar">
<button class="hamburger" onclick="toggleDrawer()">☰</button>
<span class="navbar-title">Shopify Warehouse</span>
</div>
<div class="drawer-overlay" id="drawerOverlay" onclick="toggleDrawer()"></div>
<div class="drawer" id="drawer">
<div class="drawer-header"><span>📧 Menu</span><button class="drawer-close" onclick="toggleDrawer()">×</button></div>
<div class="drawer-section">🛍️ Shopify</div>
<a href="/shopify" onclick="closeDrawer()">🏭 Shopify Warehouse</a>
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

def _page(title, body):
    return f'<!DOCTYPE html><html><head><title>{title}</title><meta name="viewport" content="width=device-width,initial-scale=1">{_navbar()}</head><body style="margin:0;font-family:Arial"><div class="page-content">{body}</div></body></html>'

# ==========================================
# PAGE
# ==========================================
@shopify_bp.route('/shopify')
def shopify_page():
    if 'user_id' not in session: return redirect('/login')
    body = '''<div style="max-width:900px;margin:20px auto;padding:20px">
<div style="background:linear-gradient(135deg,#065f46,#10b981);color:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h1 style="margin:0">🏭 Shopify Warehouse</h1>
<p style="margin:4px 0 0 0;font-size:14px;opacity:0.9">500 fresh Shopify domains daily from Leadita</p>
</div>
<div style="background:white;padding:20px;border-radius:10px;margin-bottom:20px">
<h3 style="margin-top:0">📥 Ingest</h3>
<div id="stats" style="background:#f3f4f6;padding:12px;border-radius:6px;margin:10px 0;font-size:13px">Loading…</div>
<button onclick="ingestNow()" style="background:#7c3aed;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;width:100%;margin-bottom:10px">📥 Ingest Today's Batch</button>
<div style="display:flex;gap:8px">
<input type="number" id="pullCount" value="500" min="1" max="5000" style="flex:1;padding:10px;border:1px solid #ddd;border-radius:6px;box-sizing:border-box">
<button onclick="pullFromWarehouse()" style="flex:2;background:#0d9488;color:white;padding:12px 24px;border:none;border-radius:8px;cursor:pointer;font-weight:bold">📧 Send to Shopify Finder</button>
</div>
<button onclick="resetWarehouse()" style="background:#6b7280;color:white;padding:8px 14px;border:none;border-radius:6px;cursor:pointer;font-size:12px;margin-top:8px">🔄 Reset pulled rows</button>
<div id="ingestStatus" style="margin-top:10px"></div>
<div id="pullStatus" style="margin-top:10px"></div>
</div>
<div style="background:white;padding:20px;border-radius:10px">
<h3 style="margin-top:0">📋 Recent Domains</h3>
<div id="recent" style="font-size:13px">Loading…</div>
</div>
</div>
<script>
async function loadStats(){
  try{
    const r = await fetch('/shopify/warehouse'); const d = await r.json();
    let rows = '';
    (d.daily_last_14||[]).slice(0,5).forEach(x => { rows += '<div>'+x.date+': <b>+'+x.count+'</b></div>'; });
    document.getElementById('stats').innerHTML = '<div><b>Total:</b> '+d.total+' | <b>Pending:</b> '+d.pending+' | <b>Processing:</b> '+d.processing+'</div><div style="margin-top:6px;color:#666">Last 5 days:</div>'+rows;
  }catch(e){ document.getElementById('stats').textContent = 'Error'; }
}
async function loadRecent(){
  try{
    const r = await fetch('/shopify/warehouse/recent'); const d = await r.json();
    const c = document.getElementById('recent');
    if(!d.domains || !d.domains.length){ c.innerHTML = '<p style="color:#666">Empty.</p>'; return; }
    let h = '';
    d.domains.forEach(x => { h += '<div style="padding:6px 0;border-bottom:1px solid #eee"><a href="https://'+x.domain+'" target="_blank" style="color:#3b82f6">'+x.domain+'</a> <span style="color:#888;font-size:12px">'+x.source+'</span></div>'; });
    c.innerHTML = h;
  }catch(e){}
}
async function ingestNow(){
  const s = document.getElementById('ingestStatus');
  s.innerHTML = '<p style="color:#666">⏳ Ingesting…</p>';
  try{
    const r = await fetch('/shopify/ingest', {method:'POST'});
    const d = await r.json();
    if(d.status === 'ok'){ s.innerHTML = '<div style="color:#166534;background:#f0fdf4;padding:10px;border-radius:5px"><b>✅ +'+d.new+' new</b> (skipped '+d.duplicates_skipped+')</div>'; loadStats(); loadRecent(); }
    else { s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">Error: '+(d.error||'Unknown')+'</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">'+e.message+'</div>'; }
}
async function pullFromWarehouse(){
  const s = document.getElementById('pullStatus');
  const n = parseInt(document.getElementById('pullCount').value) || 500;
  s.innerHTML = '<p style="color:#666">⏳ Pulling…</p>';
  try{
    const r = await fetch('/shopify/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({count:n})});
    const d = await r.json();
    if(d.success && d.pulled > 0){ sessionStorage.setItem('shopify_pending_domains', d.domains.join('\\n')); window.location.href='/'; }
    else { s.innerHTML = '<div style="color:#721c24;background:#f8d7da;padding:10px;border-radius:5px">No pending rows</div>'; }
  }catch(e){ s.innerHTML = '<div style="color:red">'+e.message+'</div>'; }
}
async function resetWarehouse(){ if(!confirm('Reset pulled rows?')) return; const r = await fetch('/shopify/warehouse/reset',{method:'POST'}); const d = await r.json(); if(d.success) { alert('✅ Reset '+d.reset); loadStats(); } }
window.onload = function(){ loadStats(); loadRecent(); };
</script>'''
    return _page("Shopify Warehouse", body)

# ==========================================
# API
# ==========================================
@shopify_bp.route('/shopify/ingest', methods=['GET','POST'])
def shopify_ingest():
    header_secret = request.headers.get('X-Cron-Secret', '')
    cron_secret = os.environ.get('CRON_SECRET', '')
    valid_cron = bool(cron_secret) and header_secret == cron_secret
    valid_user = ('user_id' in session) and (header_secret == 'MANUAL_FROM_UI' or (request.method == 'POST' and not header_secret))
    if not (valid_cron or valid_user):
        return jsonify({'status': 'error', 'error': 'forbidden'}), 403
    if valid_user and not valid_cron:
        result = _run_ingest()
        return jsonify(result), (200 if result.get('status') == 'ok' else 500)
    def _bg():
        try: print(f"🕒 [shopify cron] {_run_ingest()}")
        except Exception as e: print(f"🕒 [shopify cron] error: {e}")
    threading.Thread(target=_bg, daemon=True).start()
    return jsonify({'status': 'accepted'}), 202

@shopify_bp.route('/shopify/warehouse')
def shopify_warehouse():
    if 'user_id' not in session: return jsonify({'error':'auth'}), 401
    conn = sh_get_db()
    if not conn: return jsonify({'error':'db'}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM shopify_warehouse"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM shopify_warehouse WHERE status='pending'"); pending = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM shopify_warehouse WHERE status='processing'"); processing = cur.fetchone()[0]
        cur.execute("SELECT DATE(created_at) d, COUNT(*) c FROM shopify_warehouse GROUP BY DATE(created_at) ORDER BY DATE(created_at) DESC LIMIT 14")
        daily = [{'date':str(r[0]),'count':r[1]} for r in cur.fetchall()]
        cur.close()
        return jsonify({'total':total,'pending':pending,'processing':processing,'daily_last_14':daily})
    except Exception as e: return jsonify({'error':str(e)[:200]}), 500
    finally: sh_release(conn)

@shopify_bp.route('/shopify/warehouse/recent')
def shopify_recent():
    if 'user_id' not in session: return jsonify({'domains':[]}), 401
    conn = sh_get_db()
    if not conn: return jsonify({'domains':[]})
    try:
        cur = conn.cursor()
        cur.execute("SELECT domain, source, created_at FROM shopify_warehouse ORDER BY created_at DESC LIMIT 20")
        rows = cur.fetchall(); cur.close()
        return jsonify({'domains':[{'domain':r[0],'source':r[1] or '','created_at':str(r[2])[:16]} for r in rows]})
    except: return jsonify({'domains':[]})
    finally: sh_release(conn)

@shopify_bp.route('/shopify/request', methods=['POST'])
def shopify_request():
    if 'user_id' not in session: return jsonify({'success':False,'error':'auth'}), 401
    n = int((request.get_json(silent=True) or {}).get('count', 500)); n = max(1, min(n, 5000))
    conn = sh_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("""UPDATE shopify_warehouse SET status='processing'
            WHERE id IN (SELECT id FROM shopify_warehouse WHERE status='pending'
            ORDER BY created_at DESC LIMIT %s) RETURNING domain""", (n,))
        rows = cur.fetchall(); conn.commit(); cur.close()
        return jsonify({'success':True, 'pulled': len(rows), 'domains': [r[0] for r in rows]})
    except Exception as e: return jsonify({'success':False,'error':str(e)[:200]})
    finally: sh_release(conn)

@shopify_bp.route('/shopify/warehouse/reset', methods=['POST'])
def shopify_reset():
    if 'user_id' not in session: return jsonify({'success':False}), 401
    conn = sh_get_db()
    if not conn: return jsonify({'success':False})
    try:
        cur = conn.cursor()
        cur.execute("UPDATE shopify_warehouse SET status='pending' WHERE status='processing'")
        n = cur.rowcount; conn.commit(); cur.close()
        return jsonify({'success':True,'reset':n})
    except: return jsonify({'success':False})
    finally: sh_release(conn)

def attach(app):
    sh_init_db()
    app.register_blueprint(shopify_bp)
    print("✅ shopify_routes attached")
