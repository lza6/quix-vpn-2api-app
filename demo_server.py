"""QuixVPN WireGuard 节点池 demo 服务
- GET  /            demo 面板
- GET  /api/nodes   节点清单 + 最近验证结果
- POST /api/verify  逐节点起真隧道验证出口 IP（调 quixwg.exe）
- POST /api/harvest 匿名领取新凭据并刷新 wg_profiles_ok.json
- GET  /api/export  导出可用节点 conf（供网关代理池接入）
"""
import json, subprocess, threading, time, sys, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = r'C:\Users\Administrator.DESKTOP-EGNE9ND\Desktop\quix_analysis'
WGTEST = r'D:\quix-wgtest'
STATE = {'nodes': [], 'last_verify': None, 'verifying': False}

def load_state():
    try:
        profs = json.load(open(os.path.join(BASE, 'wg_profiles_ok.json')))
        hs = {}
        try:
            hs = {r['host']: r for r in json.load(open(os.path.join(BASE, 'wg_handshake_results.json')))}
        except Exception:
            pass
        STATE['nodes'] = [{'host': p['host'], 'endpoint': p['endpoint'], 'cc': p.get('cc', ''),
                           'profile_id': p.get('profile_id', '')} for p in profs]
    except Exception as e:
        print('load err', e)

def run_verify():
    STATE['verifying'] = True
    try:
        out = subprocess.run([os.path.join(WGTEST, 'quixwg.exe'), os.path.join(WGTEST, 'wg_profiles_ok.json')],
                             capture_output=True, text=True, timeout=600)
        results = [json.loads(l) for l in out.stdout.splitlines() if l.strip().startswith('{')]
        ok = [r for r in results if r.get('valid')]
        STATE['last_verify'] = {'at': time.strftime('%Y-%m-%d %H:%M:%S'), 'results': results,
                                'ok': len(ok), 'total': len(results)}
    except Exception as e:
        STATE['last_verify'] = {'error': str(e)}
    finally:
        STATE['verifying'] = False

PAGE = '''<!doctype html><html lang="zh"><head><meta charset="utf-8"><title>QuixVPN WG 节点池 Demo</title>
<style>body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0;padding:24px}
h1{font-size:20px}.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
button{background:#238636;color:#fff;border:0;border-radius:6px;padding:8px 16px;cursor:pointer;margin-right:8px}
button:disabled{opacity:.5}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #21262d}
.ok{color:#3fb950}.bad{color:#f85149}.mut{color:#8b949e}pre{background:#0d1117;padding:8px;border-radius:6px;overflow:auto;font-size:12px}</style></head>
<body><h1>🔓 QuixVPN WireGuard 节点池 — 第一轮压测 Demo</h1>
<div class="card">接口：getCredentialsV3（AWS API Gateway，x-api-key 匿名领取）· 协议 WireGuard/AmneziaWG · 数据面验证 = userspace netstack 真隧道拉 api.ipify.org
<div style="margin-top:12px"><button onclick="verify(this)" id="vb">▶ 真隧道验证全部节点</button><button onclick="location.reload()">刷新</button>
<span id="st" class="mut"></span></div></div>
<div class="card"><table id="t"><thead><tr><th>节点</th><th>Endpoint</th><th>出口 IP</th><th>RTT</th><th>状态</th></tr></thead><tbody></tbody></table></div>
<div class="card"><b>最近验证摘要</b><pre id="sum">尚未验证</pre></div>
<script>
async function load(){const r=await(await fetch('/api/state')).json();render(r)}
function render(s){
 const res={};(s.last_verify&&s.last_verify.results||[]).forEach(r=>res[r.host]=r);
 document.querySelector('#t tbody').innerHTML=(s.nodes||[]).map(n=>{const r=res[n.host]||{};
  const ok=r.valid;return `<tr><td>${n.host}</td><td class="mut">${n.endpoint}</td>
  <td>${(r.egress_ip||'-').replace(/\\{|\}|ip|:|"/g,'').trim()||'-'}</td>
  <td>${r.rtt_ms?r.rtt_ms+'ms':'-'}</td>
  <td class="${ok?'ok':(r.error?'bad':'mut')}">${ok?'✅ 已验证':(r.error?('❌ '+(r.error||'').slice(0,40)):'待验证')}</td></tr>`}).join('');
 document.getElementById('sum').textContent=s.last_verify?JSON.stringify({at:s.last_verify.at,ok:s.last_verify.ok+'/'+s.last_verify.total}):'尚未验证';
 document.getElementById('vb').disabled=s.verifying;
 document.getElementById('st').textContent=s.verifying?'验证中…（每节点约15s）':'';
}
async function verify(b){b.disabled=true;await fetch('/api/verify',{method:'POST'});poll()}
function poll(){const iv=setInterval(async()=>{const s=await(await fetch('/api/state')).json();render(s);if(!s.verifying){clearInterval(iv)}},2000)}
load();
</script></body></html>'''

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == '/':
            b = PAGE.encode(); self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        elif self.path == '/api/state':
            self._json(STATE)
        elif self.path == '/api/export':
            try:
                profs = json.load(open(os.path.join(BASE, 'wg_profiles_ok.json')))
                self._json(profs)
            except Exception as e:
                self._json({'error': str(e)}, 500)
    def do_POST(self):
        if self.path == '/api/verify':
            if STATE['verifying']:
                self._json({'status': 'already running'}); return
            threading.Thread(target=run_verify, daemon=True).start()
            self._json({'status': 'started'})
        elif self.path == '/api/harvest':
            r = subprocess.run([sys.executable, os.path.join(BASE, 'harvest_all.py')],
                               capture_output=True, text=True, timeout=300, cwd=BASE)
            load_state()
            self._json({'status': 'done', 'tail': r.stdout[-500:]})

if __name__ == '__main__':
    load_state()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8921
    print(f'demo http://127.0.0.1:{port}')
    ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
