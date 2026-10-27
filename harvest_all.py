"""Bulk harvest WireGuard/AmneziaWG credentials for all unique QuixVPN hosts."""
import json, time, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from fetch_quix import fetch

def host_cc(h):
    sl = json.load(open(r'C:\Users\Administrator.DESKTOP-EGNE9ND\Desktop\quix_analysis\serverlist_live.json'))
    m = {s['hostName']: s['country'] for s in sl['data']['servers']}
    return m.get(h, 'US')

def harvest(host, proto):
    try:
        r = fetch(host, 'US' if host == 'app.quix-vpn.com' else host.split('.')[0].upper().replace('APP','US'), proto)
        return (host, proto, r)
    except Exception as e:
        return (host, proto, {'error': str(e)[:200]})

if __name__ == '__main__':
    sl = json.load(open(r'C:\Users\Administrator.DESKTOP-EGNE9ND\Desktop\quix_analysis\serverlist_live.json'))
    hosts = []
    seen = set()
    for s in sl['data']['servers']:
        h = s['hostName']
        if h not in seen:
            seen.add(h)
            hosts.append((h, s['country']))
    print(f'{len(hosts)} unique hosts')
    out = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(harvest, h, p) for h, cc in hosts for p in ('wg',)]
        for f in as_completed(futs):
            host, proto, r = f.result()
            if 'error' in r:
                print(f'{host:28s} {proto}  ERR {r["error"][:80]}')
            else:
                cfg = r.get('data', r)
                out.append({'host': host, 'proto': proto, 'resp': r})
                print(f'{host:28s} {proto}  OK')
            time.sleep(0.1)
    json.dump(out, open(r'C:\Users\Administrator.DESKTOP-EGNE9ND\Desktop\quix_analysis\harvest_all.json', 'w'), indent=1)
    print(f'\nsaved {len(out)} profiles')
