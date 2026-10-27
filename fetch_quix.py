import json, urllib.request, ssl, sys
API="https://56rah0pl8g.execute-api.us-east-1.amazonaws.com/getCredentialsV3"
KEY="5Cd5HqWFISLxzFRp4bPEw78MM2pr7xPp"
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
def fetch(host, cc, proto="wg"):
    body=json.dumps({"os":"a","premium_status":"f","email":"anonymous","host_name":host,"country_code":cc,"protocol":proto}).encode()
    req=urllib.request.Request(API, data=body, headers={"Content-Type":"application/json","x-api-key":KEY,"Authorization":""})
    with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
        return json.loads(r.read())
if __name__=="__main__":
    host, cc = sys.argv[1], sys.argv[2]
    proto = sys.argv[3] if len(sys.argv)>3 else "wg"
    print(json.dumps(fetch(host,cc,proto), indent=2))
