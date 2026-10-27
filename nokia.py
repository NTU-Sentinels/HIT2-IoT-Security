#!/usr/bin/env python3
import base64, hashlib, json, os, random, sys, urllib.parse, urllib.request, http.cookiejar, ssl

BASE = "http://192.168.18.1"
USER = "admin"
PASS = "9bp53dJ3fv"

def b64(b): return base64.b64encode(b).decode()
def b64url_escape(s):
    return s.replace('+','-').replace('/','_').replace('=','.')
def sha_b64(v): return b64(hashlib.sha256(v.encode()).digest())
def sha_url(v, nonce): return b64url_escape(sha_b64(v + ":" + nonce))

class Nokia:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.op.addheaders = [
            ('User-Agent','Mozilla/5.0'),
            ('Accept','application/json, text/plain, */*'),
        ]
        self.sid = None
        self.token = None
        self.last = None

    def _do(self, req):
        try:
            r = self.op.open(req, timeout=20)
            body = r.read()
            return r.status, dict(r.headers), body
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def get(self, path):
        return self._do(urllib.request.Request(BASE + path))

    def post(self, path, data, ctype='application/x-www-form-urlencoded'):
        if isinstance(data, str): data = data.encode()
        req = urllib.request.Request(BASE + path, data=data, method='POST')
        req.add_header('Content-Type', ctype)
        return self._do(req)

    def login(self):
        st, hd, body = self.get('/login_web_app.cgi?nonce')
        j = json.loads(body)
        nonce, rk = j['nonce'], j['randomKey']
        l = sha_b64(USER + ":" + PASS)
        resp = sha_url(l, nonce)
        userhash = sha_url(USER, nonce)
        rkhash = sha_url(rk, nonce)
        enckey = b64url_escape(b64(os.urandom(16)))
        enciv = b64url_escape(b64(os.urandom(16)))
        body = ("userhash=%s&RandomKeyhash=%s&response=%s&nonce=%s&enckey=%s&enciv=%s&nohash=0" %
                (userhash, rkhash, resp, b64url_escape(nonce), enckey, enciv))
        st, hd, rb = self.post('/login_web_app.cgi', body)
        try: j = json.loads(rb)
        except Exception: j = {'raw': rb.decode('latin1')}
        self.last = (st, hd, j)
        if isinstance(j, dict) and j.get('result') == 0:
            self.sid = j.get('sid'); self.token = j.get('token')
            return True
        return False

    def cookies(self):
        return {c.name: c.value for c in self.cj}

    def cmd(self, cgi, payload, extra_cookie=None):
        # payload must already be urlencoded form body (no csrf needed for GET-style query?)
        tok = self.token or ''
        if 'csrf_token=' not in payload:
            payload += '&csrf_token=' + urllib.parse.quote(tok)
        return self.post('/' + cgi, payload)

if __name__ == '__main__':
    n = Nokia()
    ok = n.login()
    print('login ok=', ok)
    print('cookies=', n.cookies())
    print('last=', n.last[0], n.last[2] if isinstance(n.last[2], dict) else n.last[2])
