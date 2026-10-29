#!/usr/bin/env python3
import sys, urllib.parse, os, time, json
HERE = os.path.dirname(os.path.abspath(__file__))   # /srv/beacon on the Pi
sys.path.insert(0, HERE)
from nokia import Nokia

B = "__BEG__"
E = "__END__"
# Session log beside the script; set RCE_LOG to put it somewhere else.
LOG = os.environ.get('RCE_LOG', os.path.join(HERE, 'logs', 'session.log'))

class RCE:
    def __init__(self):
        self.n = Nokia()
        self.login()
    def login(self):
        # nokia.py tries the configured password, then its fallback one.
        ok = self.n.login_any() if hasattr(self.n, 'login_any') else self.n.login()
        if not ok:
            raise SystemExit("LOGIN FAILED")
    def _post(self, cmd):
        wrapped = "echo %s\n%s\necho %s" % (B, cmd, E)
        inj = "\n" + wrapped + "\n"
        body = urllib.parse.urlencode({
            'wan_conlist':'2','ipaddress':'127.0.0.1','direction':'rx','status':'enable',
            'domain':'','wan_port':'WAN','waninterfacename':inj,'portstatus':'Disconnected',
            'lan_port':'null','csrf_token':self.n.token})
        st, hd, rb = self.n.post('/troubleshooting_web_app.cgi?ping', body)
        return st, rb.decode('utf-8','replace')
    def run(self, cmd, retry=True):
        st, t = self._post(cmd)
        i = t.find(B); j = t.find(E, i+1)
        if i < 0 or j < 0:
            # maybe session expired -> re-login and retry once
            if retry:
                try:
                    self.login()
                    return self.run(cmd, retry=False)
                except SystemExit:
                    pass
            return "ERR st=%s len=%d tail=%r" % (st, len(t), t[-300:])
        out = t[i+len(B):j]
        out = out[1:] if out.startswith('\n') else out
        return out.rstrip('\n')

def logcmd(cmd, out):
    try:
        d = os.path.dirname(LOG)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(LOG,'a') as f:
            f.write("\n===== CMD: %s =====\n" % cmd)
            f.write(out + "\n")
    except OSError as exc:
        # A logging problem must never abort the command run.
        sys.stderr.write("[rce] cannot write %s: %s\n" % (LOG, exc))

if __name__ == '__main__':
    r = RCE()
    cmds = sys.argv[1:]
    if not cmds:
        cmds = [l for l in sys.stdin.read().split('\n') if l.strip()]
    for c in cmds:
        out = r.run(c)
        print("### CMD:", c)
        print(out)
        print()
        logcmd(c, out)

