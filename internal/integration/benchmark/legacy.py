# Test fixture only: import legacy Agent from an independent backup directory.
import sys,os,json,time,resource
from agent import Agent
root=sys.argv[1]
assert root.startswith('/var/lib/webscan-deploy/benchmarks/')
c=json.load(open(root+'/python.json')); a=Agent(c)
out={'implementation':'python','files':10000,'platform':'native_linux_amd64'}
def measure(name,f):
 b=resource.getrusage(resource.RUSAGE_SELF); start=time.monotonic(); f(); z=resource.getrusage(resource.RUSAGE_SELF)
 out[name]={'wall_seconds':time.monotonic()-start,'cpu_seconds':z.ru_utime+z.ru_stime-b.ru_utime-b.ru_stime,'peak_rss_kib':z.ru_maxrss}
measure('baseline',lambda:a.reconcile(baseline=True,full=False))
measure('unchanged_metadata',lambda:a.reconcile(baseline=False,full=False))
for i in range(100):
 with open(root+'/sites/site-000/fixture-%05d.php'%i,'w') as f:f.write('<?php /* owned modified fixture */')
measure('detect_100_changes',lambda:a.reconcile(baseline=False,full=False))
measure('full_sha256',lambda:a.reconcile(baseline=False,full=True))
print(json.dumps(out))
