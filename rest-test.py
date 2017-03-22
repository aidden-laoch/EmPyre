#!/usr/bin/python

import commands
import sys

#c = commands.getstatusoutput()
u = sys.argv[1]
p = sys.argv[2]
r = '''curl --insecure -i -H "Content-Type: application/json" https://localhost:1337/api/admin/login -X POST -d \'{"username":"%s", "password":"%s"}\'''' % (u,p)
print r

t = sys.argv[3]


o = commands.getstatusoutput('%s' % r)
print o
