#!/usr/bin/python

import commands
import sys

n = commands.getstatusoutput('touch %s.patched' % sys.argv[1])

try:
    a = open('./totala', 'r')
except:
    print 'failed to open totala'
try:
    b = open('./totalb', 'r')
except:
    print 'failed to open totalb'
try:
    f = open('%s' % sys.argv[1], 'r')
except:
    print 'failed to open target'
try:
    of = open('%s.patched' % sys.argv[1], 'w')
except:
    print 'failed to open output file'

la = []
lb = []
lt = []
lp = []

for i in a:
    la.append(i)

for i in b:
    lb.append(i)

for i in f:
    lt.append(i)

c = 0
for i in lt:
    co = 0
    lp.append(i)
    for ia in la:
        if i == ia:
            print 'this is i %s' % i
            print 'this is ia %s' % ia
            print 'this is lb[c0] %s' % lb[co]
            print 'this is c %s and co %s' % (c,co)
            lp[c] = lb[co]
        else:
            #print "this line is good: %s" % i
            co = co + 1
    c = c + 1

print '''
################################################
#   Changing 'agents.py' to look like this!:   #
################################################
'''

for i in lp:
    print i
    of.write(i)

a.close()
b.close()
f.close()
of.close()
