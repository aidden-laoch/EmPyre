#!/usr/bin/python

#import sqlite
import redis
import os
from cmd2 import Cmd, make_option, options, Cmd2TestCase
import sys, unittest, optparse
import time
import commands

r = redis.Redis(
        host='localhost',
        port=6379,)

class CmdLineApp(Cmd):
	multilineComands = ['orate']
	Cmd.shortcuts.update({'&': 'speak'})
	maxrepeats = 3
	Cmd.settable.append('maxrepeats')
	prompt = 'C2# '
	state = 'main'
	teamserver = ''
	rport = ''
	default_to_shell = True

	@options([make_option('-p', '--piglatin', action="store_true", help="atinLay"),
		make_option('-s', '--shout', action="store_true", help="NOOB EMULATIONS MODE"),
		make_option('-r', '--repeat', type="int", help="output [n] times")
		])

	def do_speak(self, arg, opts=None):
		""" Repeats what you tell it to. """
		arg = ''.join(arg)
		if opts.piglatin:
			arg = '%s%say' % (arg[1:], arg[0])
		if opts.shout:
			arg = arg.upper()
		if opts.conn:
			print 'opt.con'
		repetitions = opts.repeat or 1
		for i in range(min(repetitions, self.maxrepeats)):
			self.stdout.write(arg)
			self.stdout.write('\n')
			# self.stdout.write is betther then print, begause Cmd can be
			# initialized with a non-standard output destination.

#select an agent to interact with

	@options([make_option('-s', '--set', action='store', dest='agent', type='string', help="Specify agent interact with")
                ])

        def do_setagent(self, arg, opts=None):
                """ Set Agent to interact with """
                arg = ''.join(arg)
                a = opts.agent
                if a:
            self.state = 'agents/%s' % a
			self.prompt = 'agents/%s#: ' % a
			self.agent = a
			self.stdout.write(self.agent)
			self.stdout.write('\n')
                else:
			self.stdout.write('Specify an agent to interact with -s \n')
			while True:
				host = self.teamserver
        		port = self.rport
        		key = self.key
        		state = self.state
        		oagents = commands.getstatusoutput('curl --insecure -i https://%s:%s/api/%s?token=%s' % (host, port, state, key))
        		print oagents[1]

		#os.system('pyshell %s' % self.agent )

#list agents to interact with
        def do_listagents(self, arg, opts=None):
        	host = self.teamserver
        	port = self.rport
        	key = self.key
        	oagents = commands.getstatusoutput('curl --insecure -i https://%s:%s/api/agents?token=%s' % (host, port, key))
        	print oagents[1]


#watch agents for signs of activity
        def do_watchagents(self, arg, opts=None):
                arg = ''.join(arg)
                while True:
                	os.system('clear')
                	host = self.teamserver
                	port = self.rport
                	key = self.key
                	oagents = commands.getstatusoutput('curl --insecure -i https://%s:%s/api/agents?token=%s' % (host, port, key))
                	print oagents[1]
                	time.sleep(5)

	@options([make_option('-s', '--set', action='store', dest='teamserver', type='string', help="Specify teamserver interact with")
		       ])

    	def do_teamserver(self, arg, opts=None):
    		""" Set teamserver to interact with """
                arg = ''.join(arg)
                t = opts.teamserver
                if t:
			self.teamserver = t
			self.stdout.write(self.teamserver)
			self.stdout.write('\n')
                else:
			self.stdout.write('Specify a server to interact with -s \n')
    		teamserver = self.teamserver

 	@options([make_option('-s', '--set', action='store', dest='rport', type='string', help="Specify teamserver port interact with")
 		                ])

    	def do_rport(self, arg, opts=None):
    		""" Set teamserver port to interact with """
                arg = ''.join(arg)
                r = opts.rport
                if r:
			self.rport = r
			self.stdout.write(self.rport)
			self.stdout.write('\n')
                else:
			self.stdout.write('Specify a port to interact with -s \n')
    		rport = self.rport

 	@options([make_option('-s', '--set', action='store', dest='key', type='string', help="Specify teamserver key interact with")
 		                ])

    	def do_rkey(self, arg, opts=None):
    		""" Set teamserver key to interact with """
                arg = ''.join(arg)
                k = opts.key
                if k:
			self.key = k
			self.stdout.write(self.key)
			self.stdout.write('\n')
                else:
			self.stdout.write('Specify a key to interact with -s \n')
    		key = self.key

	def do_printagent(self, arg, opts=None):
		""" Shows currently selected Agent """
		print 'Agent selected'
		self.stdout.write(self.agent)
		self.stdout.write('\n')

	def do_agents(self, arg, opts=None):
		self.state = 'agents'
		self.prompt = 'agents#: '

	def do_listeners(self, arg, opts=None):
		self.state = 'listeners'
		self.prompt = 'listeners#: '

	def do_stagers(self, arg, opts=None):
		self.state = 'stagers'
		self.prompt = 'stagers#: '

	def do_back(self, arg, opts=None):
		self.state = 'main'
		self.prompt = 'C2#: '

	#do_agent = do_setagent 	# now setagent is a synonym for setagentdb
	do_say = do_speak	# now say is a synonym for speak
	do_ordate = do_speak	# another synonym, but this one takes multi-line input

class TestMyAppCase(Cmd2TestCase):
	CmdApp = CmdLineApp
	transscriptFilenName = 'exampleSessions.txt'


def main():
	os.system('clear')
	usage = 'Usage: %prog [Options] [Path to C2 DB]'
	parser = optparse.OptionParser(usage)
	#parser.add_option('-u', '--test', dest='unitests', action='store_true', default=False, help='Run unit test suite')
	#parser.add_option('-t', '--teamserver', action="store", metavar='ts', default='127.0.0.1', help='Connect to TeamPire||TeamPyre')
	#parser.add_option('-r', '--rport', action="store", metavar='rport', default='1337', help='Port for TeamPire||TeamPyre')
	#parser.add_option('-k', '--key', action="store", metavar='ak', help='API Key for TeamPire||TeamPyre')
	#parser.add_option('-h', '--help', action="store", metavar='h', help=usage)
	(callopts, callargs) = parser.parse_args()
	agent = ''
	state = ''
	key = ''
	teamserver = ''
	rport = ''
	#ts = callopts.teamserver
	#print ts
	#p = callopts.rport
	#print p
	# = callopts.key
	#print k

	app = CmdLineApp()
	app.cmdloop()
	
	#if callopts.unitests:
	#	sys.argv = [sys.argv[0]] # the --test argument upsets unitest.main()
	#	unittest.main()
	#else:
	#	app = CmdLineApp()
	#	app.cmdloop()

if __name__ == "__main__":
        if len(sys.argv) > 1 :
        	print 'test'
        	main()
        else:
            main()


