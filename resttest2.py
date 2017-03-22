#!/usr/bin/python

import commands
import sys
import argparse


import argparse, sys, argparse, logging, json, string, os, re, time, signal, copy, base64, MySQLdb
from flask import Flask, request, jsonify, make_response, abort
from time import localtime, strftime
from OpenSSL import SSL
from Crypto.Random import random

# Empyre imports
from lib.common import empyre
from lib.common import helpers



def c(var):
	cout = commands.getstatusoutput(var)
	return cout


#c = commands.getstatusoutput()
u = sys.argv[1]
p = sys.argv[2]
r = '''curl --insecure -i -H "Content-Type: application/json" https://localhost:1337/api/admin/login -X POST -d \'{"username":"%s", "password":"%s"}\'''' % (u,p)
print r

o = commands.getstatusoutput('%s' % r)
print o


def getRequest(var):
	url = mainRequest()
	c('%s=%s' % (var,t)

def mainRequest(conText):
	r = 'http://%s:%s/api/%s' % (ip,rport,conText)
	return r






####################################################################
#
# The EmPyre RESTful API.
# 
# Adapted from http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
#   example code at https://gist.github.com/miguelgrinberg/5614326
#
#    Verb     URI                                            Action
#    ----     ---                                            ------
#    GET      http://localhost:1337/api/version              return the current EmPyre version
#    
#    GET      http://localhost:1337/api/config               return the current default config
#
#    GET      http://localhost:1337/api/stagers              return all current stagers
#    GET      http://localhost:1337/api/stagers/X            return the stager with name X
#    POST     http://localhost:1337/api/stagers              generate a stager given supplied options (need to implement)
#
#    GET      http://localhost:1337/api/modules                     return all current modules
#    GET      http://localhost:1337/api/modules/<name>              return the module with the specified name
#    POST     http://localhost:1337/api/modules/<name>              execute the given module with the specified options
#    POST     http://localhost:1337/api/modules/search              searches modulesfor a passed term
#    POST     http://localhost:1337/api/modules/search/modulename   searches module names for a specific term
#    POST     http://localhost:1337/api/modules/search/description  searches module descriptions for a specific term
#    POST     http://localhost:1337/api/modules/search/description  searches module comments for a specific term
#    POST     http://localhost:1337/api/modules/search/author       searches module authors for a specific term
#
#    GET      http://localhost:1337/api/listeners            return all current listeners
#    GET      http://localhost:1337/api/listeners/Y          return the listener with id Y
#    GET      http://localhost:1337/api/listeners/options    return all listener options
#    POST     http://localhost:1337/api/listeners            starts a new listener with the specified options
#    DELETE   http://localhost:1337/api/listeners/Y          kills listener Y
#
#    GET      http://localhost:1337/api/agents               return all current agents
#    GET      http://localhost:1337/api/agents/stale         return all stale agents
#    DELETE   http://localhost:1337/api/agents/stale         removes stale agents from the database
#    DELETE   http://localhost:1337/api/agents/Y             removes agent Y from the database
#    GET      http://localhost:1337/api/agents/Y             return the agent with name Y
#    GET      http://localhost:1337/api/agents/Y/results     return tasking results for the agent with name Y
#    DELETE   http://localhost:1337/api/agents/Y/results     deletes the result buffer for agent Y
#    POST     http://localhost:1337/api/agents/Y/shell       task agent Y to execute a shell command
#    POST     http://localhost:1337/api/agents/Y/rename      rename agent Y
#    GET/POST http://localhost:1337/api/agents/Y/clear       clears the result buffer for agent Y
#    GET/POST http://localhost:1337/api/agents/Y/kill        kill agent Y
#
#    GET      http://localhost:1337/api/reporting            return all logged events
#    GET      http://localhost:1337/api/reporting/agent/X    return all logged events for the given agent name X
#    GET      http://localhost:1337/api/reporting/type/Y     return all logged events of type Y (checkin, task, result, rename)
#    GET      http://localhost:1337/api/reporting/msg/Z      return all logged events matching message Z, wildcards accepted
#
#    GET      http://localhost:1337/api/creds                return stored credentials
#
#    GET      http://localhost:1337/api/admin/login          retrieve the API token given the correct username and password
#    GET      http://localhost:1337/api/admin/permanenttoken retrieve the permanent API token, generating/storing one if it doesn't already exist
#    GET      http://localhost:1337/api/admin/shutdown       shutdown the RESTful API
#    GET      http://localhost:1337/api/admin/restart        restart the RESTful API
#    
####################################################################




if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='store_true', help='Display current Empire||EmPyre version.')
    parser.add_argument('--restport', nargs='?', help='Port to connect to TeamServer.')
    parser.add_argument('--teamserver', nargs='?', help='Run EmPyre Connect to an Empire||EmPyre TeamServer.')
    parser.add_argument('--username', nargs='?', help='Start the RESTful API with the specified username instead of pulling from emypre.db')
    parser.add_argument('--password', nargs='?', help='Start the RESTful API with the specified password instead of pulling from emypre.db')

    args = parser.parse_args()

    if not args.restport:
        args.restport = '1337'

    if args.version:
        print emypre.VERSION

    else:
        # normal execution
        main = teampyre.MainMenu(args=args)
        main.cmdloop()


    sys.exit()

