"""

Module handling functionality for EmPyre.

Right now, just loads up all modules from the
install path in the common config.

"""

import MySQLdb, fnmatch, os, imp
import messages
import helpers

class Modules:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu

        # pull the database connection object out of the main menu
        self.conn = self.mainMenu.conn

        self.args = args

        # module format:
        #     [ ("module/name", instance) ]
        self.modules = {}

        # pull out the code install path from the database config
        cur = self.conn.cursor()
        cur.execute("SELECT install_path FROM config")
        self.installPath = cur.fetchone()[0]
        cur.close()

        self.load_modules()

    def load_modules(self, rootPath=''):
        """
        Load modules from the install + "/lib/modules/*" path
        """

        if rootPath == '':
            rootPath = self.installPath + 'lib/modules/'

        pattern = '*.py'
        print helpers.color("[*] Loading modules from: %s" %(rootPath))
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up the template
                if filename == "template.py" or filename == "jobs-template.py":
                    continue

                # extract just the module name from the full path
                moduleName = filePath.split(rootPath)[-1][0:-3]

                if rootPath != self.installPath + 'lib/modules/':
                    moduleName = "external/%s" %(moduleName)

                # instantiate the module and save it to the internal cache
                self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])

    def reload_module(self, moduleToReload):
        """
        Reload a specific module from the install + "/lib/modules/*" path
        """

        rootPath = self.installPath + 'lib/modules/'
        pattern = '*.py'

        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up the template
                if filename == "template.py" or filename == "jobs-template.py":
                    continue

                # extract just the module name from the full path
                moduleName = filePath.split("/lib/modules/")[-1][0:-3]

                # check to make sure we've found the specific module
                if moduleName.lower() == moduleToReload.lower():
                    # instantiate the module and save it to the internal cache
                    try:
                        self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])
                    except Exception as e:
                        print helpers.color("[!] Error: Failed to reload module, not instantiate new module!")
                        print helpers.color("[!] Module Error:" + str(e), color="yellow")

    def search_modules(self, searchTerm):
        """
        Search currently loaded module names and descriptions.
        """

        print ""

        for moduleName, module in self.modules.iteritems():
            if searchTerm.lower() in moduleName.lower() or searchTerm.lower() in ''.join(module.info['Description']).lower():
                messages.display_module_search(moduleName, module)

            # for comment in module.info['Comments']:
            #     if searchTerm.lower() in comment.lower():
            #         messages.display_module_search(moduleName, module)
