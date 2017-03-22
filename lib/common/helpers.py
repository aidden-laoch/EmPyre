"""

Misc. helper functions used in EmPyre.

Includes the Python functions that generate the
randomized stagers.

"""

import re, string, base64, binascii, sys, os, socket, MySQLdb, iptools
from time import localtime, strftime
from Crypto.Random import random


###############################################################
#
# Validation methods
#
###############################################################

def validate_hostname(hostname):
    """
    Tries to validate a hostname.
    """
    if len(hostname) > 255:
        return False
    if hostname[-1:] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def validate_ip(IP):
    """
    Uses iptools to validate an IP.
    """
    return iptools.ipv4.validate_ip(IP)

def generate_ip_list(s):
    """
    Takes a comma separated list of IP/range/CIDR addresses and
    generates an IP range list.
    """

    # strip newlines and make everything comma separated
    s = ",".join(s.splitlines())
    # strip out spaces
    s = ",".join(s.split(" "))

    ranges = ""
    if s and s != "":
        parts = s.split(",")

        for part in parts:
            p = part.split("-")
            if len(p) == 2:
                if iptools.ipv4.validate_ip(p[0]) and iptools.ipv4.validate_ip(p[1]):
                    ranges += "('"+str(p[0])+"', '"+str(p[1])+"'),"
            else:
                if "/" in part and iptools.ipv4.validate_cidr(part):
                    ranges += "'"+str(p[0])+"',"
                elif iptools.ipv4.validate_ip(part):
                    ranges += "'"+str(p[0])+"',"

        if ranges != "":
            return eval("iptools.IpRangeList("+ranges+")")
        else:
            return None

    else:
        return None


####################################################################################
#
# Randomizers/obfuscators
#
####################################################################################

def random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """
    if length == -1:
        length = random.randrange(6, 16)
    random_string = ''.join(random.choice(charset) for x in range(length))
    return random_string

def randomize_capitalization(data):
    """
    Randomize the capitalization of a string.
    """
    return "".join(random.choice([k.upper(), k]) for k in data)

def chunks(l, n):
    """
    Generator to split a string l into chunks of size n.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


####################################################################################
#
# Specific Python helpers
#
####################################################################################

def strip_python_comments(data):
    """
    Strip block comments, line comments, empty lines, verbose statements,
    and debug statements from a Python source file.
    """
    # TODO: implement pyminifier functionality

    lines = data.split("\n")
    strippedLines = [line for line in lines if ((not line.strip().startswith("#")) and (line.strip() != ''))]
    return "\n".join(strippedLines)


###############################################################
#
# Miscellaneous methods (formatting, sorting, etc.)
#
###############################################################

def get_config(fields):
    """
    Helper to pull common database config information outside of the
    normal menu execution.

    Fields should be comma separated.
        i.e. 'version,install_path'
    """

    #conn = sqlite3.connect('./data/empyre.db', check_same_thread=False)
    conn = MySQLdb.connect(host='localhost',user='root',passwd='4zballs',db='empyre')
    conn.isolation_level = None

    cur = conn.cursor()
    cur.execute("SELECT %s FROM config" %(fields))
    results = cur.fetchone()
    cur.close()
    conn.close()

    return results

def get_datetime():
    """
    Return the current date/time
    """
    return strftime("%Y-%m-%d %H:%M:%S", localtime())

def get_file_datetime():
    """
    Return the current date/time in a format workable for a file name.
    """
    return strftime("%Y-%m-%d_%H-%M-%S", localtime())

def get_file_size(file):
    """
    Returns a string with the file size and highest rating.
    """
    byte_size = sys.getsizeof(file)
    kb_size = byte_size / 1024
    if kb_size == 0:
        byte_size = "%s Bytes" % (byte_size)
        return byte_size
    mb_size = kb_size / 1024
    if mb_size == 0:
        kb_size = "%s KB" % (kb_size)
        return kb_size
    gb_size = mb_size / 1024 % (mb_size)
    if gb_size == 0:
        mb_size = "%s MB" %(mb_size)
        return mb_size
    return "%s GB" % (gb_size)


def lhost():
    """
    Return the local IP.

    """

    if os.name != "nt":
        import fcntl
        import struct

        def get_interface_ip(ifname):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                return socket.inet_ntoa(fcntl.ioctl(
                        s.fileno(),
                        0x8915,  # SIOCGIFADDR
                        struct.pack('256s', ifname[:15])
                    )[20:24])
            except IOError:
                return ""

    ip = ""
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        pass
    except:
        print "Unexpected error:", sys.exc_info()[0]
        return ip

    if (ip == "" or ip.startswith("127.")) and os.name != "nt":
        interfaces = ["eth0", "eth1", "eth2", "wlan0", "wlan1", "wifi0", "ath0", "ath1", "ppp0"]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                if ip != "":
                    break
            except:
                print "Unexpected error:", sys.exc_info()[0]
                pass
    return ip

def color(string, color=None):
    """
    Change text color for the Linux terminal.
    """

    attr = []
    # bold
    attr.append('1')

    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "yellow":
            attr.append('33')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

def unique(seq, idfun=None):
    # uniquify a list, order preserving
    # from http://www.peterbe.com/plog/uniqifiers-benchmark
    if idfun is None:
        def idfun(x): return x
    seen = {}
    result = []
    for item in seq:
        marker = idfun(item)
        # in old Python versions:
        # if seen.has_key(marker)
        # but in new ones:
        if marker in seen:
            continue
        seen[marker] = 1
        result.append(item)
    return result

def uniquify_tuples(tuples):
    # uniquify mimikatz tuples based on the password
    # cred format- (credType, domain, username, password, hostname, sid)
    seen = set()
    return [item for item in tuples if "%s%s%s%s" % (item[0], item[1], item[2], item[3]) not in seen and not seen.add("%s%s%s%s" % (item[0], item[1], item[2], item[3]))]

def decode_base64(data):
    """
    Try to decode a base64 string.
    From http://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding
    """
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'=' * missing_padding

    try:
        result = base64.decodestring(data)
        return result
    except binascii.Error:
        # if there's a decoding error, just return the data
        return data

def encode_base64(data):
    """
    Decode data as a base64 string.
    """
    return base64.encodestring(data).strip()

def complete_path(text, line, arg=False):
    """
    Helper for tab-completion of file paths.
    """
    # stolen from dataq at
    #   http://stackoverflow.com/questions/16826172/filename-tab-completion-in-cmd-cmd-of-python

    if arg:
        # if we have "command something path"
        argData = line.split()[1:]
    else:
        # if we have "command path"
        argData = line.split()[0:]

    if not argData or len(argData) == 1:
        completions = os.listdir('./')
    else:
        dir, part, base = argData[-1].rpartition('/')
        if part == '':
            dir = './'
        elif dir == '':
            dir = '/'

        completions = []
        for f in os.listdir(dir):
            if f.startswith(base):
                if os.path.isfile(os.path.join(dir, f)):
                    completions.append(f)
                else:
                    completions.append(f+'/')

    return completions
