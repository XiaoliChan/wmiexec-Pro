#!/usr/bin/env python3

from __future__ import division
from __future__ import print_function

import sys
import argparse
import time
import logging

from lib.logger import Log
from lib.modules import MODULE_REGISTRY

from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL


OUTPUT_FILENAME = f"__{time.time()!s}"

class WMIEXEC:
    def __init__(self, username="", password="", domain="", hashes=None, aesKey=None, doKerberos=False, kdcHost=None, remoteHost="", options=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__remoteHost = remoteHost
        self.__options = options
        self.__logger = logging.getLogger("wmiexec-pro")

        if hashes:
            self.__lmhash, self.__nthash = hashes.split(":")

    def run(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost, remoteHost=self.__remoteHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

            # Dynamic dispatch via module registry
            for module_cls in MODULE_REGISTRY:
                if self.__options.module == module_cls.name:
                    module_cls.run(
                        iWbemLevel1Login, dcom, self.__options,
                        addr=addr,
                        username=self.__username
                    )
                    break

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger("wmiexec-pro").level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.exit(1)
        
        dcom.disconnect()

if __name__ == "__main__":
    from lib.patches import patch_impacket_wmi
    patch_impacket_wmi()

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument('-timeout', default=5, type=int, action='store', help='Set the timeout for the connection')
    parser.add_argument("-codec", default="gbk", action="store", help="Sets encoding used (codec) from the target\"s output (default "
                                                       '"gbk"). If errors are detected, run chcp.com at the target, '
                                                       "map the result with "
                                                       "https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py "
                                                       "again with -codec and the corresponding codec ")
    parser.add_argument("-com-version", action="store", metavar="MAJOR_VERSION:MINOR_VERSION",
                        help="DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7")
    subparsers = parser.add_subparsers(help="modules", dest="module")

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    # Dynamic parser registration from module registry
    for module_cls in MODULE_REGISTRY:
        module_cls.register_parser(subparsers)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logging.getLogger("impacket").disabled = True
    logger = Log(log_level=logging.DEBUG)

    if options.com_version:
        try:
            major_version, minor_version = options.com_version.split(".")
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logger.error('Wrong COMVERSION format, use dot separated integers e.g. "5.7"')
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)
    try:
        if not options.target_ip:
            options.target_ip = address

        if not domain:
            domain = ""

        if options.keytab:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if username and not (password or options.hashes or options.no_pass or options.aesKey):
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey:
            options.k = True

        executer = WMIEXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options.target_ip, options)
        executer.run(address)

    except KeyboardInterrupt as e:
        logger.error(str(e))
    except Exception as e:
        if logging.getLogger("wmiexec-pro").level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logger.error(str(e))
        sys.exit(1)

    sys.exit(0)