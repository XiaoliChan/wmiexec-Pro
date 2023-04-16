import uuid
import time
import base64
import os
import time

from lib.methods.classMethodEx import class_MethodEx
from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.dcerpc.v5.dtypes import NULL


class EXEC_COMMAND():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
    
    def save_ToFile(self, hostname, content):
        path = 'save/'+hostname
        save_FileName = str(int(time.time())) + ".txt"
        if os.path.exists(path) == False:
            os.makedirs(path, exist_ok=True)
        
        with open("{}/{}".format(path, save_FileName), 'w') as f: f.write(content)
        print("[+] Save command result to: {}/{}".format(path, save_FileName))

    # For system under NT6, like windows server 2003
    # Timer for countdown Win32_ScheduledJob, scheduled task in "Win32_ScheduledJob" only will be trigger every per minute.
    def timer_ForNT6(self, iWbemServices=None, return_iWbemServices=False):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_LocalTime")
        LocalTime = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        LocalTime = dict(LocalTime.getProperties())

        # Get remaining seconds until the next minute.
        for i in range((60-int(LocalTime['Second']['value'])),0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)
        
        iWbemServices.RemRelease()
        # Return cimv2
        if return_iWbemServices is True: return iWbemServices

    def exec_command_silent(self, command, old=False):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)

        random_TaskName = str(uuid.uuid4())

        if '"' in command: command = command.replace('"',r'""')
        if "'" in command: command = command.replace("'",r'""')
        
        print("[+] Executing command...(Sometime it will take a long time, please wait)")

        if old == False:
            with open('./lib/vbscripts/Exec-Command-Silent.vbs') as f: vbs = f.read()
            vbs = vbs.replace('REPLACE_WITH_COMMAND',command).replace('REPLACE_WITH_TASK',random_TaskName)
            
            # Experimental: use timer instead of filter query
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            #filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            #tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)
            
            # Wait 5 seconds for next step.
            for i in range(5,0,-1):
                print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
                time.sleep(1)
        else:
            with open('./lib/vbscripts/Exec-Command-Silent-UnderNT6.vbs') as f: vbs = f.read()
            vbs = vbs.replace('REPLACE_WITH_COMMAND',command)
            
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            
            self.timer_ForNT6()
        
        executer.remove_Event(tag)
    
    def exec_command_WithOutput(self, command, CODEC="gbk", ClassName_StoreOutput=None, save_Result=False, hostname=None, old=False):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        if ClassName_StoreOutput == None: ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"
        
        FileName = str(uuid.uuid4()) + ".log"
        CMD_instanceID = str(uuid.uuid4())
        random_TaskName = str(uuid.uuid4())
        
        if '"' in command: command = command.replace('"',r'""')
        if "'" in command: command = command.replace("'",r'""')

        # Reuse cimv2 namespace to avoid dcom limition
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        iWbemServices_Reuse = class_Method.check_ClassStatus(ClassName=ClassName_StoreOutput, return_iWbemServices=True)

        print("[+] Executing command...(Sometime it will take a long time, please wait)")
        if old == False:
            # Experimental: use timer instead of filter query
            with open('./lib/vbscripts/Exec-Command-WithOutput.vbs') as f: vbs = f.read()
            vbs = vbs.replace('REPLACE_WITH_COMMAND', command).replace('REPLACE_WITH_FILENAME', FileName).replace('REPLACE_WITH_CLASSNAME',ClassName_StoreOutput).replace('RELEACE_WITH_UUID',CMD_instanceID).replace('REPLACE_WITH_TASK',random_TaskName)
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            #filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            #tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)
            
            # Wait 5 seconds for next step.
            for i in range(5,0,-1):
                print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
                time.sleep(1)
        else:
            # Experimental: use timer instead of filter query
            with open('./lib/vbscripts/Exec-Command-WithOutput-UnderNT6.vbs') as f: vbs = f.read()
            vbs = vbs.replace('REPLACE_WITH_COMMAND', command).replace('REPLACE_WITH_FILENAME', FileName).replace('REPLACE_WITH_CLASSNAME',ClassName_StoreOutput).replace('RELEACE_WITH_UUID',CMD_instanceID)
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            
            # Reuse cimv2
            iWbemServices_Reuse = self.timer_ForNT6(iWbemServices=iWbemServices_Reuse, return_iWbemServices=True)
        
        executer.remove_Event(tag)

        print("\r\n[+] Getting command results...")
        command_ResultObject, resp = iWbemServices_Reuse.GetObject('{}.CreationClassName="{}"'.format(ClassName_StoreOutput, CMD_instanceID))
        record = dict(command_ResultObject.getProperties())
        result = base64.b64decode(record['DebugOptions']['value']).decode(CODEC, errors='replace')
        print(result)

        if save_Result == True and hostname != None:
            self.save_ToFile(hostname, result)
        
    def clear(self, ClassName_StoreOutput=None):
        if ClassName_StoreOutput == None: ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"

        class_Method = class_MethodEx(self.iWbemLevel1Login)
        class_Method.remove_Class(ClassName=ClassName_StoreOutput, return_iWbemServices=False)