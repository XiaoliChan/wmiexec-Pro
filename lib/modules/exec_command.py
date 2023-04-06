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


    def exec_command_silent(self, command):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)

        random_TaskName = str(uuid.uuid4())
        with open('./lib/vbs-scripts/Exec-Command-Silent.vbs') as f: vbs = f.read()
        vbs = vbs.replace('REPLEACE_WITH_COMMAND',command).replace('REPLEACE_WITH_TASK',random_TaskName)

        filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        
        print("[+] Executing command...(Sometime it will take a long time, please wait)")
        tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)
        
        # Wait 5 seconds for next step.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)
        
        executer.remove_Event(tag)
    
    def exec_command_WithOutput(self, command, CODEC="gbk", ClassName_StoreOutput=None, save_Result=False, hostname=None):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        if ClassName_StoreOutput == None: ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"
        
        FileName = str(uuid.uuid4()) + ".log"
        CMD_instanceID = str(uuid.uuid4())
        random_TaskName = str(uuid.uuid4())
        with open('./lib/vbs-scripts/Exec-Command-WithOutput.vbs') as f: vbs = f.read()
        vbs = vbs.replace('REPLEACE_WITH_COMMAND', command).replace('REPLEACE_WITH_FILENAME', FileName).replace('REPLEACE_WITH_CLASSNAME',ClassName_StoreOutput).replace('RELEACE_WITH_UUID',CMD_instanceID).replace('REPLEACE_WITH_TASK',random_TaskName)

        # Reuse cimv2 namespace to avoid dcom limition
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        iWbemServices_Reuse = class_Method.check_ClassStatus(ClassName=ClassName_StoreOutput, return_iWbemServices=True)

        print("[+] Executing command...(Sometime it will take a long time, please wait)")
        filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
        #tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)

        # Experimental: use timer instead of filter query
        tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
        
        # Wait 5 seconds for next step.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)
        
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