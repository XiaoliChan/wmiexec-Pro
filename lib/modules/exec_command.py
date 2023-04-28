import uuid
import time
import base64
import os
import time
import datetime

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
    def timer_For_UnderNT6(self, iWbemServices=None, return_iWbemServices=False):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_LocalTime")
        LocalTime = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        LocalTime = dict(LocalTime.getProperties())

        # Get remaining seconds until the next minute.
        for i in range((65-int(LocalTime['Second']['value'])),0,-1):
            print(f"[+] Waiting {i}s for command execution.", end="\r", flush=True)
            time.sleep(1)
        
        print("\r\n[+] Command executed!")

        iWbemServices.RemRelease()
        # Return cimv2
        if return_iWbemServices is True: return iWbemServices
    
    # For system under NT6, like windows server 2003
    def exec_command_silent_For_UnderNT6(self, command=None):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        
        sql1 = "SELECT * FROM Win32_LocalTime"
        sql2 = "SELECT * FROM Win32_TimeZone"
        
        iEnumWbemClassObject = iWbemServices.ExecQuery(sql1)
        Win32_LocalTime = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

        Machine_Date = datetime.datetime(100, 1, 1, int(Win32_LocalTime.Hour), int(Win32_LocalTime.Minute), 00)
        execute_time = Machine_Date + datetime.timedelta(0, 60) # Delay one miniute for command execution
        execute_time=execute_time.time()

        iEnumWbemClassObject = iWbemServices.ExecQuery(sql2)
        Win32_TimeZone = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

        executeTime = "********" + str(execute_time).replace(":", '') + ".000000+" + str(Win32_TimeZone.Bias)
        command=r'C:\Windows\System32\cmd.exe /c "%s"'%command
        Win32_ScheduledJob,resp=iWbemServices.GetObject("Win32_ScheduledJob")
        result = Win32_ScheduledJob.Create(command, executeTime, 0, 0, 0, 1)
        if int(result.ReturnValue) == 0:
            print("[+] Create schedule job for command execution successfully.")
        else:
            print("[-] Create schedule job for command execution error, code: %s" %str(result.ReturnValue))

        self.timer_For_UnderNT6(iWbemServices)

        iWbemServices.RemRelease()

    def exec_command_silent(self, command, old=False):
        if old == False:
            executer = executeVBS_Toolkit(self.iWbemLevel1Login)

            random_TaskName = str(uuid.uuid4())

            if '"' in command: command = command.replace('"',r'""')
            if "'" in command: command = command.replace("'",r'""')
            
            print("[+] Executing command...(Sometime it will take a long time, please wait)")

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
            
            executer.remove_Event(tag)
        else:
            # Windows will auto remove job after schedule job executed.
            self.exec_command_silent_For_UnderNT6(command)

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
            iWbemServices_Reuse = self.timer_For_UnderNT6(iWbemServices=iWbemServices_Reuse, return_iWbemServices=True)
        
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
