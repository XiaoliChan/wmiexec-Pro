import time
import sys

from io import StringIO
from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.dcerpc.v5.dtypes import NULL

class class_MethodEx():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    # Have no idea how to use IWbemServices::PutClass create class object via impacket function remotely.
    # So lets we jump in vbs :)
    # Prepare for download file
    def create_Class(self, ClassName, iWbemServices=None, return_iWbemServices=False):
        with open('./lib/vbs-scripts/CreateClass.vbs') as f: vbs = f.read()
        vbs = vbs.replace('REPLEACE_WITH_CLASSNAME',ClassName)

        print("[+] Creating class: %s"%ClassName)
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteVBS(vbs_content=vbs, returnTag=True)
    
        # Wait 5 seconds for next step.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)

        # Check class creation status
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        try:
            test_ClassObject, resp = iWbemServices.GetObject('%s.CreationClassName="Backup"' %ClassName)
        except Exception as e:
            print("\r\n[-] Unexpected error: %s"%str(e))
            executer.remove_Event(tag)
        else:
            print("\r\n[+] Class: %s has been created!" %ClassName)
            # Clean up
            print("[+] Stop vbs interval execution after created class.")
            executer.remove_Event(tag)
        
        iWbemServices.RemRelease()
        # Return cimv2
        if return_iWbemServices is True: return iWbemServices

    def check_ClassStatus(self, ClassName, iWbemServices=None, return_iWbemServices=False):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            test_ClassObject, resp = iWbemServices.GetObject('%s.CreationClassName="Backup"' %ClassName)
        except Exception as e:
            if "WBEM_E_INVALID_CLASS" in str(e):
                print("[-] Class %s didn't exist, start creating class." %ClassName)
                iWbemServices = self.create_Class(ClassName, iWbemServices=iWbemServices, return_iWbemServices=True)
            else:
                print("\r\n[-] Unexpected error: %s"%str(e))
        else:
            print("\r\n[+] Class: %s has been created!" %ClassName)
        
        iWbemServices.RemRelease()
        # Return cimv2
        if return_iWbemServices is True: return iWbemServices

    def remove_Class(self, ClassName, iWbemServices=None, return_iWbemServices=False):
        if iWbemServices is None:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        print("[+] Remove wmi class: %s" %ClassName)
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        iWbemServices.DeleteClass(ClassName)
        sys.stdout = current
        iWbemServices.RemRelease()
        # Return cimv2
        if return_iWbemServices is True: return iWbemServices
