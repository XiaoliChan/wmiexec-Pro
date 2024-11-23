import time
import sys

from io import StringIO
from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.dcerpc.v5.dtypes import NULL
from lib.helpers import get_vbs_path

class class_MethodEx():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    # Have no idea how to use iWbemServices_Cimv2::PutClass create class object via impacket function remotely.
    # So lets we jump in vbs :)
    # Prepare for download file
    def create_Class(self, ClassName, iWbemServices_Cimv2=None, iWbemServices_Subscription=None, return_iWbemServices=False):
        with open(get_vbs_path('CreateClass.vbs')) as f: vbs = f.read()
        vbs = vbs.replace('REPLACE_WITH_CLASSNAME',ClassName)

        print("[+] Creating class: %s"%ClassName)
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        # Login into subscription namespace
        if iWbemServices_Subscription is None:
            iWbemServices_Subscription = self.iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        tag, iWbemServices_Subscription = executer.ExecuteVBS(vbs_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription, return_iWbemServices=True)
    
        # Wait 5 seconds for next step.
        for i in range(5,0,-1):
            print(f"[+] Waiting {i}s for next step.", end="\r", flush=True)
            time.sleep(1)

        # Check class creation status
        if iWbemServices_Cimv2 is None:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            test_ClassObject, resp = iWbemServices_Cimv2.GetObject('%s.CreationClassName="Backup"' %ClassName)
        except Exception as e:
            print("\r\n[-] Unexpected error: %s"%str(e))
            executer.remove_Event(tag)
        else:
            print("\r\n[+] Class: %s has been created!" %ClassName)
            # Clean up
            print("[+] Stop vbs interval execution after created class.")
            executer.remove_Event(tag)

        # Return cimv2
        if return_iWbemServices is True:
            return iWbemServices_Cimv2, iWbemServices_Subscription

    def check_ClassStatus(self, ClassName, iWbemServices_Cimv2=None, iWbemServices_Subscription=None, return_iWbemServices=False):
        if iWbemServices_Cimv2 is None:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        try:
            test_ClassObject, resp = iWbemServices_Cimv2.GetObject('%s.CreationClassName="Backup"' %ClassName)
        except Exception as e:
            if "WBEM_E_INVALID_CLASS" in str(e):
                print("[-] Class %s didn't exist, start creating class." %ClassName)
                iWbemServices_Cimv2, iWbemServices_Subscription = self.create_Class(ClassName, iWbemServices_Cimv2=iWbemServices_Cimv2, iWbemServices_Subscription=iWbemServices_Subscription,return_iWbemServices=True)
            else:
                print("\r\n[-] Unexpected error: %s"%str(e))
        else:
            print("\r\n[+] Class: %s has been created!" %ClassName)
        
        # Return cimv2
        if return_iWbemServices is True:
            return iWbemServices_Cimv2, iWbemServices_Subscription

    def remove_Class(self, ClassName, iWbemServices_Cimv2=None, return_iWbemServices_Cimv2=False):
        if iWbemServices_Cimv2 is None:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        print("[+] Remove wmi class: %s" %ClassName)
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        iWbemServices_Cimv2.DeleteClass(ClassName)
        sys.stdout = current
        
        # Return cimv2
        if return_iWbemServices_Cimv2 is True:
            return iWbemServices_Cimv2
