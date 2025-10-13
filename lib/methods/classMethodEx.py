import time
import sys
import logging

from io import StringIO
from lib.methods.executeVBS import executeVBS_Toolkit
from lib.helpers import get_vbs
from impacket.dcerpc.v5.dtypes import NULL


class class_MethodEx():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    # Have no idea how to use iWbemServices_Cimv2::PutClass create class object via impacket function remotely.
    # So lets we jump in vbs :)
    # Prepare for download file
    def create_Class(self, ClassName, iWbemServices_Cimv2=None, iWbemServices_Subscription=None, return_iWbemServices=False):
        vbs = get_vbs("CreateClass.vbs")
        vbs = vbs.replace("REPLACE_WITH_CLASSNAME", ClassName)

        self.logger.info(f"Creating class: {ClassName}")

        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        # Login into subscription namespace
        if not iWbemServices_Subscription:
            iWbemServices_Subscription = self.iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        tag, iWbemServices_Subscription = executer.ExecuteVBS(vbs_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription, return_iWbemServices=True)

        # Wait 5 seconds for next step.
        loger_flush = logging.getLogger("CountdownLogger")
        for i in range(5,0,-1):
            loger_flush.info(f"Waiting {i}s for next step.\r")
            time.sleep(1)

        # Check class creation status
        if not iWbemServices_Cimv2:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        try:
            iWbemServices_Cimv2.GetObject(f'{ClassName}.CreationClassName="Backup"')
        except Exception as e:
            self.logger.error(f"Unexpected error: {e!s}")
            executer.remove_Event(tag)
        else:
            self.logger.info(f"Class: {ClassName} has been created!")
            # Clean up
            self.logger.info("Stop vbs interval execution after created class.")
            executer.remove_Event(tag)

        # Return cimv2
        if return_iWbemServices:
            return iWbemServices_Cimv2, iWbemServices_Subscription

    def check_ClassStatus(self, ClassName, iWbemServices_Cimv2=None, iWbemServices_Subscription=None, return_iWbemServices=False):
        if not iWbemServices_Cimv2:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        try:
            iWbemServices_Cimv2.GetObject(f'{ClassName}.CreationClassName="Backup"')
        except Exception as e:
            if "WBEM_E_INVALID_CLASS" in str(e):
                self.logger.info(f"Class {ClassName} didn't exist, start creating class.")
                iWbemServices_Cimv2, iWbemServices_Subscription = self.create_Class(ClassName, iWbemServices_Cimv2=iWbemServices_Cimv2, iWbemServices_Subscription=iWbemServices_Subscription,return_iWbemServices=True)
            else:
                self.logger.error(f"Unexpected error: {e!s}")
        else:
            self.logger.info(f"Class: {ClassName} has been created!")

        # Return cimv2
        if return_iWbemServices:
            return iWbemServices_Cimv2, iWbemServices_Subscription

    def remove_Class(self, ClassName, iWbemServices_Cimv2=None, return_iWbemServices_Cimv2=False):
        if not iWbemServices_Cimv2:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        self.logger.info(f"Remove wmi class: {ClassName}")
        # Don't output verbose
        current=sys.stdout
        sys.stdout = StringIO()
        iWbemServices_Cimv2.DeleteClass(ClassName)
        sys.stdout = current

        # Return cimv2
        if return_iWbemServices_Cimv2:
            return iWbemServices_Cimv2