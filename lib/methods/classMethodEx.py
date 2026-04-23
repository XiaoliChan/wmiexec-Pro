import sys
import logging

from io import StringIO
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import CIM_TYPE_ENUM, WBEM_FLAG_CREATE_ONLY


class class_MethodEx():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def create_Class(self, ClassName, iWbemServices_Cimv2=None, iWbemServices_Subscription=None, return_iWbemServices=False):
        self.logger.info(f"Creating class: {ClassName}")

        if not iWbemServices_Cimv2:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        # Login into subscription namespace (still needed by callers for script execution)
        if not iWbemServices_Subscription:
            iWbemServices_Subscription = self.iWbemLevel1Login.NTLMLogin("//./root/subscription", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()

        # Use native PutClass instead of VBS workaround
        newClass, _ = iWbemServices_Cimv2.GetObject('')
        newClass.setClassName(ClassName)
        newClass.addNewAttribute("CreationClassName", CIM_TYPE_ENUM.CIM_TYPE_STRING, "")
        newClass.addNewAttribute("DebugOptions", CIM_TYPE_ENUM.CIM_TYPE_STRING, "")
        iWbemServices_Cimv2.PutClass(newClass.marshalMe(), WBEM_FLAG_CREATE_ONLY)

        # Create initial "Backup" instance
        createdClass, _ = iWbemServices_Cimv2.GetObject(ClassName)
        instance = createdClass.SpawnInstance()
        instance.CreationClassName = "Backup"
        instance.DebugOptions = "For windows backup services"
        iWbemServices_Cimv2.PutInstance(instance.marshalMe())

        self.logger.info(f"Class: {ClassName} has been created!")

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