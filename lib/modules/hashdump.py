import logging

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import ENCODING_UNIT, IWbemClassObject


class Hashdump():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def test(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        Service_ClassObject,_ = iWbemServices.GetObject('Win32_Service.Name="winrm"')
        resp = Service_ClassObject.GetSecurityDescriptor()
