import logging

from impacket.dcerpc.v5.dtypes import NULL


class ENUM():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def basic_Enum(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * from Win32_ComputerSystem")
        ComputerSystem = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        ComputerSystem = dict(ComputerSystem.getProperties())

        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * from Win32_OperatingSystem")
        OperatingSystem = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        OperatingSystem = dict(OperatingSystem.getProperties())
        major_Version = int(OperatingSystem["Version"]["value"].split(".")[0])

        self.logger.log(100, "[+] Hostanme: {}\n[+] Domain: {}\n[+] Manufacturer: {}\n[+] Model: {}\n[+] Architecture: {}\n[+] OS Name: {}\n[+] System version: {}\n[*] Target NT Version is {}".format(
            ComputerSystem["DNSHostName"]["value"],
            ComputerSystem["Domain"]["value"],
            ComputerSystem["Manufacturer"]["value"],
            ComputerSystem["Model"]["value"],
            ComputerSystem["SystemType"]["value"],
            OperatingSystem["Caption"]["value"],
            OperatingSystem["Version"]["value"],
            'is under 6, please execute command or enable RDP with "-old" option.' if major_Version < 6 else "higher than 6."
        ))