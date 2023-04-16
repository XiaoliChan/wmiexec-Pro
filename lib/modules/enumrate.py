import sys

from impacket.dcerpc.v5.dtypes import NULL

class ENUM():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def basic_Enum(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/Cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_ComputerSystem')
        ComputerSystem = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        ComputerSystem = dict(ComputerSystem.getProperties())

        iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * from Win32_OperatingSystem')
        OperatingSystem = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        OperatingSystem = dict(OperatingSystem.getProperties())

        print("[+] Hostanme: {}\r\n[+] Domain: {}\r\n[+] Manufacturer: {}\r\n[+] Model: {}\r\n[+] Architecture: {}\r\n[+] OS Name: {}\r\n[+] System version: {}".format(
            ComputerSystem['DNSHostName']['value'],
            ComputerSystem['Domain']['value'],
            ComputerSystem['Manufacturer']['value'],
            ComputerSystem['Model']['value'],
            ComputerSystem['SystemType']['value'],
            OperatingSystem['Caption']['value'],
            OperatingSystem['Version']['value']
        ))

        nt_Version = OperatingSystem['Version']['value'].split('.')[0]
        if int(nt_Version) < 6:
            print('[+] Target NT Version is under 6, please execute command or enable RDP with "-old" option.')
        else:
            print('[+] Target NT version is higher than 6.')
