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
    
    def tasklist(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("Select Name, CommandLine, Description, ExecutablePath, ProcessId, ParentProcessId, SessionId from Win32_Process")
        full_Results = {}
        self.logger.info("Retrieving process list")
        while True:
            try:
                tmp_dict = {}
                query = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(query.getProperties())
                tmp_dict["Name"] = record["Name"]["value"]
                tmp_dict["CommandLine"] = record["CommandLine"]["value"]
                tmp_dict["Description"] = record["Description"]["value"]
                tmp_dict["ExecutablePath"] = record["ExecutablePath"]["value"]
                tmp_dict["ProcessId"] = record["ProcessId"]["value"]
                tmp_dict["ParentProcessId"] = record["ParentProcessId"]["value"]
                tmp_dict["SessionId"] = record["SessionId"]["value"]
                full_Results[tmp_dict["Name"]] = tmp_dict
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break
        iEnumWbemClassObject.RemRelease()

        for name, process in sorted(full_Results.items()):
            self.logger.info(f"Process Name: {process['Name'] or 'N/A'}")
            self.logger.info(f"Process ID: {process['ProcessId'] or 'N/A'}")
            self.logger.info(f"Parent Process ID: {process['ParentProcessId'] or 'N/A'}")
            self.logger.info(f"Session ID: {process['SessionId'] or 'N/A'}")
            self.logger.info(f"Description: {process['Description'] or 'N/A'}")
            self.logger.info(f"Executable Path: {process['ExecutablePath'] or 'N/A'}")
            self.logger.info(f"Command Line: {process['CommandLine'] or 'N/A'}")
            self.logger.info("-" * 100)
        self.logger.info(f"Total Processes: {len(full_Results)}")