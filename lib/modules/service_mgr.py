import sys
import logging
import json

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from lib.module_base import ModuleBase


ERROR_MSG = {
    0:"The request was accepted.",
    1:"The request is not supported.",
    2:"The user did not have the necessary access.",
    3:"The service cannot be stopped because other services that are running are dependent on it.",
    4:"The requested control code is not valid, or it is unacceptable to the service.",
    5:"The requested control code cannot be sent to the service because the state of the service (State property of the Win32_BaseService class) is equal to 0, 1, or 2.",
    6:"The service has not been started.",
    7:"The service did not respond to the start request in a timely fashion.",
    8:"Unknown failure when starting the service.",
    9:"The directory path to the service executable file was not found.",
    10:"The service is already running.",
    11:"The database to add a new service is locked.",
    12:"A dependency this service relies on has been removed from the system.",
    13:"The service failed to find the service needed from a dependent service.",
    14:"The service has been disabled from the system.",
    15:"The service does not have the correct authentication to run on the system.",
    16:"This service is being removed from the system.",
    17:"The service has no execution thread.",
    18:"The service has circular dependencies when it starts.",
    19:"A service is running under the same name.",
    20:"The service name has invalid characters.",
    21:"Invalid parameters have been passed to the service.",
    22:"The account under which this service runs is either invalid or lacks the permissions to run the service.",
    23:"The service exists in the database of services available from the system.",
    24:"The service is currently paused in the system."
}

class Service_Toolkit(ModuleBase):
    name = "service"
    description = "Service manager"

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(Service_Toolkit.name, help=Service_Toolkit.description)
        p.add_argument("-action", action="store", choices=["create", "delete", "start", "stop", "disable", "auto-start", "manual-start", "getinfo", "modify"],
                       help="Action you want to do.")
        p.add_argument("-service-name", action="store", help="Specify service name.")
        p.add_argument("-display-name", action="store", help="Specify service display name.")
        p.add_argument("-bin-path", action="store", help="Specify binary path of service creation/modification.")
        p.add_argument("-start-mode", action="store", choices=["Automatic", "Manual", "Disabled"], help="Specify start mode for service modification.")
        p.add_argument("-start-name", action="store", help="Specify service account (e.g. LocalSystem, .\\\\username) for modification.")
        p.add_argument("-start-password", action="store", help="Specify service account password for modification.")
        p.add_argument("-class", dest="_class", action="store", choices=["Win32_Service", "Win32_TerminalService", "Win32_BaseService"], default="Win32_Service",
                       help="Alternative class of service object creation.")
        p.add_argument("-dump", action="store", metavar="FILENAME", help="Dump all services to file as json format.")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = Service_Toolkit(iWbemLevel1Login, dcom)
        if options.action:
            if options.action == "create" and all([options.service_name, options.display_name, options.bin_path]):
                toolkit.create_Service(options.service_name, options.display_name, options.bin_path, options._class)
            elif options.action == "modify" and options.service_name:
                toolkit.modify_Service(
                    options.service_name,
                    displayName=options.display_name,
                    binaryPath=options.bin_path,
                    startMode=options.start_mode,
                    startName=options.start_name,
                    startPassword=options.start_password
                )
            else:
                toolkit.control_Service(options.action, options.service_name)
        if options.dump:
            toolkit.dump_Service(options.dump)

    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.logger = logging.getLogger("wmiexec-pro")

    def create_Service(self, serviceName, displayName, binaryPath, technique):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.iWbemLevel1Login.RemRelease()
        Service_ClassObject,_ = iWbemServices.GetObject(technique)
        # Format: Name, DisplayName, PathName, ServiceType, ErrorControl, StartMode, DesktopInteract, StartName, StartPassword, LoadOrderGroup, LoadOrderGroupDependencies, ServiceDependencies
        resp = Service_ClassObject.Create(serviceName, displayName, binaryPath, 16, 0, "Automatic", 0, "LocalSystem", "", "System", "", "")
        if resp.ReturnValue == 0:
            self.logger.log(100, f"Service {serviceName} created!")
        else:
            self.logger.error(f"Return value: {resp.ReturnValue!s}, reason: {ERROR_MSG[resp.ReturnValue]}")
        
    def control_Service(self, action, serviceName, iWbemServices=None):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()
        try:
            Service_ClassObject,_ = iWbemServices.GetObject(f'Win32_Service.Name="{serviceName}"')
        except Exception as e:
            if "WBEM_E_NOT_FOUND" in str(e):
                self.logger.error(f"Service: {serviceName} not found!")
            else:
                self.logger.error(f"Unknown error: {e!s}")
            self.dcom.disconnect()
            sys.exit(1)
        else:
            if action == "delete":
                resp = Service_ClassObject.Delete()
            elif action == "start":
                resp = Service_ClassObject.StartService()
            elif action == "stop":
                resp = Service_ClassObject.StopService()
            elif action == "disable":
                resp = Service_ClassObject.ChangeStartMode("Disabled")
            elif action == "auto-start":
                resp = Service_ClassObject.ChangeStartMode("Automatic")
            elif action == "manual-start":
                resp = Service_ClassObject.ChangeStartMode("Manual")
            elif action == "getinfo":
                record = dict(Service_ClassObject.getProperties())
                self.logger.log(100, 'Service info: service name: "{}", display name: "{}", path: "{}", service type: "{}", start mode: "{}", service account: "{}", state: "{}", process id: "{}"'.format(
                # ConsentUxUserSvc_6728c
                        record["Name"]["value"],
                        record["DisplayName"]["value"],
                        record["PathName"]["value"],
                        record["ServiceType"]["value"],
                        record["StartMode"]["value"],
                        "" if record["StartName"]["value"] is None else record["StartName"]["value"],
                        record["State"]["value"],
                        str(record["ProcessId"]["value"])
                ))
            
            try:
                if resp.ReturnValue == 0 :
                    self.logger.log(100, "Action done!")
                else:
                    self.logger.error(f"Return value: {resp.ReturnValue!s}, reason: {ERROR_MSG[resp.ReturnValue]}")
            except Exception:
                pass
    
    def dump_Service(self, save_FileName, iWbemServices=None):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT Name, DisplayName, PathName, ServiceType, StartMode, StartName, State, ProcessID FROM Win32_Service")
        full_Results = {}
        while True:
            try:
                tmp_dict = {}
                query = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(query.getProperties())
                tmp_dict["ServiceName"] = record["Name"]["value"]
                tmp_dict["DisplayName"] = record["DisplayName"]["value"]
                tmp_dict["PathName"] = record["PathName"]["value"]
                tmp_dict["ServiceType"] = record["ServiceType"]["value"]
                tmp_dict["StartMode"] = record["StartMode"]["value"]
                tmp_dict["ServiceAccount"] = record["StartName"]["value"] if record["StartName"]["value"] else ""
                tmp_dict["State"] = record["State"]["value"]
                tmp_dict["ProcessId"] = str(record["ProcessId"]["value"])
                full_Results[tmp_dict["ServiceName"]] = tmp_dict
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break
        with open(save_FileName, "w") as f:
            f.write(json.dumps(full_Results, indent=4))
        self.logger.info(f"Whole the services info are dumped to {save_FileName}")
        iEnumWbemClassObject.RemRelease()

    # Win32_Service.Change method: https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/change-method-in-class-win32-service
    def modify_Service(self, serviceName, displayName=None, binaryPath=None, startMode=None, startName=None, startPassword=None):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
        iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.iWbemLevel1Login.RemRelease()

        try:
            Service_ClassObject, _ = iWbemServices.GetObject(f'Win32_Service.Name="{serviceName}"')
        except Exception as e:
            if "WBEM_E_NOT_FOUND" in str(e):
                self.logger.error(f"Service: {serviceName} not found!")
            else:
                self.logger.error(f"Unknown error: {e!s}")
            self.dcom.disconnect()
            sys.exit(1)

        # Get current service properties as defaults
        record = dict(Service_ClassObject.getProperties())
        current_displayName = record["DisplayName"]["value"] or ""
        current_pathName = record["PathName"]["value"] or ""
        current_serviceType = record["ServiceType"]["value"]
        current_startMode = record["StartMode"]["value"] or "Auto"
        current_startName = record["StartName"]["value"] or "LocalSystem"

        # Format: DisplayName, PathName, ServiceType, ErrorControl, StartMode, DesktopInteract, StartName, StartPassword, LoadOrderGroup, LoadOrderGroupDependencies, ServiceDependencies
        resp = Service_ClassObject.Change(
            displayName if displayName else current_displayName,
            binaryPath if binaryPath else current_pathName,
            current_serviceType,
            0,
            startMode if startMode else current_startMode,
            0,
            startName if startName else current_startName,
            startPassword if startPassword else "",
            "",
            "",
            ""
        )

        if resp.ReturnValue == 0:
            self.logger.log(100, f"Service {serviceName} modified!")
        else:
            self.logger.error(f"Return value: {resp.ReturnValue!s}, reason: {ERROR_MSG[resp.ReturnValue]}")