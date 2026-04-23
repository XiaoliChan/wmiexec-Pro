import logging

from lib.modules.service_mgr import Service_Toolkit
from lib.modules.firewall import Firewall_Toolkit
from lib.module_base import ModuleBase


class WINRM_Toolkit(ModuleBase):
    name = "winrm"
    description = "Enable/Disable WINRM service."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(WINRM_Toolkit.name, help=WINRM_Toolkit.description)
        p.add_argument("-enable", action="store_true", help="Enable WINRM service")
        p.add_argument("-disable", action="store_true", help="Disable WINRM service")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = WINRM_Toolkit(iWbemLevel1Login, dcom)
        if options.enable:
            toolkit.WINRM_Wrapper("enable")
        if options.disable:
            toolkit.WINRM_Wrapper("disable")

    def __init__(self, iWbemLevel1Login, dcom):
        self.logger = logging.getLogger("wmiexec-pro")
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom

    def WINRM_Wrapper(self, flag):
        executer_Service = Service_Toolkit(self.iWbemLevel1Login, self.dcom)
        if flag == "enable":
            executer_Service.control_Service(action="start", serviceName="WINRM")
            self.configure_Firewall(flag)
            self.logger.log(100, "Enabled WINRM service and configure firewall.")
        else:
            executer_Service.control_Service(action="stop", serviceName="WINRM")
            self.configure_Firewall(flag)
            self.logger.log(100, "Disabled WINRM service and configure firewall.")

    def configure_Firewall(self,flag):
        winrm_Firewall = Firewall_Toolkit(self.iWbemLevel1Login)
        self.logger.info("Configuring winrm firewall...")
        id_List = ["WINRM-HTTP-In-TCP", "WINRM-HTTP-In-TCP-PUBLIC"]
        for i in id_List:
            winrm_Firewall.rule_Controller(i,flag)