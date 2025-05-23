import logging

from lib.modules.service_mgr import Service_Toolkit
from lib.modules.firewall import Firewall_Toolkit


class WINRM_Toolkit():
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