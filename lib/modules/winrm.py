import logging

from lib.modules.service_mgr import Service_Toolkit
from lib.modules.firewall import Firewall_Toolkit
from impacket.dcerpc.v5.dtypes import NULL

class WINRM_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def WINRM_Wrapper(self, flag):
        executer_Service = Service_Toolkit(self.iWbemLevel1Login)
        if flag == "enable":
            print("[+] Enabling WINRM service and configure firewall.")
            executer_Service.control_Service(action="start", serviceName="WINRM")
            self.configure_Firewall(flag)
        else:
            print("[+] Disabling WINRM service and configure firewall.")
            executer_Service.control_Service(action="stop", serviceName="WINRM")
            self.configure_Firewall(flag)

    def configure_Firewall(self,flag):
        winrm_Firewall = Firewall_Toolkit(self.iWbemLevel1Login)
        id_List = winrm_Firewall.port_Searcher("5985", returnID=True)
        for i in id_List:
            winrm_Firewall.rule_Controller(i,flag)
