import logging

from lib.modules.firewall import Firewall_Toolkit
from impacket.dcerpc.v5.dtypes import NULL

class WINRM_Toolkit:
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def WINRM_Wrapper(self, flag):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iWbemClassObject,_ = iWbemServices.GetObject("Win32_Service.Name=\"WinRM\"")
        if flag == "enable":
            iWbemClassObject.StartService()
            self.configure_Firewall(flag)
        elif flag == "disable":
            iWbemClassObject.StopService()
            self.configure_Firewall(flag)
        else:
            print("[-] Wrong operation!")
        iWbemServices.RemRelease()

    def configure_Firewall(self,flag):
        winrm_Firewall = Firewall_Toolkit(self.iWbemLevel1Login)
        id_List = winrm_Firewall.port_Searcher("5985", returnID=True)
        for i in id_List:
            winrm_Firewall.rule_Controller(i,flag)
        
    def query_WINRMResult(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT State FROM Win32_Service where Name=\"WinRM\"")
        iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        result = dict(iWbemClassObject.getProperties())
        result = result['State']['value']
        
        if result == "Running":
            print("[+] WINRM enabled!")
        else:
            print("[+] WINRM disable!")
        iWbemServices.RemRelease()