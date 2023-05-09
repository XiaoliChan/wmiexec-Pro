import logging
from array import array
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class WINRM_Toolkit:
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def WINRM_Wrapper(self, flag):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iWbemClassObject,_ = iWbemServices.GetObject("Win32_Service.Name=\"WinRM\"")
        if flag == "enable":
            iWbemClassObject.StartService()
        elif flag == "disable":
            iWbemClassObject.StopService()
        else:
            print("[-] Error action!")
        self.configure_Firewall()
    
    def checkError(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
        if call_status != 0:
            from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
        else:
            logging.info('%s - OK' % banner)

    def configure_Firewall(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/StandardCimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        
        #iEnumWbemClassObject = iWbemServices.ExecQuery(r"select * from MSFT_NetProtocolPortFilter where CreationClassName like '%EE4E9959-BF7A-4F75-B6F7-39EA8579A353%'")
        #iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #iWbemClassObject.printInformation()
        
        firewall_Class, _ = iWbemServices.GetObject('MSFT_NetFirewallRule')
        #rule = ['%WINRM-HTTP-In-TCP','']
        #iEnumWbemClassObject = iWbemServices.ExecQuery("select * from MSFT_NetFirewallRule where CreationClassName like '%WINRM-HTTP-In-TCP'")
        #iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #iWbemClassObject.printInformation()
        firewall_Instance = firewall_Class.SpawnInstance()
        firewall_Instance.CreationClassName = "fuckyouaasasasaasas"
        firewall_Instance.PolicyRuleName=""
        firewall_Instance.SystemCreationClassName=""
        firewall_Instance.SystemName=""
        # allow=2, allowBypass=3, Block=4
        firewall_Instance.Action=2
        firewall_Instance.Caption=""
        firewall_Instance.CommonName=""
        firewall_Instance.ConditionListType=3
        firewall_Instance.Description=""
        firewall_Instance.Direction=1
        firewall_Instance.DisplayGroup=""
        firewall_Instance.DisplayName="AAAAAAAAAAAAAAA"
        firewall_Instance.EdgeTraversalPolicy=0
        firewall_Instance.ElementName="3388"
        firewall_Instance.Enabled=2
        firewall_Instance.EnforcementStatus=[0]
        firewall_Instance.ExecutionStrategy=2
        firewall_Instance.InstanceID="aasaoskljakjl"
        firewall_Instance.LocalOnlyMapping=False
        firewall_Instance.LooseSourceMapping=False
        firewall_Instance.Mandatory=""
        firewall_Instance.Owner=""
        firewall_Instance.PolicyDecisionStrategy=2
        firewall_Instance.PolicyKeywords=""
        firewall_Instance.PolicyRoles=""
        firewall_Instance.PolicyStoreSource="PersistentStore"
        firewall_Instance.PolicyStoreSourceType=1
        firewall_Instance.PrimaryStatus=1
        firewall_Instance.Profiles=0
        firewall_Instance.RuleGroup=""
        firewall_Instance.RuleUsage=""
        firewall_Instance.SequencedActions=3
        firewall_Instance.Status="The rule was parsed successfully from the store."
        firewall_Instance.StatusCode=65536
        self.checkError(iWbemServices.PutInstance(firewall_Instance.marshalMe()))
        
        #MSFT|FW|FirewallRule|CoreNet-GP-NP-Out-TCP
        #MSFT|FW|FirewallRule|aasaoskljakjl
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM MSFT_NetProtocolPortFilter WHERE CreationClassName='MSFT|FW|FirewallRule|CoreNet-GP-NP-Out-TCP'")
        firewall_PortClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #firewall_PortClass.printInformation()
        #print(firewall_PortClass.getProperties())
        #firewall_PortClass['RemotePort']
        
        firewall_PortClass,_ = iWbemServices.GetObject('MSFT_NetProtocolPortFilter')
        #firewall_Instance = firewall_PortClass
        firewall_Instance = firewall_PortClass.SpawnInstance()
        firewall_Instance.CreationClassName = "fuckyouaasasasaasas"
        firewall_Instance.Name = ""
        firewall_Instance.SystemCreationClassName = ""
        firewall_Instance.SystemName = ""
        firewall_Instance.DynamicTransport=0
        firewall_Instance.InstanceID="aasaoskljakjl"
        firewall_Instance.LocalPort = "445"
        firewall_Instance.Protocol="TCP"
        firewall_Instance.RemotePort = ""
        self.checkError(iWbemServices.PutInstance(firewall_Instance.marshalMe()))
        
        
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