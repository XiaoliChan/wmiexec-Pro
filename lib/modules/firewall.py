import logging
import json
import sys

from io import StringIO
from impacket.dcerpc.v5.dtypes import NULL

from lib.checkError import checkError


class Firewall_Toolkit:
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def port_Searcher(self, port, returnID = False):
        self.logger.info(f"Searching rule include the specified port: {port}")
        id_List = []
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/StandardCimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT InstanceID, LocalPort, Protocol, RemotePort FROM MSFT_NetProtocolPortFilter")
        while True:
            try:
                firewall_PortClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(firewall_PortClass.getProperties())
                for i in record["LocalPort"]["value"]:
                    if str(port) == i and record["InstanceID"]["value"]:
                        result = self.instanceID_Searcher(record["InstanceID"]["value"], iWbemServices)
                        if not returnID:
                            result = "[+] Rule id: {}, DisplayName: {}, Direction: {}, Port: {}, Action: {}, Status: {}".format(
                                        record["InstanceID"]["value"],
                                        result["DisplayName"],
                                        result["Direction"],
                                        record["LocalPort"]["value"],
                                        result["Action"],
                                        result["Status"]
                                    )
                            self.logger.log(100, result)
                        if returnID:
                            id_List.append(record["InstanceID"]["value"]) 
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break
        iEnumWbemClassObject.RemRelease()
        if returnID:
            return id_List
    
    def instanceID_Searcher(self, ID, iWbemServices=None):
        # If user do NTLMLogin operate to many time, then will cause RPC_E_DISCONNECTED exception(DCOM connection rate limit)
        # So, we can keep using iWbemServices object from port_Searcher when doing enumeration, and do newlogin when doing invoke this function.
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/StandardCimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        tmp_dict = {}
        iEnumWbemClassObject = iWbemServices.ExecQuery(f'SELECT DisplayName, InstanceID, Direction, Action, Enabled FROM MSFT_NetFirewallRule where InstanceID = "{ID}"')
        firewall_RuleClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        record = dict(firewall_RuleClass.getProperties())
        tmp_dict["DisplayName"] = record["DisplayName"]["value"] 
        tmp_dict["Direction"] = "Inbound" if record["Direction"]["value"] == 1 else "Outbound"
        tmp_dict["Action"] = "Allow" if record["Action"]["value"] == 2 else ("AllowBypass" if record["Action"]["value"] == 3 else "Block")
        tmp_dict["Status"] = "Enabled" if record["Enabled"]["value"] == 1 else "Disabled"
        iEnumWbemClassObject.RemRelease()
        return tmp_dict

    def rule_Controller(self, ID, flag):
        # Can"t invoke disable and enable function directly
        # firewall_RuleClass.Enable/Disable not wotking
        # But we can force push firewall rule :)
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/StandardCimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        #DisplayName, InstanceID, Direction, Action, Enabled
        iEnumWbemClassObject = iWbemServices.ExecQuery(f'SELECT * FROM MSFT_NetFirewallRule where InstanceID = "{ID}"')
        firewall_RuleClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #firewall_RuleClass.Enable
        record = dict(firewall_RuleClass.getProperties())
        if flag in ["enable","disable"]:
            firewall_Instance = firewall_RuleClass.SpawnInstance()
            # windows only accept encoded string with latin-1, if chinese character in value, will get exception in impacket/structure.py line 250
            # Have no idea how to solve this, let"s submit uuid instead of original character
            firewall_Instance.ElementName = ""
            firewall_Instance.DisplayName = ""
            firewall_Instance.Description = ""
            firewall_Instance.DisplayGroup = ""
            """
            try:
                b(record["ElementName"]["value"])
            except:
                firewall_Instance.ElementName = "windows-object-" + str(uuid.uuid4())
            else:
                firewall_Instance.ElementName = record["ElementName"]["value"]
            
            try:
                b(record["DisplayName"]["value"])
            except:
                firewall_Instance.DisplayName = "windows-object-" + str(uuid.uuid4())
            else:
                firewall_Instance.DisplayName = record["DisplayName"]["value"]

            try:
                b(record["Description"]["value"])
            except:
                firewall_Instance.Description = "windows-object-" + str(uuid.uuid4())
            else:
                firewall_Instance.Description = "" if record["Description"]["value"] == None else record["Description"]["value"]

            try:
                b(record["DisplayGroup"]["value"])
            except:
                firewall_Instance.DisplayGroup = "windows-object-" + str(uuid.uuid4())
            else:
                firewall_Instance.DisplayGroup = "" if record["DisplayGroup"]["value"] == None else record["DisplayGroup"]["value"]
            """
            # allow=2, allowBypass=3, Block=4
            firewall_Instance.Action = record["Action"]["value"]
            firewall_Instance.Caption = "" if not record["Caption"]["value"] else record["Caption"]["value"]
            firewall_Instance.CommonName = "" if not record["CommonName"]["value"] else record["CommonName"]["value"]
            # Enable = 1, disable = 2
            firewall_Instance.Enabled = 2 if flag == "disable" else 1
            firewall_Instance.LocalOnlyMapping = False if record["LocalOnlyMapping"]["value"] == "False" else True
            firewall_Instance.LooseSourceMapping = False if record["LooseSourceMapping"]["value"] == "False" else True
            firewall_Instance.Mandatory = "" if not record["Mandatory"]["value"] else record["Mandatory"]["value"]
            firewall_Instance.Owner = "" if not record["Owner"]["value"] else record["Owner"]["value"]
            firewall_Instance.RuleGroup = "" if not record["RuleGroup"]["value"] else record["RuleGroup"]["value"]
            firewall_Instance.RuleUsage = "" if not record["RuleUsage"]["value"] else record["RuleUsage"]["value"]
            # Status attribute must be hardcode
            firewall_Instance.Status = "The rule was parsed successfully from the store."
            current=sys.stdout
            sys.stdout = StringIO()
            marshalled = firewall_Instance.marshalMe()
            sys.stdout = current
            checkError(iWbemServices.PutInstance(marshalled))
        else:
            checkError(iWbemServices.DeleteInstance('MSFT_NetFirewallRule.CreationClassName="{}",PolicyRuleName="{}",SystemCreationClassName="{}",SystemName="{}"'.format(
                                                    record["CreationClassName"]["value"],
                                                    record["PolicyRuleName"]["value"],
                                                    record["SystemCreationClassName"]["value"],
                                                    record["SystemName"]["value"]
                                                    )))

    def dump_FirewallRules(self, save_FileName):
        self.logger.info("Dumpping...")
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/StandardCimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT DisplayName, InstanceID, Direction, Action, Enabled FROM MSFT_NetFirewallRule")
        firewall_RuleRecord = {}
        while True:
            try:
                tmp_dict = {}
                firewall_RuleClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(firewall_RuleClass.getProperties())
                tmp_dict["DisplayName"] = record["DisplayName"]["value"] 
                tmp_dict["Direction"] = "Inbound" if record["Direction"]["value"] == 1 else "Outbound"
                tmp_dict["Action"] = "Allow" if record["Action"]["value"] == 2 else ("AllowBypass" if record["Action"]["value"] == 3 else "Block")
                tmp_dict["Status"] = "Enabled" if record["Enabled"]["value"] == 1 else "Disabled"
                firewall_RuleRecord[record["InstanceID"]["value"]] = tmp_dict
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break
        
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT InstanceID, LocalPort, Protocol, RemotePort FROM MSFT_NetProtocolPortFilter")
        firewall_RuleDetailRecord = {}
        while True:
            try:
                tmp_dict = {}
                firewall_PortClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(firewall_PortClass.getProperties())
                tmp_dict["Protocol"] = record["Protocol"]["value"]
                tmp_dict["LocalPort"] = record["LocalPort"]["value"]
                tmp_dict["RemotePort"] = record["RemotePort"]["value"]
                firewall_RuleDetailRecord[record["InstanceID"]["value"]] = tmp_dict
            except Exception as e:
                if str(e).find("S_FALSE") < 0:
                    pass
                else:
                    break
        
        test = dict(firewall_RuleDetailRecord, **firewall_RuleRecord)
        for key in test.keys():
            if key in firewall_RuleDetailRecord:
                test[key] = dict(test[key], **firewall_RuleDetailRecord[key])

        with open(save_FileName,"w") as f:
            f.write(json.dumps(test, indent=4))

        self.logger.log(100, f"[+] Whole the firewall rules are dumped to {save_FileName}")

    def FirewallProfile_Controller(self, flag):
        # Use it on your own risk :)
        iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/StandardCimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM MSFT_NetFirewallProfile")
        while True:
            try:
                firewall_ProfileClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = dict(firewall_ProfileClass.getProperties())
                firewall_ProfileInstance = firewall_ProfileClass.SpawnInstance()
                firewall_ProfileInstance.DisabledInterfaceAliases = ""
                firewall_ProfileInstance.Caption = "" if not record["Caption"]["value"] else record["Caption"]["value"]
                firewall_ProfileInstance.Enabled = 1 if flag == "enable" else 0
                firewall_ProfileInstance.Description = "" if not record["Caption"]["value"] else record["Caption"]["value"]
                current=sys.stdout
                sys.stdout = StringIO()
                iWbemServices.PutInstance(firewall_ProfileInstance.marshalMe())
                sys.stdout = current
            except Exception as e:
                    if str(e).find("S_FALSE") < 0:
                        self.logger.error(str(e))
                        raise
                    else:
                        self.logger.log(100, f"All firewall profile has been {flag}")
                        break
        iEnumWbemClassObject.RemRelease()