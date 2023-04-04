def configure_Firewall(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/StandardCimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()

        #rule = ['%WINRM-HTTP-In-TCP','']
        #iEnumWbemClassObject = iWbemServices.ExecQuery("select * from MSFT_NetFirewallRule where CreationClassName like '%WINRM-HTTP-In-TCP'")
        #firewall_object = iEnumWbemClassObject.Next(0xffffffff,1)[0]
        #iWbemClassObject.printInformation()
        
        #MSFT|FW|FirewallRule|CoreNet-GP-NP-Out-TCP
        #MSFT|FW|FirewallRule|aasaoskljakjl
        #iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM MSFT_NetProtocolPortFilter WHERE CreationClassName='MSFT|FW|FirewallRule|CoreNet-GP-NP-Out-TCP'")
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT DisplayName, InstanceID, Direction, Action, Enabled FROM MSFT_NetFirewallRule")
        firewall_RuleRecord = {}
        while True:
            try:
                tmp_dict = {}
                firewall_RuleClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = firewall_RuleClass.getProperties()
                record = dict(record)
                tmp_dict['DisplayName'] = record['DisplayName']['value'] 
                tmp_dict['Direction'] = "Inbound" if record['Direction']['value'] == 1 else "Outbound"
                tmp_dict['Action'] = "Allow" if record['Action']['value'] == 2 else ("AllowBypass" if record['Action']['value'] == 3 else "Block")
                tmp_dict['Status'] = "Enabled" if record['Enabled']['value'] == 1 else "Disabled"
                firewall_RuleRecord[record['InstanceID']['value']] = tmp_dict
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    pass
                else:
                    break
        
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT InstanceID, LocalPort, Protocol, RemotePort FROM MSFT_NetProtocolPortFilter")
        firewall_RuleDetailRecord = {}
        while True:
            try:
                tmp_dict = {}
                firewall_PortClass = iEnumWbemClassObject.Next(0xffffffff,1)[0]
                record = firewall_PortClass.getProperties()
                record = dict(record)
                tmp_dict['Protocol'] = record['Protocol']['value']
                tmp_dict['LocalPort'] = record['LocalPort']['value']
                tmp_dict['RemotePort'] = record['RemotePort']['value']
                firewall_RuleDetailRecord[record['InstanceID']['value']] = tmp_dict
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    pass
                else:
                    break
        
        test = dict(firewall_RuleDetailRecord, **firewall_RuleRecord)
        for key in test.keys():
            if key in firewall_RuleDetailRecord:
                test[key] = dict(test[key], **firewall_RuleDetailRecord[key])