from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY

class RDP_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def rdp_Wrapper(self, flag, old=False):
        if old == False:
            # According to this document: https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tslogonsetting
            # Authentication level must set to RPC_C_AUTHN_LEVEL_PKT_PRIVACY when accessing namespace "//./root/cimv2/TerminalServices"
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2/TerminalServices', NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
            if flag == 'enable':
                print("[+] Enabling RDP services and setting up firewall.")
                iWbemClassObject.SetAllowTSConnections(1,1)
                self.query_RDPPort()
            elif flag == 'disable':
                print("[+] Disabling RDP services and setting up firewall.")
                iWbemClassObject.SetAllowTSConnections(0,0)
            else:
                print("[-] Error action!")
        else:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
            if flag == 'enable':
                print("[+] Enabling RDP services (old system not support setting up firewall)")
                iWbemClassObject.SetAllowTSConnections(1)
                self.query_RDPPort()
            elif flag == 'disable':
                print("[+] Disabling RDP services (old system not support setting up firewall)")
                iWbemClassObject.SetAllowTSConnections(0)
            else:
                print("[-] Error action!")
        iWbemServices.RemRelease()
        # Need to create new iWbemServices interface in order to flush results
        self.query_RDPResult(old)
        
    def query_RDPResult(self, old=False):
        if old == False:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2/TerminalServices', NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
            result = dict(iWbemClassObject.getProperties())
            result = result['AllowTSConnections']['value']
            if result == 0:
                print("[+] RDP disabled!")
            else:
                print("[+] RDP enabled!")
        else:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
            iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM Win32_TerminalServiceSetting")
            iWbemClassObject = iEnumWbemClassObject.Next(0xffffffff,1)[0]
            result = dict(iWbemClassObject.getProperties())
            result = result['AllowTSConnections']['value']
            if result == 0:
                print("[+] RDP disabled!")
            else:
                print("[+] RDP enabled!")
        iWbemServices.RemRelease()

    def query_RDPPort(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/DEFAULT', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        out = StdRegProv.GetDWORDValue(2147483650, 'SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'PortNumber')
        print("[+] RDP port: " + str(out.uValue))
        iWbemServices.RemRelease()

    # Nt version under 6 not support this.
    def ram_Wrapper(self, flag):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        if flag == 'enable':
            print("[+] Enabling Restricted Admin Mode.")
            StdRegProv.SetDWORDValue(2147483650, 'System\\CurrentControlSet\\Control\\Lsa', 'DisableRestrictedAdmin', 0)
        elif flag == 'disable':
            print("[+] Disabling Restricted Admin Mode (Clear).")
            StdRegProv.DeleteValue(2147483650, 'System\\CurrentControlSet\\Control\\Lsa', 'DisableRestrictedAdmin')
        out = StdRegProv.GetDWORDValue(2147483650, 'System\\CurrentControlSet\\Control\\Lsa', 'DisableRestrictedAdmin')
        if out.uValue == 0:
            print("[+] Restricted Admin Mode enabled!")
        elif out.uValue == None:
            print("[+] Restricted Admin Mode disabled!")
        iWbemServices.RemRelease()