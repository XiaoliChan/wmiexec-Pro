import logging
from impacket.dcerpc.v5.dtypes import NULL, NDRPOINTERNULL

class user_Toolkit:
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
    
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

    def test(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        #wql='select * from Win32_UserAccount where Name="xiaoli"'
        #iEnumWbemClassObject = iWbemServices.ExecQuery(wql)
        #user_Class = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
        user_Class, _ = iWbemServices.GetObject('Win32_UserAccount.Domain="XIAOLI",Name="xiaoli"')
        record = user_Class.getProperties()
        record = dict(record)
        user_account=user_Class.SpawnInstance()
        user_account.AccountType=512
        user_account.Caption=record['Caption']['value']
        user_account.Description=""
        user_account.Disabled=False
        user_account.Domain=record['Domain']['value']
        user_account.FullName=record['FullName']['value']
        user_account.InstallDate=""
        user_account.LocalAccount=False
        user_account.Lockout=False
        user_account.Name=record['Name']['value']
        user_account.PasswordChangeable=True
        user_account.PasswordExpires=True
        user_account.PasswordRequired = True
        user_account.SID=record['SID']['value']
        user_account.SIDType=1
        user_account.Status="OK"
        self.checkError(iWbemServices.PutInstance(user_account.marshalMe()))

    def test2(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        classObject,_ = iWbemServices.GetObject('Win32_BaseService')
        obj = classObject.Create(
         r"test", 
         r"Personnel Database", 
         r'c:\windows\system32\cmd.exe', 
         16,
         2,
         r"Automatic",
         True,
         "",
         "",
         "",
         "",
         ""
         )
        print(obj.getProperties())
        #"DbService", "Personnel Database", _"c:\windows\system32\db.exe", OWN_PROCESS ,2 ,"Automatic" , _ NOT_INTERACTIVE ,".\LocalSystem" ,""
        #(
        # Name="DbServiceAAAAAAAAAAAAAAA", 
        # DisplayName="Personnel Database", 
        # PathName="c:\windows\system32\cmd.exe", 
        # ServiceType=16,
        # ErrorControl=2,
        # StartMode="Automatic",
        # DesktopInteract=True,
        # StartName="",
        # StartPassword="",
        # LoadOrderGroup="",
        # LoadOrderGroupDependencies="",
        # ServiceDependencies=""
        # )
        #(Name, DisplayName, PathName, ServiceType, ErrorControl, StartMode, DesktopInteract, StartName, StartPassword, LoadOrderGroup, LoadOrderGroupDependencies, ServiceDependencies)

    def test3(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        classObject,_ = iWbemServices.GetObject('Win32_Service')
        class_instance = classObject.SpawnInstance()
        class_instance.Name="Haha"
        class_instance.AcceptPause = False
        class_instance.AcceptStop = False
        class_instance.Caption = "HaHA"
        class_instance.CheckPoint = 0
        class_instance.CreationClassName = "Win32_Service"
        class_instance.DelayedAutoStart = False
        class_instance.Description = "haha"
        class_instance.DesktopInteract = False
        class_instance.DisplayName = "jkashxmska"
        class_instance.ErrorControl = "Normal"
        class_instance.ExitCode = 1077
        class_instance.InstallDate = ""
        class_instance.PathName = r"C:\Windows\System32\svchost.exe -k AppReadiness -p"
        class_instance.ProcessId = 0
        class_instance.ServiceSpecificExitCode = 0
        class_instance.ServiceType = "Share Process"
        class_instance.Started = False
        class_instance.StartMode = "Manual"
        class_instance.StartName = "LocalSystem"
        class_instance.State = "Stopped"
        class_instance.Status = "OK"
        class_instance.SystemCreationClassName = "Win32_ComputerSystem"
        class_instance.SystemName = "DC-2019"
        class_instance.TagId = 0
        class_instance.WaitHint = 0
        self.checkError(iWbemServices.PutInstance(class_instance.marshalMe()))