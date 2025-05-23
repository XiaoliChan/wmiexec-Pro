import logging

from lib.methods.executeVBS import executeVBS_Toolkit
from lib.helpers import get_vbs_path


class eventlog_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def fuck_EventLog(self):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteVBS(vbs_file="lib/vbscripts/ClearEventlog.vbs", returnTag=True)
        self.logger.warning(f"Keepping note of this tag if you want to stop it: {tag}")
    
    def retrieve_EventLog(self, tag):
        executer = executeVBS_Toolkit(self.iWbemLevel1Login)
        executer.remove_Event(tag)
        self.logger.info("Stop fucking eventlog :)")