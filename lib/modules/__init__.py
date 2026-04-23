from lib.modules.enumrate import ENUM
from lib.modules.amsi import AMSI
from lib.modules.exec_command import EXEC_COMMAND
from lib.modules.filetransfer import filetransfer_Toolkit
from lib.modules.rdp import RDP_Toolkit
from lib.modules.winrm import WINRM_Toolkit
from lib.modules.firewall import Firewall_Toolkit
from lib.modules.eventlog_fucker import eventlog_Toolkit
from lib.modules.service_mgr import Service_Toolkit
from lib.modules.smb_takeover import SMBTakeover_Toolkit
from lib.modules.processdump import ProcessDump_Toolkit
from lib.modules.rid_hijack import RID_Hijack_Toolkit
from lib.modules.hashdump import Hashdump
from lib.modules.defender import Defender_Toolkit
from lib.methods.executeScript import executeScript_Toolkit

MODULE_REGISTRY = [
    ENUM,
    AMSI,
    EXEC_COMMAND,
    filetransfer_Toolkit,
    RDP_Toolkit,
    WINRM_Toolkit,
    Firewall_Toolkit,
    eventlog_Toolkit,
    Service_Toolkit,
    SMBTakeover_Toolkit,
    ProcessDump_Toolkit,
    Defender_Toolkit,
    executeScript_Toolkit,
    RID_Hijack_Toolkit,
    Hashdump,
]

