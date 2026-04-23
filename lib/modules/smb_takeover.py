# Based on: https://github.com/zyn3rgy/smbtakeover
# Credit: @zyn3rgy

import logging

from lib.modules.service_mgr import Service_Toolkit
from lib.module_base import ModuleBase


class SMBTakeover_Toolkit(ModuleBase):
    name = "smb-takeover"
    description = "SMB service takeover (stop/start LanmanServer to release/bind port 445)."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(SMBTakeover_Toolkit.name, help=SMBTakeover_Toolkit.description)
        p.add_argument("-action", action="store", choices=["check", "stop", "start"], required=True,
                       help="Action: check (show SMB services status), stop (release port 445), start (restore SMB services).")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = SMBTakeover_Toolkit(iWbemLevel1Login, dcom)
        if options.action == "check":   toolkit.check()
        elif options.action == "stop":  toolkit.stop()
        elif options.action == "start": toolkit.start()

    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.logger = logging.getLogger("wmiexec-pro")
        self.service_toolkit = Service_Toolkit(iWbemLevel1Login, dcom)

    def check(self):
        """Check SMB-related services status (LanmanServer, srv2, srvnet)."""
        self.logger.info("Checking SMB-related services...")
        self.service_toolkit.control_Service("getinfo", "LanmanServer")
        self.service_toolkit.control_Service("getinfo", "srv2")
        self.service_toolkit.control_Service("getinfo", "srvnet")

    def stop(self):
        """Stop SMB services to release port 445: disable+stop LanmanServer, stop srv2, stop srvnet."""
        self.logger.info("Disabling and stopping SMB services...")
        self.service_toolkit.control_Service("disable", "LanmanServer")
        self.service_toolkit.control_Service("stop", "LanmanServer")
        self.service_toolkit.control_Service("stop", "srv2")
        self.service_toolkit.control_Service("stop", "srvnet")
        self.logger.log(100, "Port 445 should now be released!")

    def start(self):
        """Restore SMB services: auto-start+start LanmanServer."""
        self.logger.info("Restoring SMB services...")
        self.service_toolkit.control_Service("auto-start", "LanmanServer")
        self.service_toolkit.control_Service("start", "LanmanServer")
        self.logger.log(100, "LanmanServer restored!")
