# Windows Defender management via MSFT_MpPreference
# Namespace: root/Microsoft/Windows/Defender
# Disable real-time monitoring: tested on Server 2019
# Exclusion management: broadly supported on systems with Defender

import logging

from lib.module_base import ModuleBase
from impacket.dcerpc.v5.dtypes import NULL


class Defender_Toolkit(ModuleBase):
    name = "defender"
    description = "Windows Defender management via MSFT_MpPreference."

    NAMESPACE = "//./root/Microsoft/Windows/Defender"

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(Defender_Toolkit.name, help=Defender_Toolkit.description)
        p.add_argument("-action", action="store", required=True,
                       choices=["check", "disable", "enable", "exclude", "remove"],
                       help="Action: check (show status), disable/enable (real-time monitoring), "
                            "exclude (add exclusion), remove (remove exclusion).")
        p.add_argument("-path", action="store", help="Exclusion directory path (e.g. C:\\temp).")
        p.add_argument("-process", action="store", help="Exclusion process name (e.g. mimikatz.exe).")
        p.add_argument("-extension", action="store", help="Exclusion file extension (e.g. exe).")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = Defender_Toolkit(iWbemLevel1Login)
        if options.action == "check":
            toolkit.check()
        elif options.action == "disable":
            toolkit.set_realtime_monitoring(False)
        elif options.action == "enable":
            toolkit.set_realtime_monitoring(True)
        elif options.action == "exclude":
            toolkit.add_exclusion(path=options.path, process=options.process, extension=options.extension)
        elif options.action == "remove":
            toolkit.remove_exclusion(path=options.path, process=options.process, extension=options.extension)

    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.logger = logging.getLogger("wmiexec-pro")

    def _connect(self):
        """Connect to Defender WMI namespace."""
        iWbemServices = self.iWbemLevel1Login.NTLMLogin(self.NAMESPACE, NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        return iWbemServices

    def _get_preferences(self, iWbemServices):
        """Get current MSFT_MpPreference instance and properties."""
        iEnumWbemClassObject = iWbemServices.ExecQuery("SELECT * FROM MSFT_MpPreference")
        obj = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
        return obj, dict(obj.getProperties())

    def check(self):
        """Query current Defender preferences and exclusions."""
        try:
            iWbemServices = self._connect()
        except Exception as e:
            self.logger.error(f"Failed to connect to Defender namespace: {e!s}")
            return

        try:
            _, props = self._get_preferences(iWbemServices)
        except Exception as e:
            self.logger.error(f"Failed to query MSFT_MpPreference: {e!s}")
            return

        # Protection status
        monitor_fields = [
            "DisableRealtimeMonitoring",
            "DisableBehaviorMonitoring",
            "DisableIOAVProtection",
            "DisableScriptScanning",
            "DisableBlockAtFirstSeen",
        ]
        self.logger.log(100, "=== Defender Protection Status ===")
        for field in monitor_fields:
            value = props.get(field, {}).get("value", "N/A")
            # True = disabled (bad from defender's perspective)
            status = "DISABLED" if value is True else ("ENABLED" if value is False else str(value))
            self.logger.log(100, f"  {field}: {status}")

        # Exclusions
        exclusion_fields = [
            ("ExclusionPath", "Excluded Paths"),
            ("ExclusionProcess", "Excluded Processes"),
            ("ExclusionExtension", "Excluded Extensions"),
        ]
        self.logger.log(100, "\n=== Exclusions ===")
        for field, label in exclusion_fields:
            values = props.get(field, {}).get("value", None)
            if values:
                if isinstance(values, list):
                    for v in values:
                        self.logger.log(100, f"  [{label}] {v}")
                else:
                    self.logger.log(100, f"  [{label}] {values}")
            else:
                self.logger.info(f"  [{label}] (none)")

    def set_realtime_monitoring(self, enable):
        """Enable or disable real-time monitoring via DisableRealtimeMonitoring property."""
        action_str = "Enabling" if enable else "Disabling"
        self.logger.info(f"{action_str} real-time monitoring...")

        try:
            iWbemServices = self._connect()
            obj, props = self._get_preferences(iWbemServices)

            instance = obj.SpawnInstance()
            instance.DisableRealtimeMonitoring = not enable

            iWbemServices.PutInstance(instance.marshalMe())
        except Exception as e:
            self.logger.error(f"Failed to modify real-time monitoring: {e!s}")
            return

        # Verify
        try:
            _, props = self._get_preferences(iWbemServices)
            current = props.get("DisableRealtimeMonitoring", {}).get("value")
            if current == (not enable):
                self.logger.log(100, f"Real-time monitoring {'disabled' if not enable else 'enabled'} successfully!")
            else:
                self.logger.warning(f"DisableRealtimeMonitoring is now: {current} (may need Tamper Protection off)")
        except Exception:
            self.logger.log(100, "Setting applied (unable to verify).")

    def add_exclusion(self, path=None, process=None, extension=None):
        """Add exclusion path, process, or extension."""
        if not any([path, process, extension]):
            self.logger.error("Specify at least one of -path, -process, or -extension.")
            return

        try:
            iWbemServices = self._connect()
            obj, props = self._get_preferences(iWbemServices)

            instance = obj.SpawnInstance()
            modified = False

            if path:
                current = props.get("ExclusionPath", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if path not in current:
                    current.append(path)
                    instance.ExclusionPath = current
                    modified = True
                    self.logger.info(f"Adding exclusion path: {path}")
                else:
                    self.logger.warning(f"Path already excluded: {path}")

            if process:
                current = props.get("ExclusionProcess", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if process not in current:
                    current.append(process)
                    instance.ExclusionProcess = current
                    modified = True
                    self.logger.info(f"Adding exclusion process: {process}")
                else:
                    self.logger.warning(f"Process already excluded: {process}")

            if extension:
                current = props.get("ExclusionExtension", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if extension not in current:
                    current.append(extension)
                    instance.ExclusionExtension = current
                    modified = True
                    self.logger.info(f"Adding exclusion extension: {extension}")
                else:
                    self.logger.warning(f"Extension already excluded: {extension}")

            if modified:
                iWbemServices.PutInstance(instance.marshalMe())
                self.logger.log(100, "Exclusion added successfully!")
        except Exception as e:
            self.logger.error(f"Failed to add exclusion: {e!s}")

    def remove_exclusion(self, path=None, process=None, extension=None):
        """Remove exclusion path, process, or extension."""
        if not any([path, process, extension]):
            self.logger.error("Specify at least one of -path, -process, or -extension.")
            return

        try:
            iWbemServices = self._connect()
            obj, props = self._get_preferences(iWbemServices)

            instance = obj.SpawnInstance()
            modified = False

            if path:
                current = props.get("ExclusionPath", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if path in current:
                    current.remove(path)
                    instance.ExclusionPath = current if current else []
                    modified = True
                    self.logger.info(f"Removing exclusion path: {path}")
                else:
                    self.logger.warning(f"Path not in exclusion list: {path}")

            if process:
                current = props.get("ExclusionProcess", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if process in current:
                    current.remove(process)
                    instance.ExclusionProcess = current if current else []
                    modified = True
                    self.logger.info(f"Removing exclusion process: {process}")
                else:
                    self.logger.warning(f"Process not in exclusion list: {process}")

            if extension:
                current = props.get("ExclusionExtension", {}).get("value", None) or []
                if isinstance(current, str):
                    current = [current]
                if extension in current:
                    current.remove(extension)
                    instance.ExclusionExtension = current if current else []
                    modified = True
                    self.logger.info(f"Removing exclusion extension: {extension}")
                else:
                    self.logger.warning(f"Extension not in exclusion list: {extension}")

            if modified:
                iWbemServices.PutInstance(instance.marshalMe())
                self.logger.log(100, "Exclusion removed successfully!")
        except Exception as e:
            self.logger.error(f"Failed to remove exclusion: {e!s}")
