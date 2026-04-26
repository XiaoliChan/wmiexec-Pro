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
                       help="Action: check (show status), disable/enable (all core protection features), "
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
            toolkit.set_core_protection(False)
        elif options.action == "enable":
            toolkit.set_core_protection(True)
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

    # Enum decoders for non-boolean protection settings.
    _MAPS_REPORTING = {0: "Disabled", 1: "Basic", 2: "Advanced"}
    _SUBMIT_CONSENT = {0: "AlwaysPrompt", 1: "SendSafe", 2: "NeverSend", 3: "SendAll"}
    _PUA_PROTECTION = {0: "Disabled", 1: "Enabled", 2: "AuditMode"}

    def _print_protection(self, props):
        self.logger.log(100, "=== Defender Protection Status ===")
        for field in self.PROTECTION_FIELDS:
            value = props.get(field, {}).get("value", "N/A")
            if isinstance(value, str):
                value = (value == "True") if value in ("True", "False") else value
            status = "DISABLED" if value is True else ("ENABLED" if value is False else str(value))
            self.logger.log(100, f"  {field}: {status}")

        cloud_decoders = [
            ("MAPSReporting", self._MAPS_REPORTING),
            ("SubmitSamplesConsent", self._SUBMIT_CONSENT),
            ("PUAProtection", self._PUA_PROTECTION),
        ]
        for field, decoder in cloud_decoders:
            raw = props.get(field, {}).get("value", None)
            label = decoder.get(raw, "N/A" if raw is None else str(raw))
            self.logger.log(100, f"  {field}: {label} ({raw})")

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

        self._print_protection(props)

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

    # Core protection booleans — True means that feature is disabled.
    PROTECTION_FIELDS = [
        "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        "DisableBlockAtFirstSeen",
        "DisableIntrusionPreventionSystem",
        "DisableArchiveScanning",
        "DisableRemovableDriveScanning",
        "DisableEmailScanning",
        "DisableScanningNetworkFiles",
    ]

    # Cloud / PUA enum overrides. Disable → minimum protection; enable → Microsoft defaults.
    CLOUD_FIELDS_DISABLE = {"MAPSReporting": 0, "SubmitSamplesConsent": 2, "PUAProtection": 0}
    CLOUD_FIELDS_ENABLE = {"MAPSReporting": 2, "SubmitSamplesConsent": 1, "PUAProtection": 1}

    def set_core_protection(self, enable):
        """Toggle all core Defender protection features via MSFT_MpPreference.Set.

        MSFT_MpPreference is a singleton class without a key property, so Set must be
        invoked as a class-level method. Uses patches.py patch #5 (callMethod) to
        send only the targeted InParams — unspecified params are marked null via
        NdTable, preserving existing Defender configuration (equivalent to
        `wmic ... call Set <field>=<value>` semantics).
        """
        action_str = "Enabling" if enable else "Disabling"
        self.logger.info(f"{action_str} core protection features...")

        overrides = {}
        for field in self.PROTECTION_FIELDS:
            overrides[field] = not enable
        overrides.update(self.CLOUD_FIELDS_ENABLE if enable else self.CLOUD_FIELDS_DISABLE)

        try:
            iWbemServices = self._connect()
            MpPreference, _ = iWbemServices.GetObject("MSFT_MpPreference")
            #MpPreference.Set("DisableRealtimeMonitoring=True")
            MpPreference.Set(**overrides)
            self.logger.info("Set method executed.")
        except Exception as e:
            self.logger.error(f"Failed to modify protection settings: {e!s}")
            return

        try:
            self.logger.info("Verifying...")
            _, props = self._get_preferences(iWbemServices)
            self._print_protection(props)
        except Exception:
            self.logger.log(100, "Settings applied (unable to verify).")

    def _exclusion_kwargs(self, path, process, extension):
        kwargs = {}
        if path:
            kwargs["ExclusionPath"] = [path]
        if process:
            kwargs["ExclusionProcess"] = [process]
        if extension:
            kwargs["ExclusionExtension"] = [extension]
        return kwargs

    def add_exclusion(self, path=None, process=None, extension=None):
        """Add exclusion path, process, or extension via MSFT_MpPreference.Add."""
        if not any([path, process, extension]):
            self.logger.error("Specify at least one of -path, -process, or -extension.")
            return

        try:
            iWbemServices = self._connect()
            MpPreference, _ = iWbemServices.GetObject("MSFT_MpPreference")
            for label, value in [("path", path), ("process", process), ("extension", extension)]:
                if value:
                    self.logger.info(f"Adding exclusion {label}: {value}")
            MpPreference.Add(**self._exclusion_kwargs(path, process, extension))
            self.logger.log(100, "Exclusion added successfully!")
        except Exception as e:
            self.logger.error(f"Failed to add exclusion: {e!s}")

    def remove_exclusion(self, path=None, process=None, extension=None):
        """Remove exclusion path, process, or extension via MSFT_MpPreference.Remove."""
        if not any([path, process, extension]):
            self.logger.error("Specify at least one of -path, -process, or -extension.")
            return

        try:
            iWbemServices = self._connect()
            MpPreference, _ = iWbemServices.GetObject("MSFT_MpPreference")
            for label, value in [("path", path), ("process", process), ("extension", extension)]:
                if value:
                    self.logger.info(f"Removing exclusion {label}: {value}")
            MpPreference.Remove(**self._exclusion_kwargs(path, process, extension))
            self.logger.log(100, "Exclusion removed successfully!")
        except Exception as e:
            self.logger.error(f"Failed to remove exclusion: {e!s}")
