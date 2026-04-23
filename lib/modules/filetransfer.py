import logging
import base64
import struct
import time
import sys
import uuid
import ntpath

from lib.helpers import get_vbs
from lib.methods.classMethodEx import class_MethodEx
from lib.methods.executeScript import executeScript_Toolkit
from lib.module_base import ModuleBase
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class filetransfer_Toolkit(ModuleBase):
    name = "filetransfer"
    description = "Upload/Download file through wmi class."

    @staticmethod
    def register_parser(subparsers):
        p = subparsers.add_parser(filetransfer_Toolkit.name, help=filetransfer_Toolkit.description)
        p.add_argument("-upload", action="store_true", help="Upload file.")
        p.add_argument("-download", action="store_true", help="Download file.")
        p.add_argument("-src-file", action="store", help="Source file with fully path (include filename)")
        p.add_argument("-dest-file", action="store", help="Dest file with fully path (include filename)")
        p.add_argument("-method", action="store", choices=["native", "legacy"], default="native",
                       help="Download method: native (PS_ModuleFile, Win8+/2012+) or legacy (VBS+WMI class). Default: native with auto-fallback.")
        p.add_argument("-delete", action="store", metavar="FILEPATH", help="Delete remote file via CIM_DataFile.")
        p.add_argument("-clear", action="store_true", help="Remove temporary class for storage binary data")
        return p

    @staticmethod
    def run(iWbemLevel1Login, dcom, options, **kwargs):
        toolkit = filetransfer_Toolkit(iWbemLevel1Login, dcom)
        toolkit.timeout = options.timeout
        if options.src_file and options.dest_file:
            if options.upload:
                toolkit.uploadFile(src_File=options.src_file, dest_File=r"%s" % options.dest_file)
            if options.download:
                method = getattr(options, 'method', 'native')
                if method == "native":
                    success = toolkit.downloadFile_Native(target_File=options.src_file, save_Location=options.dest_file)
                    if not success:
                        logging.info("Falling back to legacy download method...")
                        toolkit.downloadFile(target_File=options.src_file, save_Location=options.dest_file)
                else:
                    toolkit.downloadFile(target_File=options.src_file, save_Location=options.dest_file)
        if options.delete:
            toolkit.deleteFile(target_File=options.delete)
        if options.clear:
            toolkit.clear()

    def __init__(self, iWbemLevel1Login, dcom):
        self.iWbemLevel1Login = iWbemLevel1Login
        self.dcom = dcom
        self.timeout = 5 # default timeout

        self.logger = logging.getLogger("wmiexec-pro")
        self.logger_countdown = logging.getLogger("CountdownLogger")

    def queryfile_Status(self, file, iWbemServices=None, return_iWbemServices=False):
        if not iWbemServices:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            self.iWbemLevel1Login.RemRelease()
        try:
            self.logger.info(f"Checking target file {file} info")
            file_obj, _ = iWbemServices.GetObject(f'CIM_DataFile.Name="{file}"')
            # For delete file
            # Reference: https://github.com/fortra/impacket/issues/1672
            # iWbemServices.DeleteInstance(f'CIM_DataFile.Name="{file}"')
        except Exception as e:
            if "WBEM_S_FALSE" in str(e):
                self.logger.error(f"File {file} not existed!")
            else:
                self.logger.error(f"Unexpected error when checking file: {file}, error: {e!s}")
            self.dcom.disconnect()
            sys.exit(0)
        else:
            file_Status = dict(file_obj.getProperties())
            self.logger.log(100, "File status: {}, File size: {} KB, File location: {}".format(
                file_Status["Status"]["value"],
                file_Status["FileSize"]["value"]/1024,
                file_Status["Caption"]["value"]
                )
            )
        
        # Return cimv2
        if return_iWbemServices:
            return iWbemServices
    
    # For upload file, we don't need to create class, we can make binary included in vbs script(file dropper).
    # After vbs interval job created, then release your file.
    def uploadFile(self, src_File, dest_File, iWbemServices_Subscription=None, iWbemServices_Cimv2=None):
        with open(src_File, "rb") as f:
            binary = f.read()
        binary_EncodeData = base64.b64encode(binary).decode("ascii")

        vbs = get_vbs("WriteFile.vbs")
        vbs = vbs.replace("REPLACE_WITH_DEST", base64.b64encode(dest_File.encode("utf-8")).decode("utf-8")).replace("REPLACE_WITH_DATA", binary_EncodeData)
        executer = executeScript_Toolkit(self.iWbemLevel1Login)

        self.logger.info("File uploading (will take a long time if you try to upload large size file)")
        
        tag = executer.ExecuteScript(script_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription)
        
        # Wait 5 seconds for windows decode file.
        for i in range(self.timeout, 0, -1):
            self.logger_countdown.info(f"Waiting {i}s for next step.\r")
            time.sleep(1)
        
        # Check dest file status, Cimv2
        self.queryfile_Status(dest_File.replace("\\", "\\\\"), iWbemServices=iWbemServices_Cimv2)
        
        # Clean up
        self.logger.info("Stop vbs interval execution after created class")
        executer.remove_Event(tag, iWbemServices=iWbemServices_Subscription)

    # For download file, we can write file data into wmi class
    def downloadFile(self, target_File, save_Location=None, ClassName_ForDownload=None, iWbemServices_Subscription=None, iWbemServices_Cimv2=None):
        class_Method = class_MethodEx(self.iWbemLevel1Login)
        # Default class name for download file
        if not ClassName_ForDownload:
            ClassName_ForDownload = "Win32_OSRecoveryConfigurationDataStorage"

        # Check target file status.
        # Reuse cimv2 iWbemServices object to avoid DCOM iWbemServices
        iWbemServices_Reuse = self.queryfile_Status(target_File.replace("\\", "\\\\"), return_iWbemServices=True, iWbemServices=iWbemServices_Cimv2)

        # Reuse cimv2 namespace
        self.logger.info("Create evil class for file transfer")
        class_Method.check_ClassStatus(ClassName=ClassName_ForDownload, iWbemServices_Cimv2=iWbemServices_Reuse, iWbemServices_Subscription=iWbemServices_Subscription)
        
        # Load target file into class
        self.logger.info("Converting file to base64 string and load it into wmi class.")
        Data_InstanceID = str(uuid.uuid4())

        vbs = get_vbs("LocalFileIntoClass.vbs")
        vbs = vbs.replace("REPLACE_WITH_TARGET_FILE", base64.b64encode(target_File.encode("utf-8")).decode("utf-8")).replace("RELEACE_WITH_UUID", Data_InstanceID).replace("REPLACE_WITH_CLASSNAME", ClassName_ForDownload)
        executer = executeScript_Toolkit(self.iWbemLevel1Login)
        tag = executer.ExecuteScript(script_content=vbs, returnTag=True, iWbemServices=iWbemServices_Subscription)
        
        # Wait 5 seconds for next step.
        for i in range(self.timeout, 0, -1):
            self.logger_countdown.info(f"Waiting {i}s for next step.\r")
            time.sleep(1)
        
        # Read encode data from wmi class
        self.logger.info("File downloading...")
        Data_Instance, resp = iWbemServices_Reuse.GetObject(f'{ClassName_ForDownload}.CreationClassName="{Data_InstanceID}"')
        record = dict(Data_Instance.getProperties())
        with open(save_Location, "wb") as f:
            f.write(base64.b64decode(record["DebugOptions"]["value"]))

        self.logger.log(100, f"File downloaded and save to: {save_Location}")

        self.logger.info("Stop vbs interval execution after file downloaded")
        executer.remove_Event(tag, iWbemServices=iWbemServices_Subscription)

    # Native download via PS_ModuleFile (root/Microsoft/Windows/Powershellv3)
    # Reference: https://github.com/0xthirteen/WMI_Proc_Dump
    # Reference: https://gist.github.com/mattifestation/03079a38f23e0c94c8cd39779f88adf6
    def downloadFile_Native(self, target_File, save_Location):
        """Download file via PS_ModuleFile.FileData (PSv3 namespace, no VBS needed)."""
        PSV3_NAMESPACE = "//./root/Microsoft/Windows/Powershellv3"

        try:
            iWbemServices = self.iWbemLevel1Login.NTLMLogin(PSV3_NAMESPACE, NULL, NULL)
            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()
        except Exception as e:
            if "WBEM_E_INVALID_NAMESPACE" in str(e):
                self.logger.error("PSv3 namespace not available (requires Win8+/Server2012+), falling back to legacy method.")
                return False
            else:
                raise

        escaped_path = target_File.replace("\\", "\\\\")
        try:
            self.logger.info(f"Downloading {target_File} via PS_ModuleFile...")
            file_instance, _ = iWbemServices.GetObject(f'PS_ModuleFile.InstanceID="{escaped_path}"')
        except Exception as e:
            self.logger.error(f"Failed to read file via PS_ModuleFile: {e!s}")
            return False

        props = file_instance.getProperties()
        file_data = props["FileData"]["value"]

        if not file_data:
            self.logger.error("FileData is empty!")
            return False

        # FileData format: first 4 bytes (big-endian reversed) = file length, then file content
        file_length_bytes = bytes(file_data[0:4])[::-1]
        file_length = int.from_bytes(file_length_bytes, byteorder='little', signed=False)
        file_bytes = bytes(file_data[4:file_length + 4])

        with open(save_Location, "wb") as f:
            f.write(file_bytes)

        self.logger.log(100, f"File downloaded and saved to: {save_Location}")
        return True

    def deleteFile(self, target_File, iWbemServices_Cimv2=None):
        """Delete remote file via CIM_DataFile."""
        if not iWbemServices_Cimv2:
            iWbemServices_Cimv2 = self.iWbemLevel1Login.NTLMLogin("//./root/Cimv2", NULL, NULL)
            iWbemServices_Cimv2.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            self.iWbemLevel1Login.RemRelease()

        escaped_path = target_File.replace("\\", "\\\\")
        try:
            file_obj, _ = iWbemServices_Cimv2.GetObject(f"CIM_DataFile.Name='{escaped_path}'")
            file_obj.Delete(escaped_path)
            self.logger.log(100, f"Remote file {target_File} deleted.")
        except Exception as e:
            self.logger.error(f"Failed to delete file: {e!s}")

    def clear(self, ClassName_StoreOutput=None):
        if not ClassName_StoreOutput:
            ClassName_StoreOutput = "Win32_OSRecoveryConfigurationDataStorage"

        class_Method = class_MethodEx(self.iWbemLevel1Login)
        class_Method.remove_Class(ClassName=ClassName_StoreOutput, return_iWbemServices_Cimv2=False)