import logging


@staticmethod
def checkError(banner, resp):
    logger = logging.getLogger("wmiexec-pro")
    call_status = resp.GetCallStatus(0) & 0xffffffff  # interpret as unsigned
    if call_status != 0:
        from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
        try:
            error_name = WBEMSTATUS.enumItems(call_status).name
        except ValueError:
            error_name = "Unknown"
        logger.error(f"{banner} - ERROR: {error_name} {call_status:08x}")
    else:
        logger.info(f"{banner} - OK")