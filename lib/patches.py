import struct


def patch_impacket_wmi():
    """Patch ENCODED_VALUE.getValue for fast uint8 array (CIM_TYPE 0x2011) handling.

    The default impacket implementation processes large byte arrays element-by-element,
    which is extremely slow for large binary data (e.g. PS_ModuleFile.FileData).
    This patch directly slices the heap for uint8 arrays, reducing download time
    from minutes to seconds.

    Reference: https://github.com/0xthirteen/WMI_Proc_Dump
    """
    from impacket.dcerpc.v5.dcom.wmi import ENCODED_VALUE

    _original = ENCODED_VALUE.getValue

    @staticmethod
    def _fast_getValue(cimType, entry, heap):
        if cimType == 0x2011:  # CIM_UINT8 | CIM_ARRAY_FLAG
            try:
                if isinstance(entry, int):
                    heapOffset = entry
                else:
                    heapOffset = struct.unpack('<I', entry)[0]
                heapData = heap[heapOffset:]
                numItems = struct.unpack('<I', heapData[:4])[0]
                return heapData[4:4 + numItems]
            except Exception:
                return _original(cimType, entry, heap)
        return _original(cimType, entry, heap)

    ENCODED_VALUE.getValue = _fast_getValue
