import struct


def patch_impacket_wmi():
    """对 impacket WMI 模块进行运行时补丁:

    1. ENCODED_VALUE.getValue: 加速 uint8 数组 (CIM_TYPE 0x2011) 处理
    2. addNewAttribute: 支持 qualifiers 参数 (list), 标记属性 qualifier
    3. __createCimTypeQualifierSet -> __buildPropertyQualifierSet: 支持多 qualifier 构建
    4. marshalMe: 解包 4 元素 tuple 并传递 qualifiers
    """
    from impacket.dcerpc.v5.dcom.wmi import (
        ENCODED_VALUE, IWbemClassObject,
        QUALIFIER, QUALIFIER_SET, DICTIONARY_REFERENCE_TO_VALUE,
        CIM_TYPE_ENUM, CIM_TYPES_REF, CIM_ARRAY_FLAG,
        ENCODED_STRING, CIM_TYPE_TO_NAME,
    )

    # === 补丁 1: 加速 uint8 数组读取 ===
    _original_getValue = ENCODED_VALUE.getValue

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
                return _original_getValue(cimType, entry, heap)
        return _original_getValue(cimType, entry, heap)

    ENCODED_VALUE.getValue = _fast_getValue

    # === 补丁 2: addNewAttribute 支持 qualifiers 列表 ===
    _original_addNewAttribute = IWbemClassObject.addNewAttribute

    def _patched_addNewAttribute(self, name, type, default_value=None, qualifiers=None):
        """扩展 addNewAttribute, 支持 qualifiers 参数。

        Args:
            qualifiers: list of qualifier names (全部视为 boolean True),
                        e.g. ["key"], ["key", "read"]
        """
        # 原始逻辑: 检查非 instance + 追加 + setattr
        if not self.encodingUnit['ObjectBlock'].isInstance():
            self._IWbemClassObject__new_attributes.append(
                (name, type, default_value, qualifiers or [])
            )
            setattr(self, name, default_value)
        else:
            raise Exception("Cannot add new attribute to an instance object.")

    IWbemClassObject.addNewAttribute = _patched_addNewAttribute

    # === 补丁 3: __buildPropertyQualifierSet 替代 __createCimTypeQualifierSet ===
    def _buildPropertyQualifierSet(self, heap, propertyInfo, qualifiers=None):
        """构建属性的 QUALIFIER_SET。

        始终包含 CIMTYPE qualifier, 额外 qualifier 从 qualifiers 列表追加 (全部 boolean True)。
        """
        propertyInfo['PropertyQualifierSet'] = b''

        # 1. CIMTYPE qualifier (必须)
        cimtype_qual = QUALIFIER()
        cimtype_qual['QualifierName'] = DICTIONARY_REFERENCE_TO_VALUE['CIMTYPE'] | 0x80000000
        cimtype_qual['QualifierFlavor'] = 0
        cimtype_qual['QualifierType'] = CIM_TYPE_ENUM.CIM_TYPE_STRING.value
        cimtype_qual.structure = (
            ('QualifierValue', CIM_TYPES_REF[cimtype_qual['QualifierType'] & (~CIM_ARRAY_FLAG)]),
        )

        # 2. 额外 qualifier (全部 boolean True)
        extra_data = b''
        for qname in (qualifiers or []):
            q = QUALIFIER()
            q['QualifierName'] = DICTIONARY_REFERENCE_TO_VALUE[qname] | 0x80000000
            q['QualifierFlavor'] = 0
            q['QualifierType'] = CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value
            q.structure = (
                ('QualifierValue', CIM_TYPES_REF[CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value & (~CIM_ARRAY_FLAG)]),
            )
            q['QualifierValue'] = 0xFFFF
            extra_data += q.getData()

        # 3. 组装 QUALIFIER_SET
        qualifierSet = QUALIFIER_SET()
        qualifierSet['Qualifier'] = cimtype_qual.getData() + extra_data
        qualifierSet['EncodingLength'] = len(qualifierSet.getData())

        # 修正 CIMTYPE.QualifierValue 指向 heap 中的类型字符串
        cimtype_qual['QualifierValue'] = len(heap) + len(propertyInfo) + len(qualifierSet.getData())
        qualifierSet['Qualifier'] = cimtype_qual.getData() + extra_data

        cimTypeString = ENCODED_STRING()
        cimTypeString['Character'] = CIM_TYPE_TO_NAME[propertyInfo['PropertyType']]
        return (qualifierSet, cimTypeString)

    IWbemClassObject._IWbemClassObject__createCimTypeQualifierSet = _buildPropertyQualifierSet

    # === 补丁 4: marshalMe 解包 4 元素 tuple + 传递 qualifiers ===
    _original_marshalMe = IWbemClassObject.marshalMe

    def _patched_marshalMe(self):
        if not (hasattr(self, '_IWbemClassObject__new_attributes') and self._IWbemClassObject__new_attributes):
            return _original_marshalMe(self)

        # 检查 tuple 是否已经是 4 元素 (补丁后的格式)
        first = self._IWbemClassObject__new_attributes[0]
        if len(first) == 3:
            # 兼容未经补丁 addNewAttribute 添加的属性 (3 元素)
            return _original_marshalMe(self)

        # 4 元素 tuple: 需要提取 qualifiers 并缩减为 3 元素
        # 原始 marshalMe 内部按属性名排序后逐个解包 (name, type, default_value)
        sorted_attrs = sorted(self._IWbemClassObject__new_attributes, key=lambda x: x[0])
        qualifiers_queue = [attr[3] for attr in sorted_attrs]
        call_count = [0]

        # 将 __new_attributes 缩减为 3 元素 tuple，原始 marshalMe 才能解包
        original_attrs = self._IWbemClassObject__new_attributes
        self._IWbemClassObject__new_attributes = [(a[0], a[1], a[2]) for a in original_attrs]

        _real_createQS = self._IWbemClassObject__createCimTypeQualifierSet

        def _intercepted_createQS(heap, propertyInfo):
            if call_count[0] < len(qualifiers_queue):
                quals = qualifiers_queue[call_count[0]]
                call_count[0] += 1
            else:
                quals = []
            return _real_createQS(heap, propertyInfo, qualifiers=quals)

        # 临时替换为拦截器
        old = self._IWbemClassObject__createCimTypeQualifierSet
        self._IWbemClassObject__createCimTypeQualifierSet = _intercepted_createQS
        try:
            result = _original_marshalMe(self)
        finally:
            self._IWbemClassObject__createCimTypeQualifierSet = old
            self._IWbemClassObject__new_attributes = original_attrs
        return result

    IWbemClassObject.marshalMe = _patched_marshalMe
