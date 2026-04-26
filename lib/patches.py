import struct
from struct import pack, calcsize


def patch_impacket_wmi():
    """对 impacket WMI 模块进行运行时补丁:

    1. ENCODED_VALUE.getValue: 加速 uint8 数组 (CIM_TYPE 0x2011) 处理
    2. addNewAttribute: 支持 qualifiers 参数 (list), 标记属性 qualifier
    3. __createCimTypeQualifierSet -> __buildPropertyQualifierSet: 支持多 qualifier 构建
    4. marshalMe: 解包 4 元素 tuple 并传递 qualifiers
    5. callMethod: kwargs 形式的 WMI method 呼叫, 未提供的 InParams 以 NdTable=null
       标记 (等价 wmic 行为), 避免 singleton class 大 Set 方法被迫全参数覆写。
       以 `cls.callMethod("Set", Foo=1, Bar=2)` 呼叫。
    6. createMethods-bound dispatcher: 对 class object 自动绑定的方法加一层分派:
       - 纯 kwargs → callMethod
       - 其它 → impacket 原 positional 路径 (保持 StdRegProv.SetDWORDValue 等相容)
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

    # === 补丁 5: callMethod(methodName, **kwargs) — partial-params 呼叫 ===
    from impacket.dcerpc.v5.dcom.wmi import (
        OBJECT_BLOCK, INSTANCE_TYPE, HEAP, ENCODING_UNIT,
        OBJREF_CUSTOM, CLSID_WbemClassObject,
        CIM_TYPES_REF, HEAPREF, Inherited, CIM_INSTANCE,
    )

    _SCALAR_HEAP_TYPES = {
        CIM_TYPE_ENUM.CIM_TYPE_STRING.value,
        CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
        CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value,
    }

    def _callMethod(self, methodName, **kwargs):
        """以 kwargs 呼叫 WMI 方法,只送指定的 InParams。

        未指定的 InParam 于 NdTable 标记为 null (bit pair = 0b10),remote 端视为
        "未提供" 保持原有状态。行为对齐 wmic `path CLS call M foo=1`。

        已支援型別: BOOL / 各宽度 UINT / SINT / 各宽度 REAL / STRING / DATETIME /
        REFERENCE / 以及上述之 CIM_ARRAY_FLAG 变体。未支援: CIM_TYPE_OBJECT
        (嵌入对象),传入该型别 kwarg 会 raise NotImplementedError。

        Note: 仅对 class object (GetObject 取得) 呼叫 class-level 静态方法。
        """
        methods = self.getMethods()
        if methodName not in methods:
            raise AttributeError(f"Method {methodName!r} not found on {self.getClassName()}")
        method_def = methods[methodName]
        in_params = method_def.get("InParams") or {}

        value_table = b''
        nd_table_int = 0
        instance_heap = b''

        params_class_name = ENCODED_STRING()
        params_class_name['Character'] = '__PARAMETERS'
        instance_heap += params_class_name.getData()
        cur_heap = len(instance_heap)

        for idx, (pname, pdef) in enumerate(in_params.items()):
            raw_type = pdef['type']
            ptype = raw_type & ~(CIM_ARRAY_FLAG | Inherited)
            is_array = bool(raw_type & CIM_ARRAY_FLAG)

            slot_fmt = HEAPREF[:-2] if is_array else CIM_TYPES_REF[ptype][:-2]
            slot_w = calcsize(slot_fmt)

            if pname not in kwargs:
                value_table += b'\x00' * slot_w
                # NdTable: 2 bits/param, 0b10 = null (not provided)
                nd_table_int |= (2 << (idx * 2))
                continue

            val = kwargs[pname]
            if is_array:
                if val is None or len(val) == 0:
                    value_table += pack(slot_fmt, 0)
                elif ptype in _SCALAR_HEAP_TYPES:
                    items = []
                    for sv in val:
                        s = ENCODED_STRING()
                        if isinstance(sv, str):
                            s['Encoded_String_Flag'] = 0x1
                            s.structure = s.tunicode
                            s['Character'] = sv.encode('utf-16le')
                        else:
                            s['Character'] = sv
                        items.append(s.getData())
                    n = len(items)
                    array_size = pack(HEAPREF[:-2], n)
                    cur_str_ptr = cur_heap + 4
                    heap_refs = b''
                    payload = b''
                    for j, it in enumerate(items):
                        heap_refs += pack('<L', cur_str_ptr + 4 * (n - j) + len(payload))
                        payload += it
                        cur_str_ptr += 4
                    value_table += pack('<L', cur_heap)
                    instance_heap += array_size + heap_refs + payload
                    cur_heap = len(instance_heap)
                else:
                    elem_fmt = CIM_TYPES_REF[ptype][:-2]
                    value_table += pack('<L', cur_heap)
                    instance_heap += pack(HEAPREF[:-2], len(val))
                    for e in val:
                        instance_heap += pack(elem_fmt, e)
                    cur_heap = len(instance_heap)
            elif ptype in _SCALAR_HEAP_TYPES:
                s = ENCODED_STRING()
                if isinstance(val, str):
                    s['Encoded_String_Flag'] = 0x1
                    s.structure = s.tunicode
                    s['Character'] = val.encode('utf-16le')
                else:
                    s['Character'] = val
                value_table += pack('<L', cur_heap)
                instance_heap += s.getData()
                cur_heap = len(instance_heap)
            elif ptype == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                raise NotImplementedError(
                    "CIM_TYPE_OBJECT (embedded instance) params not supported by callMethod"
                )
            else:
                if ptype == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value:
                    val = 1 if val else 0
                value_table += pack(slot_fmt, val)

        num = len(in_params)
        nd_bytes = (num * 2 + 7) // 8
        packed_nd = b''
        n = nd_table_int
        for _ in range(nd_bytes):
            packed_nd += pack('B', n & 0xff)
            n >>= 8

        instance_type = INSTANCE_TYPE()
        instance_type['CurrentClass'] = b''
        instance_type['InstanceQualifierSet'] = b'\x04\x00\x00\x00\x01'
        instance_type['NdTable_ValueTable'] = packed_nd + value_table

        heap_rec = HEAP()
        heap_rec['HeapLength'] = len(instance_heap) | 0x80000000
        heap_rec['HeapItem'] = instance_heap
        instance_type['InstanceHeap'] = heap_rec

        # Match createMethods ordering: compute EncodingLength BEFORE assigning the
        # real CurrentClass; CurrentClass bytes are appended trailing.
        instance_type['EncodingLength'] = len(instance_type)
        class_part = method_def['InParamsRaw']['ClassType']['CurrentClass']['ClassPart']
        class_part['ClassHeader']['EncodingLength'] = len(class_part.getData())
        instance_type['CurrentClass'] = class_part

        obj_block = OBJECT_BLOCK()
        obj_block.structure += OBJECT_BLOCK.instanceType
        obj_block['ObjectFlags'] = CIM_INSTANCE
        obj_block['Decoration'] = b''
        obj_block['InstanceType'] = instance_type.getData()

        enc = ENCODING_UNIT()
        enc['ObjectBlock'] = obj_block
        enc['ObjectEncodingLength'] = len(obj_block)

        objref = OBJREF_CUSTOM()
        objref['iid'] = self._iid
        objref['clsid'] = CLSID_WbemClassObject
        objref['cbExtension'] = 0
        objref['ObjectReferenceSize'] = len(enc)
        objref['pObjectData'] = enc

        ws = self._IWbemClassObject__iWbemServices
        try:
            return ws.ExecMethod(self.getClassName(), methodName, pInParams=objref)
        except TypeError as e:
            # impacket ExecMethod fails to parse OutParams for certain methods whose
            # response payload is a flat byte blob (e.g. methods returning only
            # uint32 ReturnValue). The RPC itself succeeded — swallow the parsing
            # error and return None; caller verifies via subsequent query.
            if "byte indices must be integers" in str(e):
                return None
            raise

    IWbemClassObject.callMethod = _callMethod

    # === 补丁 6: createMethods 绑定的方法支援 kwargs 语法 ===
    #
    # impacket 的 createMethods 为 class object 自动绑定方法,
    # 只接受全部 InParams 的 positional。这里 post-wrap 成 dispatcher,
    # 支援两种呼叫形式:
    #   (a) cls.Set(Foo=1, Bar=2)     — Python kwargs, 路由到 patch 5 callMethod,
    #                                   未指定 InParam 自动 NdTable=null
    #   (b) cls.Method(a, b, c, ...)  — 原有 positional 不变 (StdRegProv 等沿用)

    _orig_createMethods = IWbemClassObject.createMethods

    def _wrapped_createMethods(self, classOrInstance, methods):
        _orig_createMethods(self, classOrInstance, methods)

        for methodName in methods:
            original = getattr(self, methodName)

            def _make_dispatcher(mname, orig):
                def dispatcher(*args, **kwargs):
                    if kwargs and not args:
                        return self.callMethod(mname, **kwargs)
                    return orig(*args)

                dispatcher.__name__ = mname
                return dispatcher

            setattr(self, methodName, _make_dispatcher(methodName, original))

    IWbemClassObject.createMethods = _wrapped_createMethods
