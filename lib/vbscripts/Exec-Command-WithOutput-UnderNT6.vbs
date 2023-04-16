Dim time_zone
Dim exec_time
Dim results_save
results_save = "C:\Windows\Temp\REPLACE_WITH_FILENAME"

' Avoid execute command duplicated
If FileExists(results_save) Then
    Set inStream = CreateObject("ADODB.Stream")
    inStream.Open
    inStream.type= 1 'TypeBinary
    inStream.LoadFromFile(results_save)
    readBytes = inStream.Read()

    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = readBytes
    Base64Encode = oNode.text
    
    On Error Resume Next
    Set objTestNewInst = GetObject("Winmgmts:root\Cimv2:REPLACE_WITH_CLASSNAME.CreationClassName=""RELEACE_WITH_UUID""")
    If Err.Number <> 0 Then
        Err.Clear
        wbemCimtypeString = 8
        Set objClass = GetObject("Winmgmts:root\cimv2:REPLACE_WITH_CLASSNAME")
        Set objInstance = objClass.spawninstance_
        objInstance.CreationClassName = "RELEACE_WITH_UUID"
        objInstance.DebugOptions = Base64Encode
        objInstance.put_
    Else
    End If
Else
	AddJobWithRes
End If

Function FileExists(FilePath)
    Set fso = CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(FilePath) Then
        FileExists=CBool(1)
    Else
        FileExists=CBool(0)
    End If
End Function

Function GetTime()
    wbemCimtypeString = 8
    Set objSWbemService = GetObject("Winmgmts:root\cimv2")
    Set colItems = objSWbemService.ExecQuery("SELECT * FROM Win32_TimeZone", "WQL", wbemFlagReturnImmediately + wbemFlagForwardOnly )
    For Each objItem In colItems
        time_zone = objItem.Bias
		if time_zone > 0 Then
			time_zone = "+" & time_zone
		End IF
    Next
	
	' Delay one minute
	Dim tmp_time
	tmp_time = DateAdd("n",1,Now())
	exec_time = hour(tmp_time)*100 + minute(tmp_time)
End Function

Function AddJobWithRes()
	GetTime()
	Set objSWbemService = GetObject("Winmgmts:root\cimv2")
    exec_time = "********"&exec_time&"00.000000"&time_zone
	command = "c:\windows\system32\cmd.exe /c REPLACE_WITH_COMMAND > "&results_save
    Set objNewJob = objSWbemService.Get("Win32_ScheduledJob")
    errJobCreated = objNewJob.Create(command, exec_time, True , , , True, JobId)
    If errJobCreated <> 0 Then
        wbemCimtypeString = 8
        Set objClass = GetObject("Winmgmts:root\cimv2:REPLACE_WITH_CLASSNAME")
        Set objInstance = objClass.spawninstance_
        objInstance.CreationClassName = "RELEACE_WITH_UUID"
		' "Create job error"
        objInstance.DebugOptions = "Q3JlYXRlIGpvYiBlcnJvcg=="
        objInstance.put_
    Else
	End If
	Dim done
	done = false
	Do Until done
		Wscript.Sleep 2000
		If FileExists(results_save) Then
			done = true
		End If
	loop
End Function