Dim time_zone
Dim exec_time
Dim command
command = "c:\windows\system32\cmd.exe /Q /c "& Base64StringDecode("REPLACE_WITH_COMMAND")

AddJobWithRes

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
    Set objNewJob = objSWbemService.Get("Win32_ScheduledJob")
    errJobCreated = objNewJob.Create(command, exec_time, True , , , True, JobId)
End Function

Function Base64StringDecode(ByVal vCode)
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.Type = 1
    BinaryStream.Open
    BinaryStream.Write oNode.nodeTypedValue
    BinaryStream.Position = 0
    BinaryStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    BinaryStream.CharSet = "utf-8"
    Base64StringDecode = BinaryStream.ReadText
    Set BinaryStream = Nothing
    Set oNode = Nothing
End Function
