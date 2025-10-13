wbemCimtypeString = 8
Set objSWbemService = GetObject("Winmgmts:root\cimv2")
Set objClass = objSWbemService.Get()
objClass.Path_.Class = "REPLACE_WITH_CLASSNAME"

' Add a property
' String property
objClass.Properties_.add "CreationClassName", wbemCimtypeString  
objClass.Properties_.add "DebugOptions", wbemCimtypeString  

' Make the property a key property 
objClass.Properties_("CreationClassName").Qualifiers_.add "key", true
objClass.Properties_("DebugOptions").Qualifiers_.add "read", true

' Write the new class to the root\default namespace in the repository
Set objClassPath = objClass.Put_

'Create an instance of the new class using SWbemObject.SpawnInstance
Set objNewInst = GetObject("Winmgmts:root\Cimv2:REPLACE_WITH_CLASSNAME").Spawninstance_
objNewInst.CreationClassName = "Backup"
objNewInst.DebugOptions = "For windows backup services"

' Write the instance into the repository
Set objInstancePath = objNewInst.Put_
'WScript.Echo objInstancePath.Path