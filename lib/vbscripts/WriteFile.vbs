' Script from: https://www.vbsedit.com/scripts/misc/base64/decodefile.asp
' Const data="d2hvYW1pCg=="
' outputFile="c:\c.txt"

outputFile="REPLACE_WITH_DEST"
Const data="REPLACE_WITH_DATA"

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