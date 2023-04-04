' Function from wmihacker.vbs

Const data = "base64 string here"
dest = "C:\aab.txt"

function BytesToStr(ByVal byteArray, ByVal sTextEncoding)
    If LCase(sTextEncoding) = "utf-16le" then
        ' UTF-16 LE happens to be VBScript's internal encoding, so we can
        ' take a shortcut and use CStr() to directly convert the byte array
        ' to a string.
        BytesToStr = CStr(byteArray)
    Else ' Convert the specified text encoding to a VBScript string.
        ' Create a binary stream and copy the input byte array to it.
        With CreateObject("ADODB.Stream")
            .Type = 1 ' adTypeBinary
            .Open
            .Write byteArray
            ' Now change the type to text, set the encoding, and output the 
            ' result as text.
            .Position = 0
            .Type = 2 ' adTypeText
            .CharSet = sTextEncoding
            BytesToStr = .ReadText
            .Close
        End With
    End If
end function

Function Base64Decode(ByVal sBase64EncodedText, ByVal fIsUtf16LE)
    Dim sTextEncoding
    if fIsUtf16LE Then sTextEncoding = "utf-16le" Else sTextEncoding = "utf-8"
    ' Use an aux. XML document with a Base64-encoded element.
    ' Assigning the encoded text to .Text makes the decoded byte array
    ' available via .nodeTypedValue, which we can pass to BytesToStr()
    With CreateObject("Msxml2.DOMDocument").CreateElement("aux")
        .DataType = "bin.base64"
        .Text = sBase64EncodedText
        Base64Decode = BytesToStr(.NodeTypedValue, sTextEncoding)
    End With
End Function

Set objFSO=CreateObject("Scripting.FileSystemObject")

' How to write file
outFile=dest
Set objFile = objFSO.CreateTextFile(outFile,True)
objFile.Write Base64Decode(data,False) & vbCrLf
objFile.Close
