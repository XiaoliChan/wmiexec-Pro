Set TempFileSet = GetObject("winmgmts:\\.\ROOT\cimv2").ExecQuery("Select * from CIM_DataFile Where Path = ""\\Windows\\Temp\\"" And Extension = ""log"" And FileName Like ""windows-object%""")

for each Tempfile in TempFileSet
    Tempfile.Delete()
next