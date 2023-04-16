Set LogFileSet = GetObject("winmgmts:{(Backup,Security)}").ExecQuery("select * from Win32_NTEventLogFile")

for each Logfile in LogFileSet
 RetVal = LogFile.ClearEventlog()
next