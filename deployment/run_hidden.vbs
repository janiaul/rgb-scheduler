Set args = WScript.Arguments
arg = ""

If args.Count > 0 Then
    If args(0) = "-d" Or args(0) = "--debug" Then
        arg = args(0)
    End If
End If

username = CreateObject("WScript.Network").Username
command = "C:\Users\" & username & "\Scripts\rgb-scheduler\deployment\run_task.bat " & arg

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run command, 0, False