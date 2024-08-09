Set args = WScript.Arguments
arg = ""

If args.Count > 0 Then
    If args(0) = "-d" Or args(0) = "--debug" Then
        arg = args(0)
    End If
End If

Set WshShell = CreateObject("WScript.Shell")
command = "C:\Users\%USERNAME%\Scripts\rgb-scheduler\run_task.bat " & arg

WshShell.Run command, 0, False