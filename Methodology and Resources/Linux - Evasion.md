# Linux - Evasion

## Summary

- [File names](#file-names)
- [Command history](#command-history)
- [Hiding text](#hiding-text)
- [Timestomping](#timestomping)


## File Names

An Unicode zero-width space can be inserted into filenames which makes the names visually indistinguishable:

```bash
# A decoy file with no special characters
touch 'index.php'

# An imposter file with visually identical name
touch $'index\u200D.php'
```


## Command History

Most shells save their command history so a user can recall them again later.  The command history can be viewed with the `history` command or by manually inspecting the contents of the file pointed to by `$HISTFILE` (e.g. `~/.bash_history`).
This can be prevented in a number of ways.

```bash
# Prevent writing to the history file at all
unset HISTFILE

# Don't save this session's command history in memory
export HISTSIZE=0
```

Individual commands that match a pattern in `HISTIGNORE` will be excluded from the command history, regardless of `HISTFILE` or `HISTSIZE` settings.  
By default, `HISTIGNORE` will ignore all commands that begin with whitespace:

```bash
# Note the leading space character:
 my-sneaky-command
```

If commands are accidentally added to the command history, individual command entries can be removed with `history -d`:

```bash
# Removes the most recently logged command.
# Note that we actually have to delete two history entries at once,
# otherwise the `history -d` command itself will be logged as well.
history -d -2 && history -d -1
```

The entire command history can be purged as well, although this approach is much less subtle and very likely to be noticed:

```bash
# Clears the in-memory history and writes the empty history to disk.
history -c && history -w
```


## Hiding Text

ANSI escape sequences can be abused to hide text under certain circumstances.  
If the file's contents are printed to the terminal (e.g. `cat`, `head`, `tail`) then the text will be hidden.  
If the file is viewed with an editor (e.g. `vim`, `nano`, `emacs`), then the escape sequences will be visible.

```bash
echo "sneaky-payload-command" > script.sh
echo "# $(clear)" >> script.sh
echo "# Do not remove. Generated from /etc/issue.conf by configure." >> script.sh

# When printed, the terminal will be cleared and only the last line will be visible:
cat script.sh
```


## Timestomping

Timestomping refers to the alteration of a file or directory's modification/access timestamps in order to conceal the fact that it was modified.  
The simplest way to accomplish this is with the `touch` command:

```bash
# Changes the access (-a) and modification (-m) times using YYYYMMDDhhmm format.
touch -a -m -t 202210312359 "example"

# Changes time using a Unix epoch timestamp.
touch -a -m -d @1667275140 "example"

# Copies timestamp from one file to another.
touch -a -m -r "other_file" "example"

# Get the file's modification timestamp, modify the file, then restore the timestamp.
MODIFIED_TS=$(stat --format="%Y" "example")
echo "backdoor" >> "example"
touch -a -m -d @$MODIFIED_TS "example"
```

It should be noted that `touch` can only modify the access and modification timestamps.  It can't be used to update a file's "change" or "birth" timestamps.  The birth timestamp, if supported by the filesystem, tracks when the file was created.  The change timestamp tracks whenever the file's metadata changes, including updates to the access and modification timestamps.

If an attacker has root privileges, they can work around this limitation by modifying the system clock, creating or modifying a file, then reverting the system clock:

```bash
ORIG_TIME=$(date)
date -s "2022-10-31 23:59:59"
touch -a -m "example"
date -s "${ORIG_TIME}"
```

Don't forget that creating a file also updates the parent directory's modification timestamp as well!


## References

- [ATT&CK - Impair Defenses: Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003/)
- [ATT&CK - Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [ATT&CK - Indicator Removal on Host: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [ATT&CK - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Wikipedia - ANSI escape codes](https://en.wikipedia.org/wiki/ANSI_escape_code)
- [InverseCos - Detecting Linux Anti-Forensics: Timestomping](https://www.inversecos.com/2022/08/detecting-linux-anti-forensics.html)
