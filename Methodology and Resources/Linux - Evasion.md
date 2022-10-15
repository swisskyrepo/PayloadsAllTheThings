# Linux - Evasion

## Summary

- [File names](#file-names)
- [Command history](#command-history)
- [Hiding text](#hiding-text)


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


## References

- [ATT&CK - Impair Defenses: Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003/)
- [ATT&CK - Indicator Removal on Host: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [ATT&CK - Masquerading: Match Legitimate Name or Location](https://attack.mitre.org/techniques/T1036/005/)
- [Wikipedia - ANSI escape codes](https://en.wikipedia.org/wiki/ANSI_escape_code)