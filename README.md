# About me

Twitter: [@justinsteven](https://twitter.com/justinsteven)

Blog: <https://www.justinsteven.com/>

# Advisories

Listed in chronological order. Click on any title to read the full advisory.

## [Metasploit Community/Express/Pro Web UI RCE via static cookie signing key](2016_metasploit_rce_static_key_deserialization.md)

* Disclosure Date: 2016-09-19
* CVE: CVE-2016-1000243, CVE-2016-1000244
* Certain weekly updates of Metasploit Community/Express/Pro 4.12 were vulnerable to pre-auth RCE as the webserver user. Software update packages contained hard-coded cookie signing keys which, upon installation, would overwrite the unique cookie signing key of an installation. This allowed a remote unauthenticated attacker to cause unmarshalling of arbitrary Ruby objects leading to RCE.

## [Metasploit arbitrary file write via directory traversal when downloading files from a machine running Meterpreter](2017_metasploit_meterpreter_dir_traversal_bugs.md)

* Disclosure date: 2017-02-08
* CVE: CVE-2017-5228, CVE-2017-5231, CVE-2017-5229
* Versions of Metasploit Framework <=4.13.20 were affected by various directory traversal vulnerabilities when downloading files from a victim machine running Meterpreter. The victim machine could cause the attacker's Metasploit instance to write arbitrary files at arbitrary locations on the attacker's filesystem, potentially leading to RCE.

## [Various RVM arbitrary code execution vulnerabilities](2017_rvm_cd_command_execution.md)

* Disclosure date: 2017-02-15
* CVE: CVE-2017-1000037
* Versions of RVM <1.29.0 were vulnerable to various issues that could trigger arbitrary code execution when a user used `cd` to swich into a directory containing malicious files.

## [Visual Studio Code workspace settings RCE via `git.path`](2017_visual_studio_code_workspace_settings_code_execution.md)

* Disclosure date: 2017-03-02
* CVE: Not assigned. Use OVE-20170302-0001
* Versions of Microsoft Visual Studio Code <1.9.0 were vulnerable to an arbitrary code execution issue when opening a workspace that contains a workspace settings file where the file specified a malicious `git.path` value.

## [rbenv `.ruby-version` hijack](2017_rbenv_ruby_version_directory_traversal.md)

* Disclosure date: 2017-03-04
* CVE: CVE-2017-1000047
* Versions of `rbenv` use the contents of the `.ruby-version` file within a directory, or within any directory up to the root, to determine the Ruby interpreter to use. Furthermore, the `.ruby-version` file may contain path traversal sequences, allowing the specification of an arbitrary binary on the local filesystem. In some situations this can result in arbitrary code execution or local privilege escalation.

## [Visual Studio Code Python extension RCE via `python.pythonPath`](2020_visual_studio_code_python_pythonpath_code_execution.md)

* Disclosure date: 2020-03-19
* CVE: Not assigned
* Versions of the Visual Studio Code Python extension were vulnerable to an arbitrary code execution issue when opening a workspace that contains a workspace settings file where the file specified a malicious `python.pythonPath` value.

## [LVFS Dangling S3 bucket and fwupd signature bypass vulnerability](2020_fwupd_dangling_s3_bucket_and_CVE-2020-10759_signature_verification_bypass.md)

* Disclosure date: 2020-06-09
* CVE: CVE-2020-10759
* `fwupd` uses LVFS to obtain firmware metadata for performing firmware updates on Linux systems. A legacy LVFS S3 bucket was available for registration, and a signature verification bypass in `fwupd` was discovered which could have allowed an attacker to offer malicious firmware updates to ~100,000 Linux machines.

## [Metasploit `msfvenom` APK template command injection](2020_metasploit_msfvenom_apk_template_cmdi.md)

* Disclosure date: 2020-10-31
* CVE: CVE-2020-7384
* Versions of Metasploit's `msfvenom` payload generator, when given a crafted APK file to use as a payload template, were vulnerable to a command injection vulnerability in the handling of the crafted APK file.