# About me

Twitter: [@justinsteven](https://twitter.com/justinsteven)

Blog: <https://www.justinsteven.com/>

# Advisories

Listed in reverse chronological order. Click any title to read the full advisory.

## [Amazon Linux "log4j hotpatch" <1.3-5 local privilege escalation to root (race condition)](2022_amazon_log4j-cve-2021-44228-hotpatch_local_privesc.md)

* Disclosure date: 2022-06-16
* CVE: CVE-2022-33915
* Various packagings of Amazon Linux's log4j hotpatch, such as `log4j-cve-2021-44228-hotpatch-1.1.16`, were vulnerable to local privilege escalation via race condition. The vulnerable version would unsafely observe the EUID and EGID of a process before executing its underlying binary allowing local privilege escalation to root.

## [Git honours embedded bare repos, and exploitation via `core.fsmonitor` in a directory's `.git/config` affects IDEs, shell prompts and Git pillagers](2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md)

* Disclosure date: 2022-03-17
* A body of work regarding Git and Git integrations. Git can be shown to honour buried bare repos, allowing a malicious repo to be smuggled within a regular repo. The per-repo configuration directive `core.fsmonitor` can be shown to be dangerous. Software such as IDEs, shell prompt decorations and Git repo pillaging tools can be shown to be vulnerable to various impacts including remote code execution and/or arbitrary file write.

## [GitHub Actions `check-spelling` community workflow - `GITHUB_TOKEN` leakage via `advice.txt` symlink](2021_github_actions_checkspelling_token_leak_via_advice_symlink.md)

* Disclosure date: 2021-09-09
* CVE: CVE-2021-32724
* The `check-spelling` GitHub actions community workflow can be made to leak a `GITHUB_TOKEN` short-lived API key within a Pull Request comment by sending a Pull Request containing a symlink called `.github/actions/advice.txt` which points to `/proc/self/environ`.

## [Visual Studio Code `.ipynb` Jupyter Notebook XSS (Arbitrary File Read)](2021_vscode_ipynb_xss_arbitrary_file_read.md)

* Disclosure date: 2021-08-12
* CVE: Not assigned
* OVE: OVE-20210809-0001
* Visual Studio Code 1.59.0 ships with the Jupyter Notebook extension by default. An XSS vulnerability in the rendering of a crafted Jupyter Notebook file allows for theft of local files.

## [Metasploit `msfvenom` APK template command injection](2020_metasploit_msfvenom_apk_template_cmdi.md)

* Disclosure date: 2020-10-31
* CVE: CVE-2020-7384
* Versions of Metasploit's `msfvenom` payload generator, when given a crafted APK file to use as a payload template, were vulnerable to a command injection vulnerability in the handling of the crafted APK file.

## [LVFS Dangling S3 bucket and fwupd signature bypass vulnerability](2020_fwupd_dangling_s3_bucket_and_CVE-2020-10759_signature_verification_bypass.md)

* Disclosure date: 2020-06-09
* CVE: CVE-2020-10759
* `fwupd` uses LVFS to obtain firmware metadata for performing firmware updates on Linux systems. A legacy LVFS S3 bucket was available for registration, and a signature verification bypass in `fwupd` was discovered which could have allowed an attacker to offer malicious firmware updates to ~100,000 Linux machines.

## [Visual Studio Code Python extension RCE via `python.pythonPath`](2020_visual_studio_code_python_pythonpath_code_execution.md)

* Disclosure date: 2020-03-19
* CVE: Not assigned
* Versions of the Visual Studio Code Python extension were vulnerable to an arbitrary code execution issue when opening a workspace that contains a workspace settings file where the file specified a malicious `python.pythonPath` value.

## [rbenv `.ruby-version` hijack](2017_rbenv_ruby_version_directory_traversal.md)

* Disclosure date: 2017-03-04
* CVE: CVE-2017-1000047
* Versions of `rbenv` use the contents of the `.ruby-version` file within a directory, or within any directory up to the root, to determine the Ruby interpreter to use. Furthermore, the `.ruby-version` file may contain path traversal sequences, allowing the specification of an arbitrary binary on the local filesystem. In some situations this can result in arbitrary code execution or local privilege escalation.

## [Visual Studio Code workspace settings RCE via `git.path`](2017_visual_studio_code_workspace_settings_code_execution.md)

* Disclosure date: 2017-03-02
* CVE: Not assigned. Use OVE-20170302-0001
* Versions of Microsoft Visual Studio Code <1.9.0 were vulnerable to an arbitrary code execution issue when opening a workspace that contains a workspace settings file where the file specified a malicious `git.path` value.

## [Various RVM arbitrary code execution vulnerabilities](2017_rvm_cd_command_execution.md)

* Disclosure date: 2017-02-15
* CVE: CVE-2017-1000037
* Versions of RVM <1.29.0 were vulnerable to various issues that could trigger arbitrary code execution when a user used `cd` to swich into a directory containing malicious files.

## [Metasploit arbitrary file write via directory traversal when downloading files from a machine running Meterpreter](2017_metasploit_meterpreter_dir_traversal_bugs.md)

* Disclosure date: 2017-02-08
* CVE: CVE-2017-5228, CVE-2017-5231, CVE-2017-5229
* Versions of Metasploit Framework <=4.13.20 were affected by various directory traversal vulnerabilities when downloading files from a victim machine running Meterpreter. The victim machine could cause the attacker's Metasploit instance to write arbitrary files at arbitrary locations on the attacker's filesystem, potentially leading to RCE.

## [Metasploit Community/Express/Pro Web UI RCE via static cookie signing key](2016_metasploit_rce_static_key_deserialization.md)

* Disclosure Date: 2016-09-19
* CVE: CVE-2016-1000243, CVE-2016-1000244
* Certain weekly updates of Metasploit Community/Express/Pro 4.12 were vulnerable to pre-auth RCE as the webserver user. Software update packages contained hard-coded cookie signing keys which, upon installation, would overwrite the unique cookie signing key of an installation. This allowed a remote unauthenticated attacker to cause unmarshalling of arbitrary Ruby objects leading to RCE.