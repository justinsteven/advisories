# postMessage DOM XSS vulnerability in Gartner Peer Insights widget

A DOM XSS vulnerability in the [Gartner Peer Insights Widget](https://blogs.gartner.com/reviews-pages/widget-user-guide/) affected sites such as Black Kite, Gradle, LogRhythm, ReversingLabs, SentinelOne, Synopsys, Tata Communications, Veeam, Vodafone and more.

The [writeup](writeup/) directory contains a full writeup of the bug, the patch, the bypassing of the patch, and the final patch by the vendor. It's presented as a HTML file, and is intended to be hosted from a host that contains the string "gartner.com" in the domain name. As of the time of writing, a copy is hosted at <https://gartner.com.ring0.lol/>

The [demo](demo/) directory contains copies of various versions of the widget JavaScript code, as well as webpages that consume them. The writeup contains dynamic Proof of Concept components that target these demos. As of the time of writing, a copy of the demos is hosted at <https://justinsteven.github.io/gartnerpeerinsightsxssdemo>

There is a [video on YouTube](https://youtu.be/fCNsZU0uqVs) that discusses many aspects of this issue.