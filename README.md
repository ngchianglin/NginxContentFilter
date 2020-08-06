# Nginx Content Filter Module
An Nginx Filter Module that can filter and block sensitive content

## Introduction

This is an Nginx filter module that inspects the content of HTTP response body and blocks the content if specific texts are present.
It can be used to prevent leakage of sensitive information from websites. The filter module uses PCRE regular expression to match for
specific words and text. The filter will log an Alert message and display a blank page instead of the original content if
there are matches. Matching is done on a line by line basis.

A logging only mode is available. This can be used for troubleshooting without blocking the actual web content.
This module can be used as an additional security measure to protect websites against malicious attacks that attempt to exfiltrate
sensitive data. The regular expressions for matching content are specified via the module configuration directives.

Note, if the http content is compressed it will be skipped by the module and allowed to pass through.
If the http content exceeds a maximum size set in NGX_HTTP_CT_MAX_CONTENT_SZ (10MB), it will be skipped and allowed to pass through.

This module is based on a fork of Weibin Yao(yaoweibin@gmail.com) nginx substitution module. Refer to the following github link
for the original substitution module.
[https://github.com/yaoweibin/ngx_http_substitutions_filter_module](https://github.com/yaoweibin/ngx_http_substitutions_filter_module)

## Installation

The module requires PCRE library. At the time of writing, the latest version is pcre 8.44. Download a copy of
[pcre 8.44](https://www.pcre.org/) and the latest
[nginx version 1.18.0](https://nginx.org/en/download.html). Refer to their respective project websites for details on how to verify the integrity of the source downloads.
The following shows the sha-256 hashes for the 2 source packages.

    nginx-1.18.0.tar.gz  4c373e7ab5bf91d34a4f11a0c9496561061ba5eee6020db272a17a7228d35f99

    pcre-8.44.tar.gz  aecafd4af3bd0f3935721af77b889d9024b2e01d96b58471bd91a3063fb47728

Download or clone a copy of this module

    git clone https://github.com/ngchianglin/NginxContentFilter.git

Extract nginx and pcre source.

    tar -zxvf nginx-1.18.0.tar.gz
    tar -zxvf pcre-8.44.tar.gz

Configure and compile the module

    cd nginx-1.18.0
    ./configure --with-cc-opt="-Wextra -Wformat -Wformat-security -Wformat-y2k -fPIE -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all" --with-ld-opt="-pie -Wl,-z,relro -Wl,-z,now -Wl,--strip-all" --add-module=../NginxContentFilter  --with-pcre=../pcre-8.44 --with-pcre-opt="-O2 -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIC" --with-pcre-jit
    make
    sudo make install

This will install nginx compiled with the content filter module into /usr/local/nginx
Note pcre is not configured with UTF8 support enabled.

## Module Directives

**ct_filter**

* syntax: ct_filter [regex] [number of occurences]
* default: none
* context: Location

Specifies the regular expression for matching against the HTTP response body. Matching is done line by line on the content. The second
parameter is the threshold for blocking the content. It specifies the minimum number of matches that will cause the content to be
blocked. For example,

ct_filter mytest 5;

If "mytest" appears 5 times in the content, the content will be blocked. Multiple ct_filter directives can be specified. The content
will be blocked if any of the directives matched.


**ct_filter_types**

* syntax: ct_filter_types [mime-types] [mime-types] ...
* default: text/html
* context: HTTP, Server, Location

Specifies the content types that the filter module will process. Note these should generally only be textual content such as html, text, javascript, css, xml etc... The default is text/html.
The filter module is not able to process compressed content. It can however work with compression module such as gzip so
long as uncompressed content is run through the filter module first before being processed by gzip module.

**ct_filter_logonly**

* syntax: ct_filter_logonly [on|off]
* default: off
* context: HTTP, Server, Location

A configuration flag to specify whether web content is blocked if matches are detected. If this is switched to "on", the module will only
log Alerts when matches occured. The default is "off".  

## Example Configuration

    location / {
       root  /opt/www/html;  
       index  index.html index.htm;  

       ct_filter_types text/plain application/javascript;  
       ct_filter_logonly off;

       ct_filter S\d\d\d\d\d\d\d[A-Z] 1;  
       ct_filter (?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]\@[a-zA-Z0-9]+\.[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z] 2;  
       ct_filter 8\d\d\d\d\d\d\d 2;  
       ct_filter 9\d\d\d\d\d\d\d 2;  
       ct_filter 机密 1;  
    }

The above configuration specifies that content with the mimes type, text/html (default), text/plain and application/javascript
will be processed by the module. Log only option is explicitly set to off. This means if there are matches, a blank page will be
displayed instead of the original content.

Each of the five filter directives that follow, specifies the regular expression to match for and the occurence threshold.
The first filter attempts to match a Singapore NRIC number and the occurence threshold is set to 1. i.e. if a single NRIC is detected,
the content will be blocked.

The second filter directive attempts to match email addresses with occurence threshold of 2.
The next two tries to match mobile numbers and the last filter directive matches the chinese characters "机密" (secret). Note that in
the eariler installation instructions, utf 8 and unicode support is not enabled for pcre.

If any of these directive matches, the content will be blocked.
Note these example regular expressions don't cover all the cases for the specific content that they intends to match.
Users need to work out their own regular expressions suitable for their use cases and context.

## Security Warning

No security mechanism is perfect. This module should be used as an additional layer of mitigation in an overall security architecture.
There can be methods to bypass the protection mechanism and bugs can exist in the software.
Attackers can try to subvert the protection mechanism through encoding attacks or bypass the regex matching.

The module is released under the BSD license (same as Nginx) and there are no warranties of any kinds.
Basically use it at your own risk ! Read and understand the License carefully.

## Further Details

Refer to the following article, Blocking Sensitive Content Using Nginx and Docker for more details about the implementation and usage.

[https://www.nighthour.sg/articles/2018/blocking-sensitive-content-nginx-docker.html](https://www.nighthour.sg/articles/2018/blocking-sensitive-content-nginx-docker.html)


## Source signature
Gpg Signed commits are used for committing the source files.

> Look at the repository commits tab for the verified label for each commit, or refer to [https://www.nighthour.sg/git-gpg.html](https://www.nighthour.sg/git-gpg.html) for instructions on verifying the git commit.
>
> A userful link on how to verify gpg signature is available at [https://github.com/blog/2144-gpg-signature-verification](https://github.com/blog/2144-gpg-signature-verification)
