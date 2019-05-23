# h2buster (v0.3d-1) #
A threaded, recursive, web directory brute-force scanner over HTTP/2 using [hyper](https://github.com/Lukasa/hyper), inspired by [Gobuster](https://github.com/OJ/gobuster).

## Features ##
* Fast and portable - install [hyper](https://github.com/Lukasa/hyper) and run.
* Multiconnection scanning.
* Multithreaded connections.
* Scalable: scans can be as docile or aggressive as you configure them to be.
* h2 and h2c support.
* Configurable directory recursion depth.
* Multiplatform: works on both Linux and Windows (OS X is to be tested).

## Install ##
You only need to install one dependency. If you don't have [hyper](https://github.com/Lukasa/hyper), run:\
`pip3 install -r requirements.txt`

## Usage
```
usage: h2buster.py [-h] -w wordlist -u target [-r directory_depth]
                   [-c connections] [-t threads] [-nc] [-x extension_list]

h2buster: an HTTP/2 web directory brute-force scanner.

arguments:
  -h, --help          show this help message and exit
  -w wordlist         Directory wordlist
  -u target           Target URL/IP address (host[:port]). Default port is 443
                      and HTTPS enabled. To specify otherwise, use ':port' or
                      'http://' (port will default to 80 then).
  -r directory_depth  Maximum recursive directory depth. Minimum is 1, default
                      is 2, unlimited is 0.
  -c connections      Number of HTTP/2 connections. Default is 3.
  -t threads          Number of threads per connection. Default is 20.
  -nc                 Disable colored output text.
  -x extension_list   List of file extensions to check separated by a
                      semicolon. For example, -x '.php;.js;blank;/' will check
                      .php, .js, blank and / for every wordlist entry. The
                      'blank' keyword signifies no file extension. Default
                      extensions are '/', 'blank', '.html', '.php'
```

## Contributing ##
Check the [TODO](TODO.md) file for a list of features that need work.
