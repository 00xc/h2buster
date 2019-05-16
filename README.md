# h2buster
A recursive web directory brute-force scanner over HTTP/2 using [hyper](https://github.com/Lukasa/hyper), inspired by [Gobuster](https://github.com/OJ/gobuster).\
\
Check the [TODO](TODO.md) file for contributing.

## Features ##
* Fast and portable - no installation needed.
* Multiconnection scanning.
* Multithreaded connections.
* Scalable: scans can be as docile or aggressive as you configure them to be.
* h2 (HTTP/2 over TLS) and h2c (HTTP/2 over plain TCP) support.
* Configurable directory recursion depth.

## Usage ##

```
usage: h2buster.py [-h] -w wordlist -u target [-r directory_depth]
                      [-c connections] [-t threads]

arguments:
  -h, --help          show this help message and exit
  -w wordlist         Directory wordlist
  -u target           Target URL/IP address. Default port is 443 and HTTPS
                      enabled. To specify otherwise, use ':port' or 'http://'
                      (port will default to 80 then).
  -r directory_depth  Maximum recursive directory depth. Minimum is 1, default is 2.
  -c connections      Number of HTTP/2 connections. Default is 3.
  -t threads          Number of threads per connection. Default is 15.
```
