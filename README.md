# h2buster (v0.3c-1) #
A threaded, recursive, web directory brute-force scanner over HTTP/2 using [hyper](https://github.com/Lukasa/hyper), inspired by [Gobuster](https://github.com/OJ/gobuster).

## Features ##
* Fast and portable - install [hyper](https://github.com/Lukasa/hyper) and run.
* Multiconnection scanning.
* Multithreaded connections.
* Scalable: scans can be as docile or aggressive as you configure them to be.
* h2 and h2c support.
* Configurable directory recursion depth.

## Install ##
You only need to install one dependency. If you don't have [hyper](https://github.com/Lukasa/hyper), run:\
`pip3 install -r requirements.txt`

## Usage
```
usage: h2buster.py [-h] -w wordlist -u target [-r directory_depth]
                   [-c connections] [-t threads] [-nc]

h2buster: an HTTP/2 web directory brute-force scanner.

arguments:
  -h, --help          show this help message and exit
  -w wordlist         Directory wordlist
  -u target           Target URL/IP address. Default port is 443 and HTTPS
                      enabled. To specify otherwise, use ':port' or 'http://'
                      (port will default to 80 then).
  -r directory_depth  Maximum recursive directory depth. Minimum is 1, default
                      is 2, unlimited is 0.
  -c connections      Number of HTTP/2 connections. Default is 3.
  -t threads          Number of threads per connection. Default is 15.
  -nc                 Disable colored output text.
```

## Contributing ##

Check the [TODO](TODO.md) file for a list of features that need work.