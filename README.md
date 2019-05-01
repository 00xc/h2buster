# h2buster
A recursive web directory brute-force scanner over HTTP/2 using [hyper](https://github.com/Lukasa/hyper).\
\
Check the [TODO](TODO.md) file for contributing.

## Usage

```
usage: h2buster.py [-h] -w wordlist -u target [-r recursion_depth] [-t threads]

arguments:
  -h, --help          show this help message and exit
  -w wordlist         Directory wordlist
  -u target           Target URL/IP address. Default port is 443 with HTTPS.
                      To specify otherwise, use ':port' or 'http://' (port
                      will default to 80 then).
  -r directory_depth  Maximum directory depth. Minimum is 1, default is 2.
  -t threads          Number of threads. Default is 10.
```