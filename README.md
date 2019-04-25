# h2buster
A (very) simple web directory brute-force scanner over HTTP/2 using [hyper](https://github.com/Lukasa/hyper).\
\
Check the [TODO](TODO.md) file for contributing.

## Usage

```
usage: h2buster.py [-h] -w wordlist -u target [-r recursion_depth]

arguments:
  -h, --help          show this help message and exit
  -w wordlist         Directory wordlist
  -u target           Target URL
  -r recursion_depth  Maximum directory recursion depth. Minimum is 1, default is 2.
```
