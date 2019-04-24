* Print redirection location when receiving a 301.
* Add multithreading, where each thread establishes its own H2 connection (less flooding and better use of TCP).
* Update to [hyper-h2](https://github.com/python-hyper/hyper-h2).
* Add command line options for more functionality. Some ideas:
	- Configure ignored response codes (right now 404 is hardcoded).
	- Configurable maximum recursion (right now it is a hardcoded constant).
	- User-Agent string.
	- HTTP basic auth.
	- Proxy usage.
	- Server header detection.
	- Configurable time between requests.
	- Require valid certificates.
	- HTML parsing for web crawling (might slow things down a lot).
* Make the search breadth-first? Probably need to break recursion for that.
* Add support for HTTP/1 (not a priority whatsoever).
