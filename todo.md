* Configure ignored response codes (right now 404 is hardcoded)
* Print redirection location when receiving a 301
* Add threading, where every thread uses several stream IDs independent from the rest. Even better if each thread is its own H2 connection (less flood and better use of TCP).
* Update to [hyper-h2](https://github.com/python-hyper/hyper-h2)
* Add command line options for more functionality. Some ideas:
	- User-Agent
	- HTTP basic auth
	- Proxy usage
	- Server header detection
	- Time between requests
	- Require valid certificates
* Make the search breadth-first?. Probably need to break recursion for that
* Add support for HTTP/1 (not a priority whatsoever)
