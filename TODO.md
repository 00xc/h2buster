* Indicate response codes for redirection targets. Maybe add this as an option as it could slow things down.
* Add multithreading (or even multiprocessing). Several options here:
	- Have each thread perform requests independently under the same connection.
	- Have each thread manage its own H2 connection.
	- Have one thread sending and another one reading responses. They need to communicate stream IDs to each other (not ideal, but doable).
* Do some testing with [hyper](https://github.com/Lukasa/hyper)'s window_manager to increase throughput.
* Update to [hyper-h2](https://github.com/python-hyper/hyper-h2).
* Add command line options for more functionality. Some ideas:
	- Subdomain scanning.
	- Configure ignored response codes (right now 404 is hardcoded).
	- User-Agent string.
	- HTTP basic auth.
	- Proxy usage.
	- Server header detection.
	- Configurable time between requests.
	- Require valid certificates.
	- HTML parsing for web crawling (might slow things down a lot).
* Make the search breadth-first?
* Add support for HTTP/1 (not a priority whatsoever).
