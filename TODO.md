## Planned features/future updates ##
* Indicate response codes for redirection targets. Maybe add this as an option as it could slow things down.
* Add multiprocessing where each process manages its own H2 connection with its own children threads.
* Test [hyper](https://github.com/Lukasa/hyper)'s window_manager to increase throughput.
* Check if a found directory is listable before scanning it.
* Add command line options for more functionality. Some ideas:
	- Subdomain scanning.
	- Optional ignored response codes (right now 404 is hardcoded).
	- Optional extensions to override the hardcoded ones.
	- User-Agent string.
	- HTTP basic auth.
	- Proxy usage.
	- Server header detection.
	- Configurable time between requests to avoid flooding.
	- Require valid certificates.
	- HTML parsing for web crawling (might slow things down a lot).

## Other ideas/possible updates ##
* Make the search breadth-first.
* Add support for HTTP/1.
* Test [aioh2](https://github.com/decentfox/aioh2) for speed comparison.
