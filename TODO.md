## Planned features/future updates ##
* Improve error handling (right now it is sort of ugly when something breaks).
* Indicate response codes for redirection targets. Maybe add this as an option as it could slow things down.
* Test [hyper](https://github.com/Lukasa/hyper)'s window_manager to increase throughput.
* Check if a found directory is listable before scanning it. [dirb](https://gitlab.com/kalilinux/packages/dirb/) does this accurately, perhaps ideas can be taken from there.
* Add command line options for more functionality. Some ideas:
	- Subdomain scanning.
	- Optional ignored response codes (right now 404 is hardcoded).
	- Optional extensions to override the hardcoded ones.
	- User-Agent string and other custom headers (`header:value`)
	- HTTP basic auth.
	- Proxy usage.
	- Server header detection.
	- Configurable time between requests to avoid flooding.
	- Require valid certificates.
	- HTML parsing for web crawling (might slow things down a lot).
* Add colors based on response code.

## Other ideas/possible updates ##
* Make the search breadth-first.
* Add support for HTTP/1.
* Test [aioh2](https://github.com/decentfox/aioh2) for speed comparison. Might be difficult to do so with threading/multiprocessing.
* Add a custom 404 page content, so that sites that reply with a 200 code but display a "not found page" can be filtered. 