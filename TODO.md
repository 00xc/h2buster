## Planned features/future updates ##
* Indicate response codes for redirection targets. Maybe add this as an option as it could slow things down. The same connection could be reused to do this if certain rules are met for the redirection location ([HTTP/2 coalescing](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing/))
* Check if a found directory is listable before scanning it. [dirb](https://gitlab.com/kalilinux/packages/dirb/) does this accurately, perhaps ideas can be taken from there.
* Add command line options for more functionality. Some ideas:
	- Subdomain scanning.
	- HTTP basic auth.
	- Proxy usage.
	- Configurable time between requests in the same connection to avoid flooding.
	- Require valid certificates.
	- Output results as a JSON file.

## Other ideas/possible updates ##
* Test [hyper](https://github.com/Lukasa/hyper)'s window_manager to increase throughput.
* Make the search breadth-first.
* Add support for HTTP/1.
* Test [aioh2](https://github.com/decentfox/aioh2) for speed comparison. It's probably difficult to do so with threading/multiprocessing.
- HTML parsing for web crawling (might slow things down a lot).
* Add a custom 404 page content, so that sites that reply with a 200 code but display a "not found" page can be filtered. This requires parsing HTML.