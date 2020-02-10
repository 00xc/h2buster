## Planned features/future updates ##
* Indicate response codes for redirection targets. Maybe add this as an option as it could slow things down. The same connection could be reused to do this if certain rules are met for the redirection location ([HTTP/2 coalescing](https://daniel.haxx.se/blog/2016/08/18/http2-connection-coalescing/))
* Check if a found directory is listable before scanning it. [dirb](https://gitlab.com/kalilinux/packages/dirb/) does this accurately, perhaps ideas can be taken from there.
* Use sitemap.xml after parsing robots.txt.
* Add command line options for more functionality. Some ideas:
	- HTTP basic auth.
	- Proxy usage.
	- Configurable time between requests in the same connection to avoid flooding.

## Other ideas/possible updates ##
* Subdomain scanning.
* Test [hyper](https://github.com/Lukasa/hyper)'s window_manager to increase throughput.
* Add support for HTTP/1.
* HTML parsing for web crawling (might slow things down a lot).
* Output results as a JSON file.
