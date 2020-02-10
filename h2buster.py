#!/usr/bin/env python3

# HTTP/2 I/O module
import hyper

# Native modules
import threading, multiprocessing
import ssl, sys, time, argparse, os
import platform
from urllib.parse import quote

# Exceptions
from socket import gaierror
from ssl import SSLError
from h2.exceptions import ProtocolError

# Internal module parsers
from libh2buster import UrlParser, RobotParser, NotfoundWildcard

# Metadata variables
__author__ = "https://github.com/00xc/"
__version__ = "0.4d"

PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."
DASHLINE = "---------------------------------------------------------------"

# Hardcoded values
TIMESTAMP_ROUND = 3
STREAM_RESET_SLEEP = 2
DEFAULT_TLS = True
DEFAULT_PORT = 443
ALLOWED_HTTP_METHODS = frozenset(("GET", "HEAD"))
REDIRECT_HTTP_CODES = frozenset((301, 302, 303, 307, 308))

# CLI options default values.
# None means required. Boolean means that the option has no argument (either the flag is there or not)
WORDLIST_DEFAULT = None
TARGET_DEFAULT = None
DIR_DEPTH_DEFAULT = 2
CNX_DEFAULT = multiprocessing.cpu_count() * 2
THREADS_DEFAULT = 20
ROBOTS_DEFAULT = False
NOCOLOR_DEFAULT = False
EXT_DEFAULT = "/|blank|.html|.php"
HEADERS_DEFAULT = "user-agent->Mozilla/5.0 (X11; Linux x86_64)"
BLACKLISTED_DEFAULT = "404"
VERIFYCERT_DEFAULT = False
HTTP_METHOD_DEFAULT = "HEAD"
RESPONSE_LENGTH_DEFAULT = False
NOTFOUND_DEFAULT = False

# CLI options metavariable names
WORDLIST_MVAR = "wordlist"
TARGET_MVAR = "target"
DIR_DEPTH_MVAR = "directory_depth=" + str(DIR_DEPTH_DEFAULT)
CNX_MVAR = "connections=" + str(CNX_DEFAULT)
THREADS_MVAR = "threads=" + str(THREADS_DEFAULT)
ROBOTS_MVAR = ""
NOCOLOR_MVAR = ""
EXT_MVAR = "extension_list"
HEADERS_MVAR = "header_list"
BLACKLISTED_MVAR = "http_code_list"
VERIFYCERT_MVAR = ""
HTTP_METHOD_MVAR = "http_method=" + HTTP_METHOD_DEFAULT
RESPONSE_LENGTH_MVAR = ""
NOTFOUND_MVAR = ""

# CLI options help strings
WORDLIST_HELP = "Directory wordlist"
TARGET_HELP = "Target URL/IP address ([scheme://]host[:port]). Default port is 443 and HTTPS enabled. To specify otherwise, use ':port' and/or 'http://' (port will default to 80 then)."
DIR_DEPTH_HELP = "Maximum recursive directory depth. Minimum is 1, unlimited is 0."
CNX_HELP = "Number of HTTP/2 connections."
THREADS_HELP = "Number of threads per connection."
ROBOTS_HELP = "Flag: scan for a robots.txt file. If found, a prompt will be displayed asking whether to use the results."
NOCOLOR_HELP = "Flag: disable colored output text."
EXT_HELP = "List of file extensions to check separated by a vertical bar (|). For example, -x '.php|.js|blank|/'. The 'blank' keyword signifies no file extension. Default extensions are " + ", ".join(f"'{ex}'" for ex in EXT_DEFAULT.split("|"))
HEADERS_HELP = "List of headers in the format 'header->value|header->value...'. For example: -hd 'user-agent->Mozilla/5.0|accept-encoding->gzip, deflate, br'."
BLACKLISTED_HELP = "List of blacklisted response codes separated by a vertical bar (|). Directories with these response codes will not be shown in the output. Default is 404."
VERIFYCERT_HELP = "Flag: force TLS certificate verification."
HTTP_METHOD_HELP = f"HTTP request method. Allowed values are {', '.join(ALLOWED_HTTP_METHODS)}."
RESPONSE_LENGTH_HELP = "Flag: show response length in output. This overrides the request method to GET."
NOTFOUND_HELP = "Flag: request a random path and analyze response to detect false positives (wildcard processing)."

# Define colors and color functions (only Linux and OS X)
if platform.system() == "Linux" or platform.system() == "Darwin":

	# Compatibility for all Unix-like systems
	multiprocessing.set_start_method('fork')

	COLORS = {
		"red": '\033[91m',
		"blue": '\033[94m',
		"green": '\033[92m',
		"yellow": '\033[93m',
		"bold": '\033[1m',
		"end": '\033[0m'
	}

	STATUS_COLORS = {
		200: COLORS["green"],
		301: COLORS["blue"],
		302: COLORS["blue"],
		303: COLORS["blue"],
		307: COLORS["blue"],
		308: COLORS["blue"],
		400: COLORS["red"],
		401: COLORS["yellow"],
		403: COLORS["yellow"],
		405: COLORS["yellow"],
		503: COLORS["red"],
		999: COLORS["red"]
	}

	def colorstring(s, status=0):
		s = "\x1b[K" + s
		if status==0 or NOCOLOR==True:
			return s
		else:
			try: start = STATUS_COLORS[status]
			except KeyError:
				try: start = COLORS[status]
				except KeyError: return s
		return start + s + COLORS["end"]

else:
	# This function is a mess trying to keep things readable in (old) Windows CMD
	# INFO returns the string plus a clear of the previous line
	# status = 0 will return a blank string
	def colorstring(s, status=0):
		if status == "INFO":
			# Extremely hacky solution to clear last line of stdout on Windows cmd
			return ("\t\t\t\t\t\t.\r").rstrip() + s
		elif status!=0:
			return s
		else:
			# The only inputs without a status are the feedback prints, so we can suppress them (we can't clear last line in Windows cmd easily)
			return ""

# Function: print total running time
def end(t0, exit_status):

	def _timestamp(t0):
		return str(round(time.time() - t0, TIMESTAMP_ROUND))

	if exit_status == 0: print(colorstring(f"\n[*] Scan done in {_timestamp(t0)} seconds.", status="INFO"))
	else: print(colorstring(f"\r[*] Scan aborted after {_timestamp(t0)} seconds.", status="INFO"))

# Function: return True if entry is a directory, False otherwise.
def isdir(e):
	if len(e)>1 and e[-1] == "/":
		if e[0] == ".": e = e[1:-1]
		else: e = e[:-1]

		if "." not in e: return True
		elif e[-1] == ".": return True
	return False

# Function: read options from CLI.
def read_inputs(info, opts, h, defaults, mvar):
	parser = argparse.ArgumentParser(description=info)
	for default, o, htext, mtext in zip(defaults, opts, h, mvar):
		if isinstance(default, bool):
			if default == True: action = "store_false"
			else: action = "store_true"
			parser.add_argument("-"+o, help=htext, default=default, action=action)
		else:
			if default==None: req = True
			else: req = False
			parser.add_argument("-"+o, help=htext, default=default, required=req, metavar=mtext)
	args = parser.parse_args()
	return args

# Function: parse protocol (TLS/plaintext), port and starting directory from imput target
def parse_target(target):
	try:
		p = UrlParser(DEFAULT_TLS, DEFAULT_PORT)
		p.parse(target)
		return p.secure, p.host, p.port, p.path
	except ValueError as error:
		sys.exit(colorstring(f"[-] {error}", status="red"))

# Function: parse input headers
def parse_header_opt(hd):
	try:
		out = dict()
		if hd[-1] == "|": hd = hd[:-1]
		for e in hd.split("|"):
			h, v = e.split("->", 1)
			out[h] = v
		return out
	except ValueError:
		sys.exit(colorstring("[-] Invalid header list.", status="red"))

# Function: connect via H2 to specified IP[:port] and return connection object
def h2_connect(s, ip, port, verify):
	if s == True:
		ctx = ssl.SSLContext()
		ctx.set_alpn_protocols(['h2'])
		if verify:
			ctx.verify_mode = ssl.CERT_REQUIRED
			ctx.load_default_certs()
		else: ctx.verify_mode = ssl.CERT_NONE
		conn = hyper.HTTP20Connection(ip, port=port, ssl_context=ctx)
	elif s == False:
		conn = hyper.HTTP20Connection(ip, port=port)
	conn.connect()
	return conn

# Function: main scan function. Starts up a number of processes which handle their own h2 connection and sends them entries to scan
def main_scan(s, ip, port, directory, args, dir_depth, robots_content, nf_fingerprint):

	if args.r!=0:
		if dir_depth >= args.r: return

	# Start input/output queues
	manager = multiprocessing.Manager()
	output = manager.list()
	inwork = multiprocessing.SimpleQueue()
	printq = multiprocessing.SimpleQueue()
	seen = set()

	print(colorstring(f"\n[*] Starting scan on {directory}", status="INFO"))

	# Start printing thread
	print_thread = threading.Thread(target=print_worker, args=(printq, ))
	print_thread.daemon = True
	print_thread.start()

	# Start connection processes
	process_pool = list()
	for i in range(args.c):
		p = multiprocessing.Process(
			target=process_worker,
			args=(
				(s, ip, port, args.vr),
				args.t,
				(args.m, args.hd, args.l, args.b, nf_fingerprint),
				(inwork, output, printq)
			),
			name=f"connection {i+1}"
		)
		p.daemon = True
		p.start()
		process_pool.append(p)

	try:
		# Add dictionary entries to queue
		with open(args.w, "r") as f:
			for entry in f:
				entry = entry.lstrip().rstrip()
				if entry == "" or entry[0] == "#": continue
				for ex in args.x:
					if (entry+ex) not in seen:
						inwork.put((directory, quote(entry)+ex))
						seen.add(entry+ex)

		# Add robots.txt entries to queue
		for entry in robots_content:
			if len(entry) >= (dir_depth+1):
				if dir_depth == 0 or (entry[dir_depth-1] == directory):
					if entry[dir_depth] not in seen:
						if "*" in entry[dir_depth]:
							for ex in args.x:
								inwork.put((directory, entry[dir_depth].replace("*", ex)))
						else:
							inwork.put((directory, entry[dir_depth]))
						seen.add(entry[dir_depth])

		# Add full path robots.txt entries too
		if dir_depth == 0:
			for entry in robots_content:
				entry = "".join(entry)
				if entry not in seen:
					if "*" in entry:
						for ex in args.x:
							inwork.put(("/", entry.replace("*", ex)))
					else:
						inwork.put(("/", entry))
					seen.add(entry)

		# Send kill signals and wait until processes are done
		for _ in range(args.c*args.t):
			inwork.put(None)
		for p in process_pool: p.join()

		# Send kill signal to printer
		printq.put(None)

	except FileNotFoundError:
		for _ in range(args.c*args.t):
			inwork.put(None)
		for p in process_pool: p.join()
		sys.exit(colorstring("[-] Wordlist file not found.", status="red"))

	except KeyboardInterrupt:
		# Kill printing thread and let processes handle the interrupt themselves
		print("\r[*] Received interrupt. Waiting for remaining requests to return.")
		printq.put(None)
		for p in process_pool: p.join(3)
		print_thread.join()

		# Exit
		end(t0, 1)
		sys.exit()

	# Delete big variables still in use
	del seen, inwork, printq, print_thread, process_pool

	# Recursive calls with found directories
	for d in output:
		main_scan(s, ip, port, d, args, dir_depth+1, robots_content, nf_fingerprint)

# Function: process worker. Starts one connection and a number of threads that perform requests on that connection.
def process_worker(connection_args, threads, thread_args, queues):
	conn = h2_connect(*connection_args)

	kill_threads_event = threading.Event()

	thread_pool = list()
	for _ in range(threads):
		t = threading.Thread(target=thread_worker, args=(conn, *thread_args, *queues, kill_threads_event))
		t.daemon = True
		t.start()
		thread_pool.append(t)

	# Wait for threads to be done or keyboard interrupt
	try:
		for t in thread_pool: t.join()
	except KeyboardInterrupt:
		kill_threads_event.set()
		for t in thread_pool: t.join()
	finally: conn.close()

# Function: thread worker. For each entry in the inwork queue, sends one request and reads response status code
def thread_worker(conn, method, head, length, blacklisted, nf_fingerprint, inwork, output, printq, kill_threads_event):
	global exit_status
	for directory, entry in iter(inwork.get, None):

		if kill_threads_event.is_set():
			break

		# Feedback on the last line of stdout
		printq.put((colorstring(entry, status=0), "\r"))

		try:
			#entry = entry.replace(" ", "%20")
			sid = conn.request(method, directory + entry, headers=head)
			resp = conn.get_response(sid)

		except TypeError:
			break
		except hyper.http20.exceptions.StreamResetError:
			printq.put((colorstring(f"[-] Warning: stream reset. Decrementing number of threads by one in {multiprocessing.current_process().name} - should probably restart with less threads.", status="yellow"), "\n"))
			break
		except ProtocolError as error:
			if not kill_threads_event.is_set():
				printq.put((colorstring(f"[-] Error: protocol compliance error in {multiprocessing.current_process().name}\n{error}", status="red"), "\n"))
				exit_status = 1
				kill_threads_event.set()
			break
		except ConnectionResetError as error:
			if not kill_threads_event.is_set():
				printq.put((colorstring(f"[-] Error: connection reset in {multiprocessing.current_process().name}\n{error}", status="red"), "\n"))
				exit_status = 1
				kill_threads_event.set()
			break

		# Print found entries
		if resp.status not in blacklisted:

			# Get response length if necessary
			if length:
				content = resp.read().decode("utf-8", "backslashreplace")
				tail = f" ({len(content)})"
			else:
				content = False
				tail = ""

			# Get redirect location if there is one
			if resp.status in REDIRECT_HTTP_CODES: redirect_location = resp.headers.get(b'location')[0].decode('utf-8')
			else: redirect_location = False

			# Check for wildcard not found responses
			if nf_fingerprint:
				if resp.status == nf_fingerprint.status:
					if content:
						if nf_fingerprint.match(directory+entry, content, resp.status, redirect_location):
							continue
					else:
						if nf_fingerprint.match(directory+entry, resp.read().decode("utf-8", "backslashreplace"), resp.status, redirect_location):
							continue

			if redirect_location:
				tail = tail + f" -> {redirect_location}"
			else:
				if resp.status == 200 and isdir(entry):
					tail = " [DIRECTORY]" + tail
					output.append(directory + entry)

			printq.put((colorstring(f"[{resp.status}] {directory}{entry}{tail}", status=resp.status), "\n"))

# Function: thread worker that prints everything on the queue. References to this queue are given to all the scanning threads
def print_worker(printq):
	count = 0
	for item, end in iter(printq.get, None):
		if end == "\n":
			print(item, end=end)
		elif end == "\r":
			count+=1
			if count == 50:
				print(item[:70], end=end)
				count = 0

# Function: prompt for 'opts' options
def prompt_select(banner, msg, opts):
	c = None
	print(banner)
	while c is None:
		c = input(msg)
		c.lower()
		if c not in opts:
			c = None
	return c

# Function: parse robot entries and prompt for their use
def parse_robots(ip, port, content, status, location, ua):
	try:

		if location != "/robots.txt":
			print(f"[*] Got a redirection from /robots.txt to {location}")

		if content == False:
			if location[0] == "/": print(colorstring(f"[-] {ip}{':'+port if port not in (80, 443) else ''}{location} could not be read. Status: {status}", status="yellow"))
			else: print(colorstring("[-] External redirection", status="yellow"))
			return frozenset()

		elif len(content) == 0:
			print(colorstring(f"[-] {ip}{':'+port if port not in (80, 443) else ''}{location} is empty.", status="yellow"))
			return frozenset()

		elif len(content) > 0:

			# Parse robots.txt entries
			try:
				p = RobotParser(ua)
				# Parse all entries
				p.parse(content, policy="all")
				all_entries = p.get_entries()
				# Parse allowed entries
				p.parse(content, policy="allow")
				allowed_entries = p.get_entries()
				# Parse sitemaps
				sitemaps = p.get_sitemaps()

			except ValueError as error:
				print(colorstring(f"[-] Error parsing robots.txt:\n{error}", status="red"))
				c = prompt_select(
					"Do you want to continue scanning?\n\t[Y/y] to continue\n\t[N/n] to exit",
					"Selected option: ",
					("y", "n")
				)
				if c == "y":
					return frozenset()
				elif c == "n":
					sys.exit()

			# Print found information
			print(colorstring(f"[+] {ip}{':'+port if port not in (80, 443) else ''}{location} found!", status="green"))
			if len(all_entries)>0:
				print(f"[*] Found {len(all_entries)} total entries.")
				print(f"[*] Found {len(allowed_entries)} allowed entries.")

				# Prompt to use robots entries
				use_robots = prompt_select(
					"Should we use this information?\n\t[A/a] to use all entries\n\t[Y/y] to use only allowed entries\n\t[N/n] to ignore all entries.",
					"Selected option: ",
					("a", "y", "n")
				)
				if use_robots == "a": out_entries = all_entries
				elif use_robots == "y": out_entries = allowed_entries
				else: out_entries = frozenset()

			else:
				print(colorstring("[-] File contains no entries, nothing to use here.", status="yellow"))
				out_entries = frozenset()

			# Print sitemap information
			if len(sitemaps) > 0:
				print(DASHLINE)
				if len(sitemaps) == 1: print(colorstring("[+] 1 sitemap found! Inspect it manually.", status="green"))
				else: print(colorstring(f"[+] {len(sitemaps)} sitemaps found! Inspect them manually.", status="green"))
				for s in sitemaps:
					print(f"\t{s}")

			# Convert each entry into an n-tuple of directories (must use tuple, cannot have a set of lists)
			out_parsed_entries = set()
			for entry in out_entries:
				parsed_entry = [f+"/" for f in entry.split("/") if f!=""]
				if entry[-1] != "/":
					parsed_entry[-1] = parsed_entry[-1][:-1]
				out_parsed_entries.add(tuple(parsed_entry))
			return frozenset(out_parsed_entries)

	except KeyboardInterrupt:
		sys.exit("")

# Function: gets content of robots.txt, follows redirection. Returns content and URI of content.
def get_robots_content(conn, loc="/robots.txt"):
	sid = conn.request("GET", loc)
	resp = conn.get_response(sid)

	if resp.status == 200:
		robots_content = (resp.read().decode("utf-8"), resp.status, loc)

	elif resp.status in REDIRECT_HTTP_CODES:
		redirect_location = resp.headers.get(b'location')[0].decode('utf-8')
		robots_content = get_robots_content(conn, redirect_location)

	else:
		robots_content = (False, resp.status, loc)

	return robots_content

def argument_cleanup(args):
	# Input checking
	try:
		args.r, args.c, args.t = int(args.r), int(args.c), int(args.t)
		args.m = args.m.upper()
		if args.t<1 or args.c<1 or args.r<0:
			sys.exit(colorstring("[-] Connections and threads must be greater than zero. Directory depth must be greater than or equal to zero.", status="red"))
		if args.l:
			args.m = "GET"
		elif args.m not in ALLOWED_HTTP_METHODS:
			sys.exit(colorstring(f"[-] Allowed HTTP methods are: {', '.join(ALLOWED_HTTP_METHODS)}", status="red"))
	except ValueError:
		sys.exit(colorstring("[-] Invalid non-numerical option introduced.", status="red"))

	# Parse listed arguments
	args.x = tuple(set(args.x.replace("blank", "").split("|")))
	args.hd = parse_header_opt(args.hd)
	args.b = frozenset(args.b.split("|"))
	try: args.b = tuple(map(int, args.b))
	except ValueError: sys.exit(colorstring("[-] Blacklisted codes must be numerical.", status="red"))

	return args

# Function: check for redirections when accessing the target site, and update target based on user input
def update_redirect(conn, connection_args, verify):

	start_dir = connection_args[-1]

	sid = conn.request("GET", start_dir)
	resp = conn.get_response(sid)

	if resp.status in REDIRECT_HTTP_CODES:
		redirect_location = resp.headers.get(b'location')[0].decode('utf-8')
		answer = prompt_select(
			f"[*] Got a redirection from {start_dir} to: {colorstring(redirect_location, status='bold')}",
			"\tDo you update the target? [y/n] ",
			("y", "n")
		)

		if answer == "y":
			if redirect_location[0] == "/":
				return update_redirect(conn, (*connection_args[:3], redirect_location), verify)

			else:
				conn.close()
				s, ip, port, redirect_dir = parse_target(redirect_location)
				conn = h2_connect(s, ip, port, verify)
				return update_redirect(conn, (s, ip, port, start_dir), verify)

		elif answer == "n":
			return conn, resp, connection_args

	else:
		return conn, resp, connection_args

# Main start point. Read, verify inputs and call main_scan()
if __name__ == '__main__':

	print(DASHLINE)
	print("h2buster v" + __version__)
	print(DASHLINE)

	# Read CLI inputs
	opts = ("w", "u", "c", "t", "m", "r", "hd", "x", "b", "l", "vr", "wc", "rb", "nc")
	mvar = (
		WORDLIST_MVAR,
		TARGET_MVAR,
		CNX_MVAR,
		THREADS_MVAR,
		HTTP_METHOD_MVAR,
		DIR_DEPTH_MVAR,
		HEADERS_MVAR,
		EXT_MVAR,
		BLACKLISTED_MVAR,
		RESPONSE_LENGTH_MVAR,
		VERIFYCERT_MVAR,
		NOTFOUND_MVAR,
		ROBOTS_MVAR,
		NOCOLOR_MVAR
	)
	h = (
		WORDLIST_HELP,
		TARGET_HELP,
		CNX_HELP,
		THREADS_HELP,
		HTTP_METHOD_HELP,
		DIR_DEPTH_HELP,
		HEADERS_HELP,
		EXT_HELP,
		BLACKLISTED_HELP,
		RESPONSE_LENGTH_HELP,
		VERIFYCERT_HELP,
		NOTFOUND_HELP,
		ROBOTS_HELP,
		NOCOLOR_HELP
	)
	defaults = (
		WORDLIST_DEFAULT,
		TARGET_DEFAULT,
		CNX_DEFAULT,
		THREADS_DEFAULT,
		HTTP_METHOD_DEFAULT,
		DIR_DEPTH_DEFAULT,
		HEADERS_DEFAULT,
		EXT_DEFAULT,
		BLACKLISTED_DEFAULT,
		RESPONSE_LENGTH_DEFAULT,
		VERIFYCERT_DEFAULT,
		NOTFOUND_DEFAULT,
		ROBOTS_DEFAULT,
		NOCOLOR_DEFAULT
	)
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	# Set NOCOLOR as global constant so colorstring() knows what to do
	if platform.system() == "Linux" or platform.system() == "Darwin":
		global NOCOLOR
		NOCOLOR = args.nc

	# Argument checking and parsing
	args = argument_cleanup(args)
	s, ip, port, start_dir = parse_target(args.u)

	# Start scout connection and check if target is valid
	try:
		# Test HTTP/2
		conn = h2_connect(s, ip, port, args.vr)
		conn, resp, (s, ip, port, start_dir) = update_redirect(conn, (s, ip, port, start_dir), args.vr)

		# Server header
		try: server = resp.headers.get(b"server")[0].decode("utf-8")
		except TypeError: server = False

	# Handle errors
	except ConnectionResetError: sys.exit(colorstring("[-] Connection reset. Are you sure the target supports HTTP/2?", status="red"))
	except AssertionError: sys.exit(colorstring("[-] HTTP/2 not supported for that target.", status="red"))
	except gaierror as error: sys.exit(colorstring("[-] Could not get address information. Are you sure the target exists?", status="red"))
	except SSLError as error: sys.exit(colorstring(f"[-] TLS error.\n{error}", status="red"))
	except ProtocolError as error: sys.exit(colorstring(f"[-] Protocol compliance error:\n{error}", status="red"))
	except ConnectionRefusedError: sys.exit(colorstring("[-] Connection refused.", status="red"))
	except Exception as error: sys.exit(colorstring(f"[-] Error:\n{error}", status="red"))
	except KeyboardInterrupt:
		try: conn.close()
		except NameError: pass
		sys.exit(colorstring("\r\n[-] Program aborted."))

	# Print information
	print(colorstring("[+] Target supports HTTP/2", status="green"))
	if server: print(colorstring(f"[+] Target server: {server}", status="green"))
	print("[*] Initializing scan on ", end="")
	print(colorstring(f"{ip}{':'+port if port not in (80, 443) else ''}", status="bold"))
	print(f"[*] TLS is {'ON' if s else 'OFF'}")
	print(f"[*] TLS certificate verification is {'ON' if args.vr and s else 'OFF'}")
	print(f"[*] Request method: {args.m}")
	print(f"[*] Base directory: {start_dir}")
	print(f"[*] Maximum directory depth: {args.r} (base directory is depth 1)")
	print("[*] Ignored response codes: " + ", ".join(map(str, args.b)))
	print("[*] Headers:")
	for k, e in args.hd.items():
		print(f"\t{k}: {e}")
	print(f"[*] Number of connections: {args.c}")
	print(f"[*] Number of threads per connection: {args.t}")
	print("[*] File extensions: " + ", ".join(f"'{ex}'" for ex in args.x))
	print(DASHLINE)

	# Not found content: perform request and print information
	if args.wc:
		nf_fingerprint = NotfoundWildcard(conn, args.m, REDIRECT_HTTP_CODES)
		print(colorstring("[+] Random request done.", status="green"))
		print(f"[*] Request string: {nf_fingerprint.request_string}")
		print(f"[*] Response code: {nf_fingerprint.status}")
		if nf_fingerprint.redirect:
			print(f"\t redirect to: {nf_fingerprint.redirect}")
		print(f"[*] Response length: {nf_fingerprint.response_length}")
		print(DASHLINE)

	else:
		nf_fingerprint = False

	# robots.txt: get robots.txt content and parse it according to user input
	if args.rb:
		robots_content, robots_status, robots_location = get_robots_content(conn)
		print(colorstring("[+] robots.txt scanning done", status="green"))
		parsed_robots_content = parse_robots(ip, port, robots_content, robots_status, robots_location, args.hd.get("user-agent", f"h2buster v{__version__}"))
		print(DASHLINE)
	else:
		parsed_robots_content = frozenset()


	# Close scout connection
	conn.close()

	# This variable can be changed by any of the threads
	exit_status = 0

	# Start timer (for benchmarking purposes)
	t0 = time.time()

	# Start recursive scan and exit when it returns
	main_scan(s, ip, port, start_dir, args, 0, parsed_robots_content, nf_fingerprint)
	end(t0, exit_status)
