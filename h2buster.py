#!/usr/bin/env python3

# HTTP/2 I/O module
import hyper

# Native modules
import threading, multiprocessing
import ssl, sys, time, argparse, os
import platform, signal

# Exceptions
from socket import gaierror
from ssl import SSLError
from h2.exceptions import ProtocolError

# Internal module parsers
from libh2buster import UrlParser, RobotParser

# Metadata variables
__author__ = "https://github.com/00xc/"
__version__ = "0.4c"

PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."
DASHLINE = "---------------------------------------------------------------"

# Hardcoded values
TIMESTAMP_ROUND = 3
STREAM_RESET_SLEEP = 1
DEFAULT_TLS = True
DEFAULT_PORT = 443
ALLOWED_HTTP_METHODS = frozenset(("GET", "HEAD"))
REDIRECT_HTTP_CODES = frozenset((301, 302, 303, 307, 308))

# CLI options default values.
# None means required. Boolean means that the option has no argument (either the flag is there or not)
WORDLIST_DEFAULT = None
TARGET_DEFAULT = None
DIR_DEPTH_DEFAULT = 2
CNX_DEFAULT = 4
THREADS_DEFAULT = 20
ROBOTS_DEFAULT = False
NOCOLOR_DEFAULT = False
EXT_DEFAULT = "/|blank|.html|.php"
HEADERS_DEFAULT = "user-agent->Mozilla/5.0 (X11; Linux x86_64)"
BLACKLISTED_DEFAULT = "404"
VERIFYCERT_DEFAULT = False
HTTP_METHOD_DEFAULT = "HEAD"
RESPONSE_LENGTH_DEFAULT = False

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

# Define colors and color functions (only Linux and OS X)
if platform.system() == "Linux" or platform.system() == "Darwin":

	COLORS = {
		"red": '\033[91m', 
		"green": '\033[92m',
		"yellow": '\033[93m',
		"blue": '\033[94m',
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

	# Function: return line with colors according to status code
	def colorstring(s, status=0):
		global NOCOLOR
		s = "\x1b[K" + s
		if status==0 or NOCOLOR==True:
			return s
		else:		
			if status in STATUS_COLORS.keys(): start = STATUS_COLORS[status]
			elif status in COLORS.keys(): start = COLORS[status]
			else: return s			
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

# Function: return time since t0
def _timestamp(t0):
	return str(round(time.time() - t0, TIMESTAMP_ROUND))

# Function: print total running time
def end(t0, exit_status):
	if exit_status == 0: print(colorstring(f"\n[*] Scan done in {_timestamp(t0)} seconds.", status="INFO"))
	else: print(colorstring(f"\r[*] Scan aborted after {_timestamp(t0)} seconds.", status="INFO"))

# Function: return True if entry is a directory, False otherwise.
def isdir(e):
	if e == "/" or len(e)==0 or e[-1]!="/":
		return False
	elif e.count(".")==0 or any(len(x)==0 for x in e.split(".")):
		return True
	else:
		return False

# Function: read "opts" options from CLI. 
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

# Function: parse protocol (TLS or not), port and starting directory from imput target
def parse_target(target):
	try:
		p = UrlParser(default_secure=DEFAULT_TLS, default_port=DEFAULT_PORT)
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
def main_scan(s, ip, port, directory, args, dir_depth, robots_content):

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
		p = multiprocessing.Process(target=process_worker, args=(s, ip, port, args.t, args.m, args.hd, args.l, args.b, args.vr, inwork, output, printq))
		p.daemon = True
		p.start()
		process_pool.append(p)

	try:
		# Add dictionary entries to queue
		with open(args.w, "r") as f:
			for entry in f:
				if entry[0]=="#": continue
				entry = entry.lstrip().rstrip()
				for ex in args.x:
					if (entry+ex) not in seen:
						inwork.put((directory, entry+ex))
						seen.add(entry+ex)

		# Add robots.txt entries to queue
		for entry in robots_content:
			if len(entry) >= (dir_depth+1):
				if dir_depth == 0 or (entry[dir_depth-1] == directory):
					if entry[dir_depth] not in seen:
						if entry[dir_depth].count("*")>0:
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
					if entry.count("*")>0:
						for ex in args.x:
							inwork.put(("/", entry.replace("*", ex)))
					else:
						inwork.put(("/", entry))
					seen.add(entry)

		# Send kill signals and wait until processes are done
		for i in range(args.c*args.t):
			inwork.put((None, None))
		for p in process_pool: p.join()

		# Send kill signal to printer and wait
		printq.put((None, None))
		print_thread.join()

	except FileNotFoundError:
		for i in range(args.c*args.t):
			inwork.put((None, None))
		for p in process_pool: p.join()
		sys.exit(colorstring("[-] Wordlist file not found.", status="red"))

	except KeyboardInterrupt:
		for p in process_pool: p.terminate()
		end(t0, 1)
		sys.exit()

	# Delete big variables still in use
	del printq, inwork, seen, manager

	# Recursive calls with found directories
	for d in output:
		main_scan(s, ip, port, d, args, dir_depth+1, robots_content)

# Function: process worker. Starts one connection and a number of threads that perform requests on that connection.
def process_worker(s, ip, port, threads, method, head, length, blacklisted, verify, inwork, output, printq):
	conn = h2_connect(s, ip, port, verify)
	thread_pool = list()
	for i in range(threads):
		t = threading.Thread(target=thread_worker, args=(conn, method, head, length, blacklisted, inwork, output, printq))
		t.daemon = True
		t.start()
		thread_pool.append(t)

	for t in thread_pool: t.join()
	conn.close()

# Function: thread worker. For each entry in the inwork queue, sends one request and reads response status code
def thread_worker(conn, method, head, length, blacklisted, inwork, output, printq):
	global exit_status
	while True:
		directory, entry = inwork.get()
		if entry is None: break

		# Feedback on the last line of stdout
		printq.put((colorstring(entry, status=0), "\r"))

		try:
			sid = conn.request(method, directory + entry.replace(" ", "%20"), headers=head)
			resp = conn.get_response(sid)
		except hyper.http20.exceptions.StreamResetError:
			print(colorstring(f"[-] Warning: stream reset. Pausing thread for a bit in process with PID={os.getpid()} - should probably restart with less threads.", status="yellow"))
			time.sleep(STREAM_RESET_SLEEP)
			continue
		except ProtocolError as error:
			print(colorstring(f"[-] Error: protocol compliance error. Killing process with PID={os.getpid()}\n{error}", status="red"))
			conn.close()
			exit_status = 1
			os.kill(os.getpid(), signal.SIGTERM)
			break
		except ConnectionResetError as error:
			print(colorstring(f"[-] Error. connection reset. Killing process with PID={os.getpid()}\n{error}", status="red"))
			conn.close()
			exit_status = 1
			os.kill(os.getpid(), signal.SIGTERM)
			break

		st = resp.status
		headers = resp.headers
		if length:
			response_length = len(resp.read().decode("utf-8"))
			tail = f" ({response_length})"
		else:
			tail = ""

		# Print found entries
		if st not in blacklisted:
			if st in REDIRECT_HTTP_CODES:
				tail = tail + f" -> {headers.get(b'location')[0].decode('utf-8')}"
			else:
				if st == 200 and isdir(entry):
					output.append(directory + entry)
			printq.put((colorstring(f"[{st}] {directory}{entry}{tail}", status=st), "\n"))

# Function: thread worker that prints everything on the queue. References to this queue are given to all the scanning threads
def print_worker(printq):
	count = 0
	while True:
		item, end = printq.get()
		if item is None: break

		if end == "\n":
			print(item, end=end)
		elif end == "\r":
			count+=1
			if count == 30:
				print(item, end=end)
				count = 0			

# Function: prompt for 'opts' options
def prompt_select(msg, opts):
	c = None
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
			print(colorstring(f"[-] {ip}{':'+port if port not in (80, 443) else ''}{location} could not be read. Status: {status}", status="yellow"))
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
				c = prompt_select("Do you want to continue scanning?\n\t[Y/y] to continue\n\t[N/n] to exit\nSelected option: ", ("y", "n"))
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
				print("Should we use this information?")
				use_robots = prompt_select("\t[A/a] to use all entries\n\t[Y/y] to use only allowed entries\n\t[N/n] to ignore all entries.\nSelected option: ", ("a", "y", "n"))
				if use_robots == "a": out_entries = all_entries
				elif use_robots == "y": out_entries = allowed_entries
				else: out_entries = set()

			else:
				print(colorstring("[-] File contains no entries, nothing to use here.", status="yellow"))
				out_entries = set()

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
		location = resp.headers.get(b'location')[0].decode('utf-8')
		robots_content = get_robots_content(conn, location)

	else:
		robots_content = (False, resp.status, loc)

	return robots_content

# Main start point. Read, verify inputs and call main_scan()
if __name__ == '__main__':

	print(DASHLINE)
	print("h2buster v" + __version__)
	print(DASHLINE)

	# Read CLI inputs
	opts = ("w", "u", "c", "t", "m", "r", "hd", "x", "b", "l", "vr", "rb", "nc")
	mvar = (WORDLIST_MVAR, TARGET_MVAR, CNX_MVAR, THREADS_MVAR, HTTP_METHOD_MVAR, DIR_DEPTH_MVAR, HEADERS_MVAR, EXT_MVAR, BLACKLISTED_MVAR, RESPONSE_LENGTH_MVAR, VERIFYCERT_MVAR, ROBOTS_MVAR, NOCOLOR_MVAR)
	h = (WORDLIST_HELP, TARGET_HELP, CNX_HELP, THREADS_HELP, HTTP_METHOD_HELP, DIR_DEPTH_HELP, HEADERS_HELP, EXT_HELP, BLACKLISTED_HELP, RESPONSE_LENGTH_HELP, VERIFYCERT_HELP, ROBOTS_HELP, NOCOLOR_HELP)
	defaults = (WORDLIST_DEFAULT, TARGET_DEFAULT, CNX_DEFAULT, THREADS_DEFAULT, HTTP_METHOD_DEFAULT, DIR_DEPTH_DEFAULT, HEADERS_DEFAULT, EXT_DEFAULT, BLACKLISTED_DEFAULT, RESPONSE_LENGTH_DEFAULT, VERIFYCERT_DEFAULT, ROBOTS_DEFAULT, NOCOLOR_DEFAULT)
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	# Set NOCOLOR as global constant so colorstring() knows what to do
	if platform.system() == "Linux" or platform.system() == "Darwin":
		NOCOLOR = args.nc

	# Input checking
	try:
		args.r, args.c, args.t = int(args.r), int(args.c), int(args.t)
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
	args.b = set(args.b.split("|"))
	try: args.b = tuple(map(int, args.b))
	except ValueError: sys.exit(colorstring("[-] Blacklisted codes must be numerical.", status="red"))

	# Parse target URL
	s, ip, port, start_dir = parse_target(args.u)

	# Check if target is valid
	try:
		# Test HTTP/2 connection
		conn = h2_connect(s, ip, port, args.vr)
		sid = conn.request("GET", start_dir)
		resp = conn.get_response(sid)

		# Get robots.txt
		if args.rb:
			robots_content, robots_status, robots_location = get_robots_content(conn)

		# Server header
		try: server = resp.headers.get(b"server")[0].decode("utf-8")
		except TypeError: server = False

	except ConnectionResetError:
		sys.exit(colorstring("[-] Connection reset. Are you sure the target supports HTTP/2?", status="red"))
	except AssertionError:
		sys.exit(colorstring("[-] HTTP/2 not supported for that target.", status="red"))
	except gaierror as error:
		sys.exit(colorstring("[-] Could not get address information. Are you sure the target exists?", status="red"))
	except SSLError as error:
		sys.exit(colorstring(f"[-] TLS error.\n{error}", status="red"))
	except ProtocolError as error:
		sys.exit(colorstring(f"[-] Protocol compliance error:\n{error}", status="red"))
	except ConnectionRefusedError:
		sys.exit(colorstring("[-] Connection refused.", status="red"))
	except Exception as error:
		sys.exit(colorstring(f"[-] Error:\n{error}", status="red"))

	conn.close()
	print(colorstring("[+] Target supports HTTP/2", status="green"))
	if server: print(colorstring(f"[+] Target server: {server}", status="green"))

	# Print info
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

	# Print robots info
	if args.rb:
		print(DASHLINE)
		parsed_robots_content = parse_robots(ip, port, robots_content, robots_status, robots_location, args.hd.get("user-agent", "h2buster"))
	else:
		parsed_robots_content = frozenset()
	print(DASHLINE)

	# This variable can be changed by any of the threads
	exit_status = 0

	# Start timer (for benchmarking purposes)
	t0 = time.time()

	# Start recursive scan and exit when it returns
	main_scan(s, ip, port, start_dir, args, 0, parsed_robots_content)
	end(t0, exit_status)
