import hyper
import threading, queue, multiprocessing
import ssl, sys, time, argparse
import platform
from socket import gaierror
from ssl import SSLError
from h2.exceptions import ProtocolError

# Metadata variables
__author__ = "https://github.com/00xc/"
__version__ = "0.3e-1"

PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."
DASHLINE = "------------------------------------------------"

# CLI options metavariable names
WORDLIST_MVAR = "wordlist"
TARGET_MVAR = "target"
DIR_DEPTH_MVAR = "directory_depth"
CNX_MVAR = "connections"
THREADS_MVAR = "threads"
NOCOLOR_MVAR = ""
EXT_MVAR = "extension_list"
HEADERS_MVAR = "header_list"

# CLI options default values.
# None means required. Boolean means that the option has no argument (either the flag is there or not)
WORDLIST_DEFAULT = None
TARGET_DEFAULT = None
DIR_DEPTH_DEFAULT = 2
CNX_DEFAULT = 3
THREADS_DEFAULT = 20
NOCOLOR_DEFAULT = False
EXT_DEFAULT = "/|blank|.html|.php"
HEADERS_DEFAULT = "user-agent->Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/74.0.3729.169 Chrome/74.0.3729.169 Safari/537.36"

# CLI options help strings
WORDLIST_HELP = "Directory wordlist"
TARGET_HELP = "Target URL/IP address (host[:port]). Default port is 443 and HTTPS enabled. To specify otherwise, use ':port' or 'http://' (port will default to 80 then)."
DIR_DEPTH_HELP = "Maximum recursive directory depth. Minimum is 1, default is " + str(DIR_DEPTH_DEFAULT) + ", unlimited is 0."
CNX_HELP = "Number of HTTP/2 connections. Default is " + str(CNX_DEFAULT) + "."
THREADS_HELP = "Number of threads per connection. Default is " + str(THREADS_DEFAULT) + "."
NOCOLOR_HELP = "Disable colored output text."
EXT_HELP = "List of file extensions to check separated by a vertical bar. For example, -x '.php|.js|blank|/' will check .php, .js, blank and / for every wordlist entry. The 'blank' keyword signifies no file extension. Default extensions are " + ", ".join(["'"+ex+"'" for ex in EXT_DEFAULT.split("|")])
HEADERS_HELP = "List of headers in the format 'header->value[|header->value|header->value...]'. For example: -hd 'user-agent->Mozilla/5.0|accept-encoding->gzip, deflate, br'."

# Other hardcoded values
TIMESTAMP_ROUND = 3
TLS_ON = True
TLS_OFF = False
TLS_PORT = 443

# Define colors and color functions (only Linux and OS X)
if platform.system() == "Linux" or platform.system() == "Darwin":
	COLOR_200 = '\033[92m' # green
	COLOR_301 = '\033[94m' # blue
	COLOR_302 = '\033[94m' # blue
	COLOR_303 = '\033[94m' # blue
	COLOR_400 = '\033[91m' # red
	COLOR_403 = '\033[93m' # yellow
	COLOR_ERROR = '\033[91m' # red
	COLOR_END = '\033[0m' # end color
	COLOR_BOLD = '\033[1m' # bold

	# Function: return line with colors according to status code
	def colorstring(s, status=0, overwrite=False):
		global NOCOLOR
		s = "\x1b[K" + s
		if status==0 or NOCOLOR==True: return s
		else:
			try:
				start = globals()["COLOR_" + str(status)]
				end = COLOR_END
				return "".join([start, s, end])
			except KeyError:
				return s
else:
	# This function is a mess trying to keep things readable in (old) Windows CMD
	# status = 0 will return a blank string
	def colorstring(s, status=0):
		if status == "INFO":
			# Extremely hacky solution to clear last line of stdout on Windows cmd
			return ("\t\t\t\t\t\t.\r").rstrip() + s
		elif status!=0:
			# The only inputs without a status are the feedback prints, so we can suppress them (we can't clear last line in Windows cmd easily)
			return s
		else:
			return ""

# Function: return time since t0
def timestamp(t0):
	return str(round(time.time() - t0, TIMESTAMP_ROUND))

# Function: return True if entry is a directory, False otherwise.
def isdir(e):
	if e == "/" or len(e)==0 or e[-1]!="/": return False
	if e.count(".")==0 or any([len(x)==0 for x in e.split(".")]):
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

	# Protocol
	target = target.split("://")
	if len(target) == 1:
		url = target[0]
		s = None
	else:
		url = target[1]
		if target[0] == "http": s = TLS_OFF
		elif target[0] == "https": s = TLS_ON
		else: sys.exit(colorstring("[-] Invalid URL", status="ERROR"))
		
	# Directory 
	url = url.split("/", 1)
	tup = url[0]
	if len(url) == 1 or len(url[1])==0:
		directory = "/"
	else:
		directory = "/" + url[1]
		if directory[-1]!="/": directory = directory + "/"

	# IP / port
	if tup.count(":") == 0:
		ip = tup
		if s==TLS_ON: port = 443
		elif s==TLS_OFF: port = 80
		else:
			s = TLS_ON
			port = TLS_PORT
	elif tup.count(":") == 1:
		try:
			ip, port = tup.split(":", 1)
			port = int(port)
		except ValueError:
			sys.exit(colorstring("[-] Invalid URL", status="ERROR"))
		if port == 80 and target[0]!="https":
			s = TLS_OFF
		else:
			s = TLS_ON
	else:
		sys.exit(colorstring("[-] Invalid URL", status="ERROR"))

	return s, ip, port, directory

# Function: parse input headers
def parse_header_opt(hd):
	try:
		hd = hd.split("|")
		out = dict()
		for e in hd:
			if len(e)<4: continue
			h, v = e.split("->", 1)
			out[h] = v
		return out
	except ValueError:
		sys.exit(colorstring("[-] Invalid " + HEADERS_MVAR + " value.", status="ERROR"))

# Function: connect via H2 to specified IP[:port] and return connection object
def h2_connect(s, ip, port):
	if s == TLS_ON:
		ctx = ssl.SSLContext()
		ctx.set_alpn_protocols(['h2'])
		ctx.verify_mode = ssl.CERT_NONE
		conn = hyper.HTTP20Connection(ip, port=port, ssl_context=ctx, enable_push=False)
	elif s == TLS_OFF:
		conn = hyper.HTTP20Connection(ip, port=port, enable_push=False)
	conn.connect()
	return conn

# Function: main scan function. Starts up a number of processes which handle their own h2 connection and sends them entries to scan
def main_scan(s, ip, port, directory, args, dir_depth):

	if args.r!=0:
		if dir_depth >= args.r: return

	print(colorstring("\n[*] Starting scan on " + directory, status="INFO"))

	# Start input/output queues
	manager = multiprocessing.Manager()
	output = manager.list()
	inwork = manager.Queue(args.c)

	# Start connections
	pool = list()
	for i in range(args.c):
		p = multiprocessing.Process(target=process_worker, args=(s, ip, port, args.t, args.hd, inwork, output))
		p.daemon = True
		p.start()
		pool.append(p)

	# Put work
	try:
		with open(args.w, "r") as f:
			for entry in f:
				if entry[0]=="#": continue
				entry = entry.rstrip()
				for ex in args.x:
					inwork.put((directory, entry+ex))
	except FileNotFoundError:
		for i in range(args.c*args.t):
			inwork.put((None, None))
		for p in pool: p.join()
		sys.exit(colorstring("[-] Wordlist file not found.", status="ERROR"))

	# Send kill signals
	for i in range(args.c*args.t):
		inwork.put((None, None))

	# Block until processes are done
	for p in pool: p.join()

	# Recursive calls with found directories
	for d in output:
		main_scan(s, ip, port, d, args, dir_depth+1)

# Function: process worker. Starts a connection and a number of threads that perform requests on that connection.
def process_worker(s, ip, port, threads, head, inwork, output):
	conn = h2_connect(s, ip, port)

	threadpool = list()
	for i in range(threads):
		t = threading.Thread(target=thread_worker, args=(conn, head, inwork, output))
		t.daemon = True
		t.start()
		threadpool.append(t)

	for t in threadpool: t.join()
	conn.close()

# Function: thread worker. For each entry in the inwork queue, sends one request and reads response status code
def thread_worker(conn, head, inwork, output):
	while True:
		directory, entry = inwork.get()
		if entry is None: break

		# Feedback on the last line of stdout
		print(colorstring(entry, status=0), end="\r")

		sid = conn.request("HEAD", directory + entry.replace(" ", "%20"), headers=head)
		try: resp = conn.get_response(sid)
		except hyper.http20.exceptions.StreamResetError:
			print(colorstring("[-] Warning: stream reset", status="403"))
			inwork.put((directory, entry))
			continue

		st = resp.status
		headers = resp.headers

		if st!=404:
			if st==301 or st==302 or st==303: tail = " -> " + headers.get(b"location")[0].decode("utf-8")
			else:
				tail = ""
				if st==200 and isdir(entry):
					output.append(directory + entry)
			print(colorstring("".join([directory, entry, ": ", str(st), tail]), status=st))

# Main start point. Read, verify inputs and call main_scan()
if __name__ == '__main__':

	print(DASHLINE)
	print("h2buster v" + __version__)
	print(DASHLINE)

	# Read CLI inputs
	opts = ["w", "u", "c", "t", "r", "hd", "x", "nc"]
	mvar = [WORDLIST_MVAR, TARGET_MVAR, CNX_MVAR, THREADS_MVAR, DIR_DEPTH_MVAR, HEADERS_MVAR, EXT_MVAR, NOCOLOR_MVAR]
	h = [WORDLIST_HELP, TARGET_HELP, CNX_HELP, THREADS_HELP, DIR_DEPTH_HELP, HEADERS_HELP, EXT_HELP, NOCOLOR_HELP]
	defaults = [WORDLIST_DEFAULT, TARGET_DEFAULT, CNX_DEFAULT, THREADS_DEFAULT, DIR_DEPTH_DEFAULT, HEADERS_DEFAULT, EXT_DEFAULT, NOCOLOR_DEFAULT]
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	# Set NOCOLOR as global constant so colorstring() knows what to do
	if platform.system() == "Linux" or platform.system() == "Darwin":
		NOCOLOR = args.nc

	# Input checking
	try:
		args.r = int(args.r)
		args.c = int(args.c)
		args.t = int(args.t)
		if args.t<1 or args.c<1 or args.r<0:
			sys.exit(colorstring("[-] " + CNX_MVAR + " and " + THREADS_MVAR + " must be greater than zero. " + DIR_DEPTH_MVAR + " must be greater than or equal to zero.", status="ERROR"))
	except ValueError:
		sys.exit(colorstring("[-] Invalid non-numerical option introduced", status="ERROR"))

	# Parse file extensions and headers
	args.x = list(set(args.x.replace("blank", "").split("|")))
	args.hd = parse_header_opt(args.hd)

	# Start timer (for benchmarking purposes)
	t0 = time.time()

	# Parse target URL
	s, ip, port, start_dir = parse_target(args.u)

	# Check if target is valid
	try:
		conn = h2_connect(s, ip, port)
		sid = conn.request("HEAD", start_dir)
		resp = conn.get_response(sid)
		try:
			server = resp.headers.get(b"server")[0].decode("utf-8")
		except TypeError:
			server = False
	except ConnectionResetError:
		conn.close()
		sys.exit(colorstring("[-] Connection reset. Are you sure the target supports HTTP/2?", status="ERROR"))
	except AssertionError:
		sys.exit(colorstring("[-] HTTP/2 not supported for that target.", status="ERROR"))
	except gaierror:
		sys.exit(colorstring("[-] Could not get address information. Are you sure the target exists?", status="ERROR"))
	except SSLError:
		sys.exit(colorstring("[-] Unkown TLS error.", status="ERROR"))
	except ProtocolError as e:
		sys.exit(colorstring("[-] Protocol compliance error:\n" + str(e), status="ERROR"))
	except ConnectionRefusedError:
		sys.exit(colorstring("[-] Connection refused.", status="ERROR"))

	conn.close()
	print(colorstring("[+] Target supports HTTP/2", status=200))
	if server: print(colorstring("[+] Target server: " + server, status=200))

	# Print info
	print("[*] Initializing scan on " + colorstring(ip, status="BOLD"))
	if s==TLS_ON: print("[*] TLS is ON")
	else: print("[*] TLS is OFF")
	print("[*] Base directory: " + start_dir)
	print("[*] Maximum directory depth: " + str(args.r) + " (base directory is depth 1)")
	print("[*] File extensions: " + ", ".join(["'"+ex+"'" for ex in args.x]))
	print("[*] Headers:")
	for k, e in args.hd.items():
		print("\t" + k + ": " + e)
	print("[*] Number of connections: " + str(args.c))
	print("[*] Number of threads per connection: " + str(args.t))
	print(DASHLINE)

	# Start recursive scan
	main_scan(s, ip, port, start_dir, args, 0)

	print(colorstring("\n[*] Program ran in " + timestamp(t0) + " seconds", status="INFO"))