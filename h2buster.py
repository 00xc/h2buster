import hyper
import threading, queue
import ssl, sys, time, argparse
import multiprocessing

# Metadata variables, program constants and global variables.
__author__ = "https://github.com/00xc/"
__version__ = "0.3a"

PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."
DASHLINE = "------------------------------------------------"

WORDLIST_MVAR = "wordlist"
TARGET_MVAR = "target"
DIR_DEPTH_MVAR = "directory_depth"
CNX_MVAR = "connections"
THREADS_MVAR = "threads"

WORDLIST_DEFAULT = None
TARGET_DEFAULT = None
DIR_DEPTH_DEFAULT = 2
CNX_DEFAULT = 3
THREADS_DEFAULT = 15

WORDLIST_HELP = "Directory wordlist"
TARGET_HELP = "Target URL/IP address. Default port is 443 and HTTPS enabled. To specify otherwise, use ':port' or 'http://' (port will default to 80 then)."
DIR_DEPTH_HELP = "Maximum recursive directory depth. Minimum is 1, default is " + str(DIR_DEPTH_DEFAULT) + ", unlimited is 0."
CNX_HELP = "Number of HTTP/2 connections. Default is " + str(CNX_DEFAULT) + "."
THREADS_HELP = "Number of threads per connection. Default is " + str(THREADS_DEFAULT) + "."

TIMESTAMP_ROUND = 3
TLS_DEFAULT = 1

ext = ["/", "" ,".php", ".html", ".asp", ".js", ".css"]

# Function: return time since t0
def timestamp(t0):
	t = str(round(time.time() - t0, TIMESTAMP_ROUND))
	return t

# Function: return True if entry is a directory, False otherwise.
def isdir(e):
	if e == "/": return False

	if len(e)>0 and e[-1]=="/":
		if e.count(".") > 0:
			if any([len(x)==0 for x in e.split(".")]):
				return True
			else:
				return False
		else: return True
	else:
		return False

# Function: read "opts" options from command line interface
def read_inputs(info, opts, h, defaults, mvar):
	parser = argparse.ArgumentParser(description=info)
	for i, o in enumerate(opts):
		if defaults[i]==None: req = True
		else: req = False
		parser.add_argument("-"+o, help=h[i], default=defaults[i], required=req, metavar=mvar[i])
	args = parser.parse_args()
	return args

# Function: parse input target and decide h2 or h2c
def parse_target(target):
	target = target.split("://")
	if len(target) == 1:
		s = TLS_DEFAULT
		url = target[0]
	else:
		url = target[1]
		if target[0] == "http": s = 0
		elif target[0] == "https": s = 1
		else: sys.exit("[-] Target not understood")

	url = url.split("/", 1)
	ip = url[0]
	if len(url)==1 or len(url[1])==0:
		start_dir = "/"
	else: 
		start_dir = "/" + url[1]
		if start_dir[-1] != "/": start_dir = start_dir + "/"

	return ip, start_dir, s

# Function: connect via H2 to specified IP[:port]. s=1 means TLS, s=0 means h2c
def h2_connect(s, ip):
	# Get port
	if len(ip.split(":")) == 1:
		if s==1: port=443
		elif s==0: port=80
	else:
		try: port = int(ip.split(":")[-1])
		except ValueError: sys.exit("[-] Invalid URL")
	# Start connection
	if s == 1:
		ctx = ssl.SSLContext()
		ctx.set_alpn_protocols(['h2'])
		ctx.verify_mode = ssl.CERT_NONE
		conn = hyper.HTTP20Connection(ip, port=port, ssl_context=ctx, enable_push=False)
	elif s == 0:
		conn = hyper.HTTP20Connection(ip, port=port, enable_push=False)
	try: conn.connect()
	except AssertionError: sys.exit("[-] H2 not supported for that target.")
	return conn, port

# Function: main scan function. Starts up a number of processes which handle their own h2 connection and sends them entries to scan
def main_scan(s, ip, directory, wordlist, dir_depth, max_depth, connections, threads):

	if max_depth!=0:
		if dir_depth >= max_depth: return
	global ext

	print("\n[*] Starting scan on " + directory)

	# Start input/output queues
	manager = multiprocessing.Manager()
	output = manager.list()
	inwork = manager.Queue(connections)

	# Start connections
	pool = list()
	for i in range(connections):
		p = multiprocessing.Process(target=process_worker, args=(s, ip, threads, inwork, output))
		p.daemon = True
		p.start()
		pool.append(p)

	# Put work
	c = 0
	try:
		with open(wordlist, "r") as f:
			for entry in f:
				entry = entry.rstrip()
				for ex in ext:
					c+=1
					inwork.put((directory, entry+ex))
	except FileNotFoundError:
		for i in range(connections*threads):
			inwork.put((None, None))
		for p in pool: p.join()
		sys.exit("[-] Wordlist file not found.")

	# Send kill signals
	for i in range(connections*threads):
		inwork.put((None, None))

	# Block until processes are done
	for p in pool: p.join()

	# Recursive calls with found directories
	for d in output:
		main_scan(s, ip, d, wordlist, dir_depth+1, max_depth, connections, threads)

# Function: process worker. Starts a connection and a number of threads that perform requests on that connection.
def process_worker(s, ip, threads, inwork, output):
	conn, port = h2_connect(s, ip)

	threadpool = list()
	for i in range(threads):
		t = threading.Thread(target=thread_worker, args=(conn, inwork, output))
		t.daemon = True
		t.start()
		threadpool.append(t)

	for t in threadpool: t.join()
	conn.close()

# Function: thread worker. For each entry in the inwork queue, sends one request and reads response status code
def thread_worker(conn, inwork, output):
	while True:
		directory, entry = inwork.get()
		if entry is None: break

		sid = conn.request("HEAD", directory + entry.replace(" ", "%20"))
		resp = conn.get_response(sid)

		st = resp.status
		headers = resp.headers

		if st!=404:
			if st==301 or st==302: tail = " -> " + headers.get(b"location")[0].decode("utf-8")
			else:
				tail = ""
				if st==200 and isdir(entry):
					output.append(directory + entry)
			print("".join([directory, entry, ": ", str(st), tail]))

# Main start point. Read, verify inputs and call main_scan()
if __name__ == '__main__':

	print(DASHLINE)
	print("h2buster v" + __version__)
	print(DASHLINE)

	# Read CLI inputs
	opts = ["w", "u", "r", "c", "t"]
	mvar = [WORDLIST_MVAR, TARGET_MVAR, DIR_DEPTH_MVAR, CNX_MVAR, THREADS_MVAR]
	h = [WORDLIST_HELP, TARGET_HELP, DIR_DEPTH_HELP, CNX_HELP, THREADS_HELP]
	defaults = [WORDLIST_DEFAULT, TARGET_DEFAULT, DIR_DEPTH_DEFAULT, CNX_DEFAULT, THREADS_DEFAULT]
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	# Input checking
	try:
		args.r = int(args.r)
		args.c = int(args.c)
		args.t = int(args.t)
		if args.t<1 or args.c<1 or args.r<0:
			sys.exit("[-] " + CNX_MVAR + " and " + THREADS_MVAR + " must be greater than zero. " + DIR_DEPTH_MVAR + " must be greater than or equal to zero.")
	except ValueError:
		sys.exit("[-] Invalid non-numerical option introduced")

	# Start timer (for benchmarking purposes)
	t0 = time.time()

	# Parse target URL
	ip, start_dir, s = parse_target(args.u)

	# Print info
	print("[*] Initializing scan on " + ip)
	if s==1: print("[*] TLS is ON")
	else: print("[*] TLS is OFF\n")
	print("[*] Base directory: " + start_dir)
	print("[*] Maximum directory depth: " + str(args.r) + " (base directory is depth 1)")
	print("[*] Checking for file extensions: " + ", ".join(["'"+ex+"'" for ex in ext]))
	print("[*] Number of connections: " + str(args.c))
	print("[*] Number of threads per connection: " + str(args.t))
	print(DASHLINE)

	# Start main scan which will call itself for each found directory
	main_scan(s, ip, start_dir, args.w, 0,  args.r, args.c, args.t)

	print("\n[*] Program ran in " + timestamp(t0) + " seconds")