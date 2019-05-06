import hyper
import threading, queue
import ssl, sys, time, argparse
import urllib.parse
from socket import gaierror

__author__ = "https://github.com/00xc/"
__version__ = "0.2"
PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."
QUEUE_LIMIT = 100000

# Global variable of extensions
ext = ["/", "" ,".php", ".html", ".asp", ".js", ".css"]

# Read "opts" options from command line
def read_inputs(info, opts, h, defaults, mvar):
	parser = argparse.ArgumentParser(description=info)
	for i, o in enumerate(opts):
		if defaults[i]==None: req = True
		else: req = False
		parser.add_argument("-"+o, help=h[i], default=defaults[i], required=req, metavar=mvar[i])
	args = parser.parse_args()
	return args

# Parse target and check if its HTTPS
def check_tls(ip):
	ip = ip.split("://")
	if len(ip) == 1:
		s = 1
		ip = ip[0]
	else:
		if ip[0] == "http": s = 0
		elif ip[0] == "https": s = 1
		else: sys.exit("[-] Target not understood")
		ip = ip[1]
	return ip, s

# Connect to target and return connection object
def h2_connect(ip, s):
	# Get port
	if len(ip.split(":")) == 1:
		if s==1: port=443
		elif s==0: port=80
	else: port = int(ip.split(":")[-1])
	# Start connection
	if s == 1:
		ctx = ssl.SSLContext()
		ctx.set_alpn_protocols(['h2'])
		ctx.verify_mode = ssl.CERT_NONE
		conn = hyper.HTTP20Connection(ip, port=port, ssl_context=ctx, enable_push=False)
	elif s == 0:
		conn = hyper.HTTP20Connection(ip, port=port, enable_push=False)
	# Test connectivity before starting the scan
	try: conn.connect()
	except AssertionError: sys.exit("H2 not supported for that target.")
	except gaierror as excp: sys.exit(excp)
	except Exception as excp: sys.exit(excp)
	conn.ping("00000000")
	return conn, port

# Thread function
def stream_worker(q, conn, output):
	global ext
	results = dict()
	redirections = dict()

	try:
		while True:
			# Retrieve dictionary entry
			directory, entry = q.get()
			if entry is None: break
			entry = entry.rstrip()
			if entry=="":
				q.task_done()
				continue

			# Scan wordlist entry with all extensions
			for ex in ext:
				sid = conn.request("HEAD", directory + urllib.parse.quote_plus(entry) + ex)
				resp = conn.get_response(sid)
				results[directory + entry + ex] = resp.status
				if resp.status==301 or resp.status==302:
					try: redirections[directory + entry + ex] = resp.headers.get(b"location")[0].decode("utf-8")
					except TypeError: redirections[directory + entry + ex] = "NULL"

			# Print results
			for url, st in results.items():
				if st!=404:
					if st==301 or st==302: tail = " -> " + redirections[url]
					else:
						tail = ""
						if url[-1]=="/" and st!=400: output.put(url)
					print(url + ": " + str(st) + tail)

			results.clear()
			redirections.clear()
			q.task_done()
	except Exception as exc: sys.exit(exc)

# Recursive threaded scan for a specific directory
def threaded_scan(conn, directory, file, rec_level, max_rec, nthreads):

	if rec_level >= max_rec: return

	# Input and output queues work and results for the threads
	work = queue.Queue(QUEUE_LIMIT)
	output = queue.Queue(QUEUE_LIMIT)

	# Start threads
	threads = list()
	for i in range(nthreads):
		t = threading.Thread(target=stream_worker, args=(work, conn, output))
		t.daemon = True
		t.start()
		threads.append(t)
		time.sleep(0.05)

	print("\n[*] Starting scan on " + directory)

	# Put entries to be scanned into work queue
	with open(file, "r") as f:
		for entry in f:
			work.put((directory, entry))

	# Block until the queue is over
	work.join()

	# Send stop signal to threads
	for i in range(nthreads):
		work.put(("", None))
	for t in threads:
		t.join()

	# Call recursively with each found directory
	while not output.empty():
		fd = output.get()
		threaded_scan(conn, fd, file, rec_level+1, max_rec, nthreads)

if __name__ == '__main__':

	print("--------------------------------")
	print("h2buster v" + __version__)
	print("--------------------------------")

	# Input reading
	opts = ["w", "u", "r", "t"]
	mvar = ["wordlist", "target", "directory_depth", "threads"]
	h = ["Directory wordlist", "Target URL/IP address. Default port is 443 with HTTPS. To specify otherwise, use ':port' or 'http://' (port will default to 80 then).", "Maximum directory depth. Minimum is 1, default is 2.", "Number of threads. Default is 10."]
	defaults = [None, None, 2, 10]  # None => argument is required
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	try:
		# Input checking
		try:
			args.r = int(args.r)
			args.t = int(args.t)
			if args.t<1 or args.r<1:
				sys.exit("\n[-] threads and recursion_depth must be greater than zero.")
		except ValueError:
			sys.exit("\n[-] Invalid non-numerical option introduced.")

		# For benchmarking purposes
		t0 = time.time()

		# Check wheter we should use HTTP or HTTPS and start connection
		ip, s = check_tls(args.u)
		conn, port = h2_connect(ip, s)

		print("[+] Connected to " + ip + " on port " + str(port))
		if s==1: print("[*] TLS is ON")
		else: print("[*] TLS is OFF")
		print("[*] Number of threads: " + str(args.t))
		print("[*] Directory depth: " + str(args.r))

		# Start threaded scan. This will call itself recursively with found directories args.r-1 times
		try: threaded_scan(conn, "/", args.w, 0, args.r, args.t)
		except Exception as exc: sys.exit(exc)

		conn.close()

		print(" \n[*] Program ran in " + str(round(time.time()-t0, 3)) + " seconds.")

	except KeyboardInterrupt:
		conn.close()
		print("\r[-] Scan aborted after " + str(round(time.time()-t0, 3)) + " seconds.")
