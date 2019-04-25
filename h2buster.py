#coding=utf-8

import hyper
import ssl, sys, time
import argparse

__author__ = "https://github.com/00xc/"
__version__ = "0.1d"

# Program information to be displayed with -h or --help
PROGRAM_INFO = "h2buster: an HTTP/2 web directory brute-force scanner."

# Maximum recursion depth for directories (minimum is 1)
MAX_RECURSION = 2

# This controls how often we read responses and update results on screen
# If this value is too high we're opening too many streams without reading responses
# If this value is too low we're reading too often (not using stream multiplexing effectively due to single thread)
UPDATE_THRESHOLD = 99

# Read inputs
def read_inputs(info, opts, h, defaults, mvar):
	import argparse
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
		s = 0
		ip = ip[0]
	else:
		if ip[0] == "http": s = 0
		elif ip[0] == "https": s = 1
		else: sys.exit("[-] Target not understood")
		ip = ip[1]
	return s, ip

# Connect to target and return connection object
def h2_connect(ip, s):
	# Get port
	if len(ip.split(":")) == 1:
		if s==1: port=443
		elif s==0: port=80
	else: port = int(ip.split(":")[-1])
	# Perform connection
	if s == 1:
		ctx = ssl.SSLContext()
		ctx.set_alpn_protocols(['h2'])
		ctx.verify_mode = ssl.CERT_NONE
		conn = hyper.HTTP20Connection(ip, port=port, ssl_context=ctx, enable_push=False)
	elif s == 0:
		conn = hyper.HTTP20Connection(ip, port=port, enable_push=False)
	# Test connectivity before starting the scan
	conn.ping("00000000")
	return conn

# Read responses, print results and return found directories
def dump_scan(requests):

	# List of directories that will be recursively scanned afterwards
	o = list()
	
	for url, sid in requests.items():
		resp = conn.get_response(sid)
		status = resp.status
		#resp.read() # Not reading the entire response improves performance, but might be needed in the future
		resp.close()

		# Print meaningful results
		if status != 404:
			if status==301 or status==302:
				ftype = " <REDIRECTION> -> " + resp.headers.get(b"location")[0].decode("utf-8")
			elif url[-1]=="/":
				o.append(url)
				ftype = " <DIRECTORY>"
			else: ftype = ""
			print("[+] " + url + ": " + str(status) + ftype)
	return o

# Scan directory over connection "conn" with dictionary "file"
def recursive_dirscan(conn, directory, file, ext, rec_level, max_rec_level):

	if rec_level >= max_rec_level: return

	print(" \n[*] Scanning " + directory)

	i = 0
	requests = dict()
	found = list()

	l = ["|", "/", "-", "\\"]
	t = 0

	with open(file, "r") as f:
		
		# Main loop
		for entry in f:
			entry = entry.rstrip()

			if entry == "/" or entry=="": continue

			for ex in ext:
				# Rotating bar
				if int(time.time())%5==0:
					print(l[t], end="\r")
					t = (t+1)%4
				# Don't need to scan entry.php/ so we skip it
				if entry.split(".")[-1] in ext and ex=="/": continue
				# Prevent flood
				time.sleep(0.05)
					
				if i>UPDATE_THRESHOLD:
					found += dump_scan(requests)
					requests.clear()
					i = 0

				# Perform request and store stream ID
				sid = conn.request("HEAD", directory + entry + ex)
				requests[directory + entry + ex] = sid
				i += 1

		found += dump_scan(requests)

		# Recursively scan found directories
		for fd in found:
			recursive_dirscan(conn, fd, file, ext, rec_level+1, max_rec_level)

if __name__ == "__main__":

	print("--------------------------------")
	print("h2buster v" + __version__)
	print("--------------------------------\n")

	# For benchmarking purposes
	t0 = time.time()

	# For every entry in the dictionary, every extension will be checked
	ext = ["/", "",".php", ".html", ".htm", ".asp", ".js", ".css"]

	# Input reading
	opts = ["w", "u", "r"]
	mvar = ["wordlist", "target", "recursion_depth"]
	h = ["Directory wordlist", "Target URL", "Maximum directory recursion depth. Minimum is 1, default is 2."]
	defaults = [None, None, 2]	# None => argument is required
	args = read_inputs(PROGRAM_INFO, opts, h, defaults, mvar)

	try:

		# Input checking
		args.r = int(args.r)
		if args.r<1:
			sys.exit("[-] Recursion depth must be greater than 1.")

		# Check HTTP/HTTPS and start connection
		s, ip = check_tls(args.u)
		conn = h2_connect(ip, s)
		print("[*] Starting scan on " + ip)
		print("[*] recursion_depth = " + str(args.r))

		# Main function
		recursive_dirscan(conn, "/", args.w, ext, 0, args.r)
		conn.close()

		print(" \n[*] Program ran in " + str(round(time.time()-t0, 3)) + " seconds.")

	except ValueError:
		print("[-] Recursion depth must be a numeric value.")

	except OSError as ose:
		print(ose)

	except FileNotFoundError:
		print("[-] File not found.")

	except AssertionError:
		print("[-] That target does not support HTTP/2.")

	except KeyboardInterrupt:
		conn.close()
		print("\r[-] Scan aborted after " + str(round(time.time()-t0, 3)) + " seconds.")