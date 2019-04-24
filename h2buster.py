#coding=utf-8

__author__ = "https://github.com/00xc/"
__version__ = "0.1a"

import hyper
import ssl, sys, time

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

	# List of directories that didn't return 404
	o = list()

	for key, element in requests.items():
		resp = conn.get_response(element)
		status = resp.status
		#resp.read(decode_content=True) # This seems to improve performance
		resp.close()

		# Print meaningful results
		if status != 404:
			if key[-1] == "/":
				o.append(key)
				ftype = " <DIR>"
			else: ftype = ""
			print("[+] " + key + ": " + str(status) + ftype)

			# Print redirection location?
			#if status == 301: print(resp.headers)
	return o

# Scan directory over connection "conn" with dictionary "file". Admits recursion.
def recursive_dirscan(conn, directory, file, ext):

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
				# Prevent flood
				time.sleep(0.05)
				# Rotating bar
				if int(time.time())%5==0:
					print(l[t], end="\r")
					t = (t+1)%4
					
				# This controls how often we read responses and update results
				# If this value is too high we're opening too many streams without reading responses
				# If this value is too low we're reading too often (not using stream multiplexing effectively due to single thread)
				# This value (20) is eyeballed, it should be tested more thoroughly
				if i>20:
					found += dump_scan(requests)
					requests.clear()
					i = 0

				# Don't need to scan entry.php/ so we skip it
				if len(entry.split(".")[-1]) in ext and ex=="/": continue
				# Perform request and store stream ID
				sid = conn.request("HEAD", directory + entry + ex)
				requests[directory + entry + ex] = sid
				i += 1

		found += dump_scan(requests)

		# Recursively scan found directories
		for fd in found:
			print(" \n[*] Scanning " + fd)
			recursive_dirscan(conn, fd, file, ext)

if __name__ == "__main__":

	print("--------------------------------")
	print("h2buster v" + __version__)
	print("--------------------------------\n")

	try:

		# For benchmarking purposes
		t0 = time.time()
		# Some basic input checking
		if len(sys.argv)<3:
			print("Usage: " + sys.argv[0] + " <dictionary> <target>")
			sys.exit()
		file = sys.argv[1]
		ip = sys.argv[2]

		# For every entry in the dictionary, every extension will be checked
		ext = ["/", ".php", ".html", ".htm", ".asp", ".js", ".css"]

		# Check HTTP/HTTPS
		s, ip = check_tls(ip)
		# Open connection
		conn = h2_connect(ip, s)
		print("[*] Starting scan on " + ip)

		# Main function
		recursive_dirscan(conn, "/", file, ext)

		print("\n[*] Program ran in " + str(round(time.time()-t0, 3)) + " seconds")

	except OSError as ose:
		print(ose)

	except FileNotFoundError:
		print("[-] File not found")

	except AssertionError:
		print("[-] H2 not supported for that target")

	except KeyboardInterrupt:
		print("\r[-] Scan aborted")
