import fnmatch
import random, string

class NotfoundWildcard:

	__slots__ = (
		"request_string",
		"status",
		"redirect",
		"real_redirect",
		"content",
		"real_content",
		"response_length"
	)

	def __init__(self, connection, method, redirect_codes):
		self.request_string = "/" + "".join((random.choice(string.ascii_lowercase) for _ in range(20)))
		sid = connection.request(method, self.request_string)
		resp = connection.get_response(sid)

		if resp.status in redirect_codes:
			self.redirect = resp.headers.get(b'location')[0].decode('utf-8')
			self.real_redirect = self.redirect.replace(self.request_string, "")
		else:
			self.redirect = False
			self.real_redirect = False

		self.content = resp.read().decode('utf-8')
		self.real_content = self.content.replace(self.request_string, "")
		self.response_length = len(self.content)
		self.status = resp.status

	def match(self, request_string, content, status, redirect):
		if status == 404:
			return False

		if self.redirect and redirect:
			return (self.real_redirect == redirect.replace(request_string, ""))

		elif self.response_length > 0 and len(content) > 0:
			return (self.real_content == content.replace(request_string, ""))

		else:
			return False

class RobotParser:

	def __init__(self, user_agent=""):
		self.user_agent = user_agent
		self.entries = set()
		self.sitemaps = set()

	def parse(self, content, policy="allow"):
		policy = policy.lower()
		if policy not in ("all",  "allow"):
			raise ValueError("Invalid robot policy.")

		# Initialize variables for this parsing call
		self.entries = set()
		self.sitemaps = set()
		disallowed = set()
		applies = False
		content = content.split("\n")

		# Loop over robots.txt content
		for line in content:
			if len(line) == 0 or line[0] == "#" or line.count(":") == 0: continue
			line = tuple([x.lstrip().split("$")[0] for x in line.rstrip().lower().split(":", 1)])

			# Rules for a specific useragent
			if line[0] == "user-agent":
				if policy=="allow" and fnmatch.filter(self.user_agent, line[1]):
					applies = True
				else:
					applies = False

			# Entry for a specific URI
			elif line[0] in ("allow", "disallow"):
				if (not applies and line[1] not in disallowed) or (applies and line[0] == "allow"):
					if len(line[1])>0:
						self.entries.add(line[1])

				elif applies and line[0] == "disallow":
					disallowed.add(line[1])
					self.entries.discard(line[1])

			# URL for a sitemap
			elif line[0] == "sitemap":
				self.sitemaps.add(line[1])

	def get_entries(self):
		return self.entries

	def get_sitemaps(self):
		return self.sitemaps


class UrlParser:

	def __init__(self, default_secure=True, default_port=443):
		self.default_secure = default_secure
		self.default_port = default_port

	def parse(self, url):

		# Remove GET parameters
		if url.count("?") > 0:
			target, params = url.split("?", 1)
		else:
			target = url
			params = ""

		# Protocol
		target = target.split("://", 1)
		if len(target) == 1:
			url = target[0]
			s = None
		else:
			target[0] = target[0].lower()
			url = target[1]
			if target[0] == "http": s = False
			elif target[0] == "https": s = True
			else: raise ValueError("Invalid URL: protocol scheme not recognized.")
			
		# Directory 
		url = url.split("/", 1)
		tup = url[0]
		if len(url) == 1 or len(url[1])==0:
			directory = "/"
		else:
			directory = "/" + url[1]
			if directory[-1]!="/": directory = directory + "/"	# force URIs to end in '/'

		# IP / port
		if tup.count(":") == 0:
			ip = tup
			if s == True: port = 443
			elif s == False: port = 80
			else:
				s = self.default_secure
				port = self.default_port
		elif tup.count(":") == 1:
			try:
				ip, port = tup.split(":", 1)
				port = int(port)
			except ValueError: raise ValueError("Invalid URL: Non-numeric port.")

			if port == 80 and target[0]!="https": s = False
			else: s = True
			
		else:
			raise ValueError("Invalid URL: parsing error.")

		# Save values to object properties
		self.secure = s
		self.host = ip
		self.port = port
		self.path = directory
		self.params = params