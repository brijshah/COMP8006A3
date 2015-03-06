#-----------------------------------------------------------------------------
#--	SOURCE FILE:	py_ips -   A simple IPS written in python
#--
#--	CLASSES:		EventHandler
#--					Connections
#--
#--	FUNCTIONS:		EventHandler:
#--						process_IN_MODIFY(event)
#--					Connections:
#--						failed_attempt(service)
#--						reset_attempts(service)
#--					ban_ip(ip, service)
#--					unban_ip(ip, service)
#--					handle_attempt(line, service)
#--					load_cfg()
#--					get_last_lines(file, keyword)
#--					def main()
#--
#--	DATE:			February 28, 2015
#--
#--	DESIGNERS:		David Wang
#--					Brij Shah
#--
#--	PROGRAMMERS:	David Wang
#--					Brij Shah
#--
#--	NOTES:
#--	This script runs as an intrusion detection/prevention system that carries
#--	out the following tasks:
#-- 1) monitors the log files of user's choice using the config file
#-- 2) detects the number of attempts by a particular IP that has gone over
#--	   a user-specified limit and implements an iptables rule to ban it a
#--	   user specified time limit
#--	3) Unbans user from upon expiration of user-specified time limit
#-- 4) Determines if slow brute-force attempts are being made
#--
#-- The script is designed to be activated via crontab to run at system boot.
#-----------------------------------------------------------------------------

import pyinotify, re, os, threading, argparse, time
from ConfigParser import SafeConfigParser
from collections import defaultdict

# Global variables
CONNLIST = []				# List of connections
THREADS = []				# List of active threads
SERVICES = defaultdict()	# Map of services (with log and keyword to monitor)
UNBAN_TIME = 0				# Time until an IP is banned
MAX_ATTEMPTS = 3			# Failed attempts before banning
ATTEMPT_RESET_TIME = 60 	# Time till we flush connection attempts
SLOW_SCAN_TIME = 30			# Time to wait for re-input before we think it's slow scanning

# Location of configuration file
CFG_NAME = "/root/Temp/c8006-idps/idsconf"

#-----------------------------------------------------------
#-- CLASS:       	EventHandler
#--
#-- FUNCTIONS:		process_IN_MODIFY(self, event)
#--
#-- NOTES: 			Handles events triggered by pyinotify
#-----------------------------------------------------------
class EventHandler(pyinotify.ProcessEvent):

	#-----------------------------------------------------------------------------
	#-- FUNCTION:       def process_IN_MODIFY(self, event)
	#--
	#-- VARIABLES(S):	event - Contains information about the event
	#--
	#-- NOTES:			When an "IN_MODIFY" event triggers, this function will
	#--					process it by attempting to find a keyword from the last
	#--					line of a log file and and handling the attempt if it
	#--					matches the keyword
	#-----------------------------------------------------------------------------
	def process_IN_MODIFY(self, event):
		line = None
		for service, attr in SERVICES.iteritems():
			if event.pathname == attr[1]:
				line = get_last_lines(attr[1], attr[0])
				if line is not None:
					# Regex for IP address
					ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)[0]
					if ip is not None:
						handle_attempt(ip, service)

#-----------------------------------------------------------------
#-- CLASS:       	Connections
#--
#-- FUNCTIONS:		failed_attempt()
#--					reset_attempts()
#--
#--	VARIABLES:		ip 				- IP of the connection
#--					reset_timer 	- Whether the reset timer is
#--									  currently counting down
#--					odd_attempts	- Number of suspicious attempts
#--					prev_attempt 	- Time of previous attempt
#--
#-- NOTES: 			Class which handles each and every
#--					failed connections that is detected by
#--					the IDS.
#-----------------------------------------------------------------
class Connections:
	def __init__(self, ip, attempts=None):
		self.ip = ip
		self.reset_timer = 0
		self.odd_attempts = 0
		self.prev_attempt = time.time()

		if attempts is None:
			self.attempts = {}
		else:
			self.attempts = attempts

		# Initialize all service counts to 0 (prevent key access errors)
		for service in SERVICES:
			self.attempts[service] = 0

	#-----------------------------------------------------------------------------
	#-- FUNCTION:       failed_attempt(ip, service)
	#--
	#-- VARIABLES(S):   service - Type of service (ssh, ftp, etc)
	#--
	#-- NOTES:
	#-- Handles a failed attempt to access a service from this connection.
	#--
	#-- If the user takes too long between the each failed connection attempt, but
	#-- not long enough that we can assume the user simply successfully logged in
	#-- or gave up and came back, then we raise suspicion on the possibility of
	#-- a slow brute-force attack. If the suspicion occurs 3 times, we permanently
	#-- ban the connection on that service
	#--
	#-- Otherwise, we check if the user has attempted more than the MAX_ATTEMPT
	#-- allowed. If so, ban the connection on that service. The amount of attempts
	#-- is reset according to a user-defined time
	#-----------------------------------------------------------------------------
	def failed_attempt(self, service):
		self.attempts[service] += 1
		previous_attempt_elapse = time.time() - self.prev_attempt
		self.prev_attempt = time.time()

		# If the user took longer than SLOW_SCAN_TIME but less than 2 hours
		if previous_attempt_elapse >= SLOW_SCAN_TIME and previous_attempt_elapse < 7200:
			self.odd_attempts += 1
			if self.odd_attempts >= 3:
				ban_ip(self.ip, service, 1) # Ban forever
				print "Banning %s on %s due to slow scanning suspicions" % (self.ip, service)
				return

		# If amount of attempts exceeded MAX_ATTEMPTS, ban the IP
		if self.attempts[service] == MAX_ATTEMPTS:
			ban_ip(self.ip, service)
			print "Banning %s from %s" % (self.ip, service)
			self.attempts[service] = 0
		# Else set a timer to reset the attempt count
		elif self.reset_timer == 0:
			reset_thread = threading.Timer(ATTEMPT_RESET_TIME, self.reset_attempts, args=[service,]).start()
			THREADS.append(reset_thread)
			self.reset_timer = 1

	#-----------------------------------------------------------------------------
	#-- FUNCTION:       reset_attempts(service)
	#--
	#-- VARIABLES(S):   service - Type of service (ssh, ftp, etc)
	#--
	#-- NOTES:			Resets attempts made on a service by the connection
	#-----------------------------------------------------------------------------
	def reset_attempts(self, service):
		print "Resetting ban timer for %s on %s" % (self.ip, service)
		self.attempts[service] = 0
		self.reset_timer = 0

#-----------------------------------------------------------------------------
#-- FUNCTION:       handle_attempt(service)
#--
#-- VARIABLES(S):   ip 			- IP of the attempt
#--					service 	- Type of service attempted (ssh, ftp, etc)
#--
#-- NOTES:
#-- Determines whether to Create a new connection or modify an existing one
#-----------------------------------------------------------------------------
def handle_attempt(ip, service):
	print "Invalid access from %s on %s" % (ip, service)
	# if list is empty
	if len(CONNLIST) == 0:
		conn = Connections(ip)
		conn.failed_attempt(service)
		CONNLIST.append(conn)
	else:
		append = 0
		# if we can find the IP in the list of connections
		for conn in CONNLIST:
			if conn.ip == ip:
				append = 1
				conn.failed_attempt(service)
				break
		# If we can't, add it to the list
		if append == 0:
			conn = Connections(ip)
			conn.failed_attempt(service)
			CONNLIST.append(conn)

#-----------------------------------------------------------------------------
#-- FUNCTION:		ban_ip(ip, service)
#--
#-- VARIABLESS:   	ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being banned
#-- from and invokes an iptable using netfilter to block the specified ip. It
#-- creates a thread that runs the fuction in a given time(in seconds). If
#-- UNBAN_TIME is set (to not 0) it unbans the ip in UNBAN_TIME(seconds).
#-----------------------------------------------------------------------------
def ban_ip(ip, service, forever=0):
	os.system("/usr/sbin/iptables -A INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))
	if UNBAN_TIME != 0 and forever == 0:
		unban_timer = threading.Timer(UNBAN_TIME, unban_ip, args=[ip, service,]).start()
		THREADS.append(unban_timer)

#-----------------------------------------------------------------------------
#-- FUNCTION:       unban_ip(ip, service)
#--
#-- VARIABLES(S):   ip - external client ip address to be banned
#--					service - type of service the ip is banned from
#--
#-- NOTES:
#-- This function takes in an ip and a type of service the ip is being unbanned
#-- from and invokes an iptable using netfilter to unblock the specified ip.
#-----------------------------------------------------------------------------
def unban_ip(ip, service):
	print "Unbanning ip %s from %s" % (ip, service)
	os.system("/usr/sbin/iptables -D INPUT -p tcp --dport %s -s %s -j DROP" % (service, ip))

#-----------------------------------------------------------------------------
#-- FUNCTION:       load_cfg()
#--
#-- NOTES:
#-- This function creates a configParser object and parses the config file to
#-- obtain service(s) as well as keywords and log location associated with the
#-- service. It proceeds to store the information in a list of services to
#-- monitor.
#-- keyword example: "FAIL LOGIN"
#-----------------------------------------------------------------------------
def load_cfg():
	cfg_parser = SafeConfigParser()
	cfg_parser.read(CFG_NAME)

	for sections in cfg_parser.sections():
		for variable, value in cfg_parser.items(sections):
			if variable == "keyword":
				keyword = value
			elif variable == "file":
				filepath = value
		SERVICES[sections] = [keyword, filepath]

#-----------------------------------------------------------------------------
#-- FUNCTION:       get_last_lines(file, keyword)
#--
#-- VARIABLES(S):   file - the file to read
#--					keyword - specific words to inspect for
#--
#-- NOTES:
#-- This function seeks to the end of the file and returns the line that obtains
#-- the keyword.
#-----------------------------------------------------------------------------
def get_last_lines(logfile, keyword):
	with open(logfile, "r") as f:
		f.seek(0, 2) # go to the end
		fsize = f.tell() # get current position
		f.seek(max(fsize-1024, 0), 0)
		lines = f.readlines()
	lines = lines[-1:] # read one line up
	for line in lines: # Shouldn't be needed, but just in case
		if keyword in line:
			return line

#-----------------------------------------------------------------------------
#-- FUNCTION:       main()
#--
#-- NOTES:
#-- Main function of the program
#-- Creates the Watch manager and notifier of pyinotify (based on inotify)
#-- Loops and catches file_events
#-----------------------------------------------------------------------------
def main():
	load_cfg() # Load configuration file

	wm = pyinotify.WatchManager()
	handler = EventHandler()

	file_events = pyinotify.IN_MODIFY  # Monitor on MODIFY events
	notifier = pyinotify.Notifier(wm, handler)

	for service, attr in SERVICES.iteritems():
		print "Monitoring %s..." % attr[1]
		wm.add_watch(attr[1], file_events)
	print "-- Each IP will have %s attempts to access each service" % MAX_ATTEMPTS
	print "-- Attempts are reset every %s seconds" % ATTEMPT_RESET_TIME
	print "-- Slow scan timer set to %s seconds" % SLOW_SCAN_TIME
	if UNBAN_TIME != 0:
		print "-- IPs will be unbanned after %s seconds" % UNBAN_TIME
	else:
		print "-- Banned IPs will not be automatically unbanned"
	print "running..."
	notifier.loop()

# Checks if it's the main file at runtime
# Only run main() if it is
# Ensures that main() does not get run if file is merely imported
if __name__ == '__main__':

	# Sets up argument parser, see python py_ips.py -h for more info
	parser = argparse.ArgumentParser(description="Python IDS")
	parser.add_argument("-t", "--UNBAN_TIME", type=int, help="Time till IP's get unbanned in seconds")
	parser.add_argument("-a", "--attempt", type=int, help="Max attempts until program bans IP")
	parser.add_argument("-r", "--reset", type=int, help="Time before attempts are reset")
	parser.add_argument("-s", "--slowscan", type=int, help="Time to wait for re-input before we think it's slow scanning")
	args = parser.parse_args()

	if args.UNBAN_TIME is not None:
		UNBAN_TIME = args.UNBAN_TIME
	if args.attempt is not None:
		MAX_ATTEMPTS = args.attempt
	if args.reset is not None:
		ATTEMPT_RESET_TIME = args.reset
	if args.slowscan is not None:
		SLOW_SCAN_TIME = args.slowscan

	try:
		main()
	except KeyboardInterrupt:
		for thread in THREADS:
			thread.cancel() # cancel any remaining Timer threads
