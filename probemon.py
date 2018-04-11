#!/usr/bin/env python
# -.- coding: utf-8 -.-

try:
	import os
	import time
	import datetime
	import argparse
	import netaddr
	import sys
	import logging
	import numpy
	import json
	import threading
	import traceback
	import sqlite3
	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	from scapy.all import *
	from pprint import pprint
	from logging.handlers import RotatingFileHandler
except KeyboardInterrupt:
	print("\n[I] Stopping...")
	raise SystemExit
except:
	print("[!] Failed to import the dependencies... " +\
			"Please make sure to install all of the requirements " +\
			"and try again.")
	raise SystemExit


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"
USAGE = "probemon.py -i [monitor-mode-interface] [options]"

DEBUG = False

parser = argparse.ArgumentParser(description=DESCRIPTION, usage=USAGE)
parser.add_argument('-i', '--interface', help="capture interface")
parser.add_argument('--filter', type=str, help='only show requests from the specified mac address')
parser.add_argument('--nosql', action='store_true', help='disable SQL logging completely')
parser.add_argument('--addnicks', action='store_true', help='add nicknames to mac addresses')
parser.add_argument('--flushnicks', action='store_true', help='flush nickname database')
parser.add_argument('--noresolve', action='store_true', help='skip resolving mac address')
parser.add_argument('-u', '--unique', action='store_true', help='do not show duplicate requests')
parser.add_argument('-a', '--broadcast', action='store_true', help='do not show broadcast requests (without ssid)')
parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
parser.add_argument('-o', '--output', default='probemon.log', help="logging output location")
parser.add_argument('-b', '--max-bytes', default=5242880, help="maximum log size in bytes before rotating")
parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
parser.add_argument('-d', '--delimiter', default=';', help="output field delimiter")
parser.add_argument('-f', '--mac-info', action='store_true', help="include MAC address manufacturer")
parser.add_argument('-s', '--ssid', action='store_true', help="include probe SSID in output")
parser.add_argument('--bssid', action='store_true', help='include bssid')
parser.add_argument('-r', '--rssi', action='store_true', help="include rssi in output")
parser.add_argument('-D', '--debug', action='store_true', help="enable debug output")
parser.add_argument('-l', '--log', action='store_true', help="enable scrolling live view of the logfile")
parser.add_argument('-e', '--exclude', default='exclude.conf', help="list of MAC addresses to exclude from output, one MAC per line")
parser.add_argument('-z', '--daemon', action='store_true', help="fork process and run in background")

if len(sys.argv) == 1:
	parser.print_help()
	sys.exit(-1)

args = parser.parse_args()
showDuplicates = not args.unique
showBroadcasts = not args.broadcast
noSQL = args.nosql
addNicks = args.addnicks
flushNicks = args.flushnicks
DEBUG = args.debug
filterMode = args.filter != None
noresolve = args.noresolve
ssid = args.ssid
bssid = args.bssid
if args.filter != None:
	filterMac = args.filter
monitor_iface = args.interface
alreadyStopping = False

def restart_line():
	sys.stdout.write('\r')
	sys.stdout.flush()
	
def statusWidget(devices):
	if not filterMode:
		sys.stdout.write("Devices found: [" + str(devices) + "]")
	else:
		sys.stdout.write("Devices found: [FILTER MODE]")
	restart_line()
	sys.stdout.flush()
	
header = """
 ____  ____   ___  ____	___ 
|	\|	\ /   \|	\  /  _/
|  o  |  D  |	 |  o  )/  [
|   _/|	/|  O  |	 |	_\
|  |  |	\|	 |  O  |   [_/
|  |  |  .  |	 |	 |	 \
|__|  |__|\_|\___/|_____|_____|
"""

try:
	print(header + "									   \n")
except:
	print(header + "									   \n")

print("[W] Make sure to use an interface in monitor mode!\n")

devices = []
script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False
if noSQL:
	externalOptionsSet = True
	print("[I] NO-SQL MODE!")
if not showDuplicates:
	externalOptionsSet = True
	print("[I] Not showing duplicates...")
if not showBroadcasts:
	externalOptionsSet = True
	print("[I] Not showing broadcasts...")
if filterMode:
	externalOptionsSet = True
	print("[I] Only showing requests from '" + filterMac + "'.")
if noresolve:
	externalOptionsSet = True
	print("[I] Not resolving MAC addresses...")
if DEBUG:
	externalOptionsSet = True
	print("[I] Showing debug messages...")
if externalOptionsSet:
	print()

print("[I] Loading MAC database...")
with open(script_path + "oui.json", 'r') as content_file:
	obj = content_file.read()
resolveObj = json.loads(obj)

def stop():
	global alreadyStopping
	debug("stoping called")
	if not alreadyStopping:
		debug("setting stopping to true")
		alreadyStopping = True
		print("\n[I] Stopping...")
		if not noSQL:
			print("[I] Results saved to 'DB-probemon.db'")
		print("[I] probemon stopped.")
		raise SystemExit
		
def debug(msg):
	if DEBUG:
		print("[DEBUG] " + msg)
		
def chopping():
	while True:
		if not alreadyStopping:
			channels = [1, 6, 11]
			for channel in channels:
				os.system("iwconfig " + monitor_iface + " channel " +
						  str(channel) + " > /dev/null 2>&1")
				debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " +
					  "iwconfig " + monitor_iface + " channel " + str(channel))
				debug("[CHOPPER] HI I CHANGED CHANNEL TO " + str(channel))
				time.sleep(5)
		else:
			debug("[CHOPPER] IM STOPPING TOO")
			sys.exit()

def resolveMac(mac):
	try:
		global resolveObj
		for macArray in resolveObj:
			if macArray[0] == mac[:8].upper():
				return macArray[1]
		return "UNKNOWN"
	except:
		return "UNKNOWN"

def build_packet_callback(time_fmt, logger, delimiter, mac_info, ssid, rssi):
	def packet_callback(packet):
		
		statusWidget(len(devices))
		debug("packetHandler started")
		
		if not packet.haslayer(Dot11):
			return

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
		if packet.type != 0 or packet.subtype != 0x04:
			return
		if packet.addr2 in exclude:
			return
 
		ssidname = packet.info.decode("utf-8")
		if ssidname == "":
			if not showBroadcasts:
				return
		# list of output fields
		fields = []

		# determine preferred time format 
		log_time = str(int(time.time()))
		if time_fmt == 'iso':
			log_time = datetime.now().isoformat()

		fields.append(log_time)

		# append the mac address itself
		mac_address = packet.addr2
		fields.append(mac_address)
		
		# bssid
		bssidname = packet.addr3

		# parse mac address and look up the organization from the vendor octets
		if mac_info:
			try:
				parsed_mac = netaddr.EUI(packet.addr2)
				vendor = parsed_mac.oui.registration().org
				fields.append(vendor)
			except netaddr.core.NotRegisteredError, e:
				debug("resolving mac")
				vendor = resolveMac(mac_address)
				debug("vendor query done")
				fields.append(vendor)
		else:
				fields.append('RESOLVEMAC-OFF')
				
		# include the SSID in the probe frame
		if ssid:
			if ssidname == "":
				ssidname = 'broadcast'
			fields.append(ssidname)
			
		inDevices = False
		for device in devices:
			if device == mac_address:
				inDevices = True
		if not inDevices:
			devices.append(mac_address)
			
		if filterMode:
			if mac_address != filterMac:
				return
			
		if rssi:
			rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
			fields.append(str(rssi_val))
			
		if bssid:
			fields.append(bssidname)
			
		if noSQL:	
			logger.info(delimiter.join([f.decode("utf-8") for f in fields]))
		else:
			if showDuplicates:
				saveToMYSQL(mac_address, vendor, ssidname, rssi_val)
			else:
				if not checkSQLDuplicate(ssidname, mac_address, bssidname):
					saveToMYSQL(mac_address, vendor, ssidname, rssi_val, bssidname)
				else:
					return
	return packet_callback

def SQLConncetor():
	try:
		debug("sqlconnector called")
		global db
		db = sqlite3.connect("DB-probemon.db")
		cursor = db.cursor()
		return cursor
	except KeyboardInterrupt:
		stop()
		exit()
	except:
		debug("[!!!] CRASH IN SQLConncetor")
		debug(traceback.format_exc())


def checkSQLDuplicate(ssid, mac_add, bssid):
	try:
		debug("[1] checkSQLDuplicate called")
		cursor = SQLConncetor()
		cursor.execute(
			"select count(*) from probemon where ssid = ? and mac_address = ? and bssid = ?", (ssid, mac_add, bssid))
		data = cursor.fetchall()
		data = str(data)
		debug("[2] checkSQLDuplicate data: " + str(data))
		db.close()
		return data != "[(0,)]"
	except KeyboardInterrupt:
		stop()
		exit()
	except:
		debug("[!!!] CRASH IN checkSQLDuplicate")
		debug(traceback.format_exc())


def saveToMYSQL(mac_add, vendor, ssid, rssi, bssid):
	try:
		debug("saveToMYSQL called")
		cursor = SQLConncetor()
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		cursor.execute("INSERT INTO probemon VALUES (?, ?, ?, ?, ?, ?)", (mac_add, vendor, ssid,  st, rssi, bssid))
		db.commit()
		db.close()
	except KeyboardInterrupt:
		stop()
		exit()
	except:
		debug("[!!!] CRASH IN saveToMYSQL")
		debug(traceback.format_exc())


def setNickname(mac, nickname):
	debug("setNickname called")
	cursor = SQLConncetor()
	cursor.execute(
		"INSERT INTO probeSnifferNicknames VALUES (?, ?)", (mac, nickname))
	db.commit()
	db.close()


def getNickname(mac):
	debug("getNickname called")
	cursor = SQLConncetor()
	cursor.execute(
		"SELECT nickname FROM probeSnifferNicknames WHERE mac = ?", (mac,))
	data = cursor.fetchone()
	db.close()
	if data == None:
		return False
	else:
		data = data[0]
		data = str(data)
		return data	

def main():
	global alreadyStopping
	
	if os.geteuid() != 0:
		print '[FATAL]: You have to be root to run this script'
		sys.exit(-1)

	if not args.interface:
		print "error: capture interface not given, try --help"
		sys.exit(-1)
	
	if args.daemon:
		fpid = os.fork()
		if fpid!=0:
			sys.exit(0)

	global exclude
	exclude = numpy.genfromtxt(args.exclude, delimiter="\t", dtype=None)
	
	if not noSQL:
		print("[I] Setting up SQLite...")

		try:
			setupDB = sqlite3.connect("DB-probemon.db")
		except:
			print("\n[!] Cant connect to database. Permission error?\n")
			exit()
		setupCursor = setupDB.cursor()
		if flushNicks:
			try:
				setupCursor.execute("DROP TABLE probeSnifferNicknames")
				print("\n[I] Nickname database flushed.\n")
			except:
				print(
					"\n[!] Cant flush nickname database, since its not created yet\n")
		setupCursor.execute(
			"CREATE TABLE IF NOT EXISTS probemon (mac_address VARCHAR(50),vendor VARCHAR(50),ssid VARCHAR(50), date VARCHAR(50), rssi INT, bssid VARCHAR(50))")
		setupCursor.execute(
			"CREATE TABLE IF NOT EXISTS probeSnifferNicknames (mac VARCHAR(50),nickname VARCHAR(50))")
		setupDB.commit()
		setupDB.close()
		
	if addNicks:
		print("\n[NICKNAMES] Add nicknames to mac addresses.")
		while True:
			print()
			mac = input("[?] Mac address: ")
			if mac == "":
				print("[!] Please enter a mac address.")
				continue
			nick = input("[?] Nickname for mac '" + str(mac) + "': ")
			if nick == "":
				print("[!] Please enter a nickname.")
				continue
			setNickname(mac, nick)
			addAnother = input("[?] Add another nickname? Y/n: ")
			if addAnother.lower() == "y" or addAnother == "":
				pass
			else:
				break

	print("[I] Starting channelhopper in a new thread...")
	path = os.path.realpath(__file__)
	chopper = threading.Thread(target=chopping)
	chopper.daemon = True
	chopper.start()
	# print("[I] Saving requests to 'DB-probeSniffer.db'")
	print("\n[I] Sniffing started... Please wait for requests to show up...\n")
	statusWidget(len(devices))
		
	if noSQL or args.log:
		# setup our rotating logger
		logger = logging.getLogger(NAME)
		logger.setLevel(logging.INFO)
		handler = RotatingFileHandler(args.output, maxBytes=args.max_bytes, backupCount=args.max_backups)
		logger.addHandler(handler)
	if args.log:
		logger.addHandler(logging.StreamHandler(sys.stdout))
	built_packet_cb = build_packet_callback(args.time, logger, 
		args.delimiter, args.mac_info, args.ssid, args.rssi)
	try:
		sniff(iface=monitor_iface, prn=built_packet_cb, store=0)
	except KeyboardInterrupt:
		stop()
	except:
		print("[!] An error occurred. Debug:")
		print(traceback.format_exc())
		print("[!] Restarting in 5 sec... Press CTRL + C to stop.")
	 	stop()
if __name__ == '__main__':
	main()