#!/usr/bin/env python
# -.- coding: utf-8 -.-

from __future__ import with_statement

try:
	import os
	import time
	import datetime
	import argparse
	import netaddr
	import sys
	import logging
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
			"and try again.\r\n" +\
			"pip install -r requirements.txt")
	raise SystemExit


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"
VERSION = '1.0.0'
OUTPUTFILE = ""
SQLEXT = ".db"
LOGEXT = ".log"

parser = argparse.ArgumentParser(description=DESCRIPTION)
parser.add_argument('interface', help="capture interface")
parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso) (default: iso)")
parser.add_argument('-d', '--delimiter', default=';', help="output field delimiter (default: ;)")
parser.add_argument('--filter', type=str, help='only show requests from the specified mac address')
parser.add_argument('--nosql', action='store_true', help='disable SQL logging completely (default: false)')
parser.add_argument('--addnicks', action='store_true', help='add nicknames to mac addresses (default: false)')
parser.add_argument('--flushnicks', action='store_true', help='flush nickname database (default: false)')
parser.add_argument('-o', '--output', default='DB-probemon', help="location and name of output file (default: DB-probemon)")
parser.add_argument('-e', '--exclude', default='exclude.conf', help="list of MAC addresses to exclude from output, one MAC per line (default: exclude.conf)")
parser.add_argument('-z', '--daemon', action='store_true', help="fork process and run in background (default: false)")
parser.add_argument('-D', '--debug', action='store_true', help="enable debug output (default: false)")
parser.add_argument('-s', '--nossid', action='store_true', help="do not include probe SSID in output (default: false)")
parser.add_argument('-b', '--nobssid', action='store_true', help='do not include bssid in output (default: false)')
parser.add_argument('-r', '--norssi', action='store_true', help="do not include rssi in output (default: false)")
parser.add_argument('-u', '--duplicate', action='store_true', help='show duplicate requests (default: false)')
parser.add_argument('-c', '--broadcast', action='store_true', help='show broadcast requests (without ssid) (default: false)')
parser.add_argument('-f', '--noresolve', action='store_true', help="do not include MAC address manufacturer (default: false)")
parser.add_argument('-v', '--noview', action='store_true', help="do not show live view of requests (default: false)")
parser.add_argument('--max-bytes', default=5242880, help="maximum log size in bytes before rotating (default: 5MB)")
parser.add_argument('--max-backups', default=99999, help="maximum number of log files to keep (default: 99999)")

if os.geteuid() != 0:
	print '[FATAL]: You have to be root to run this script'
	sys.exit(-1)

if len(sys.argv) == 1:
	parser.print_help()
	sys.exit(-1)

args = parser.parse_args()

monitor_iface = args.interface
filterMode = args.filter != None
if filterMode:
	filterMac = args.filter
noSQL = args.nosql
if not noSQL:
	addNicks = args.addnicks
	flushNicks = args.flushnicks
	OUTPUTFILE = args.output + SQLEXT
else:
	addNicks = False
	flushNicks = False
	OUTPUTFILE = args.output + LOGEXT
daemon = args.daemon
DEBUG = args.debug
showSsid = not args.nossid
showBssid = not args.nobssid
showRssi = not args.norssi
showDuplicates = args.duplicate
showBroadcasts = args.broadcast
noresolve = args.noresolve
showOutput = not args.noview

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
                   ___.
_____________  ____\_ |__   ____   _____   ____   ____
\____ \_  __ \/  _ \| __ \_/ __ \ /     \ /  _ \ /    \
|  |_> |  | \(  <_> | \_\ \  ___/|  Y Y  (  <_> |   |  \
|   __/|__|   \____/|___  /\___  |__|_|  /\____/|___|  /
|__|                    \/     \/      \/            \/

"""

try:
	print(header + "				v" + VERSION + "\n")
except:
	print(header + "				v" + VERSION + "\n")

print("[W] Make sure to use an interface in monitor mode!\n")

devices = []
script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False
if filterMode:
	externalOptionsSet = True
	print("[I] Only showing requests from '" + filterMac + "'.")
if noSQL:
	externalOptionsSet = True
	print("[I] NO-SQL MODE!")
if addNicks:
	externalOptionsSet = True
	print("[I] add nicknames in db...")
if flushNicks:
	externalOptionsSet = True
	print("[I] flushing nicknames db...")
if daemon:
	externalOptionsSet = True
	print("[I] daemon mode...")
if DEBUG:
	externalOptionsSet = True
	print("[I] Showing debug messages...")
if showSsid:
	externalOptionsSet = True
	print("[I] Showing ssid...")
if showBssid:
	externalOptionsSet = True
	print("[I] Showing bssid...")
if showRssi:
	externalOptionsSet = True
	print("[I] Showing rssi...")
if showDuplicates:
	externalOptionsSet = True
	print("[I] Showing duplicates...")
if showBroadcasts:
	externalOptionsSet = True
	print("[I] Showing broadcasts...")
if noresolve:
	externalOptionsSet = True
	print("[I] Not resolving MAC addresses...")
if not showOutput:
	externalOptionsSet = True
	print("[I] Not showing live output...")
if externalOptionsSet:
	print()

if not noresolve:
	try:
		with open(script_path + "oui.json", 'r') as content_file:
			print("[I] Loading local MAC database...")
			obj = content_file.read()
		resolveObj = json.loads(obj)
	except EnvironmentError:
		print("[I] Eroor when opening local MAC database...abort")

def stop():
	global alreadyStopping
	debug("stoping called")
	if not alreadyStopping:
		debug("setting stopping to true")
		alreadyStopping = True
		print("\n[I] Stopping...")
		if not noSQL:
			print("[I] Results saved to '" + OUTPUTFILE + "'")
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
				debug("[RESOLVEMAC] resolve OK for " + mac)
				return macArray[1]
		return "UNKNOWN"
	except:
		debug("[RESOLVEMAC] error when trying to resolve obj")
		return "UNKNOWN"

def build_packet_callback(delimiter):
	def packet_callback(packet):
		statusWidget(len(devices))
		# debug("packetHandler started")

		if not packet.haslayer(Dot11):
			return

		mac_address = packet.addr2
		bssid = packet.addr3

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
		if packet.type != 0 or packet.subtype != 0x04:
			return
		if mac_address in exclude:
			debug("[BUILD_PACKET_CALLBACK] " + mac_address + " is in the list of mac address to exclude")
			return

		ssid = packet.info.decode("utf-8")
		if ssid == "":
			if not showBroadcasts:
				debug("[BUILD_PACKET_CALLBACK] drop broadcast request...")
				return
		# list of output fields
		fields = []

		# determine preferred time format
		log_time = str(int(time.time()))
		if args.time == 'iso':
			log_time = datetime.now().isoformat()

		debug("append log_time")
		fields.append(log_time)

		debug("append mac_address")
		# append the mac address itself
		fields.append(mac_address)

		# parse mac address and look up the organization from the vendor octets
		if not noresolve:
			try:
				debug("[BUILD_PACKET_CALLBACK] resolving online mac adress " + mac_address + "...")
				parsed_mac = netaddr.EUI(mac_address)
				vendor = parsed_mac.oui.registration().org
				fields.append(vendor)
				debug("[BUILD_PACKET_CALLBACK] resolving OK")
			except netaddr.core.NotRegisteredError, e:
				debug("[BUILD_PACKET_CALLBACK] online resolving failed, trying with local db...")
				vendor = resolveMac(mac_address)
				fields.append(vendor)
				debug("[BUILD_PACKET_CALLBACK] local resolving ok...")
		else:
				fields.append('RESOLVEMAC-OFF')

		# include the SSID in the probe frame
		if showSsid:
			# if ssid == "":
			# 	ssid = 'broadcast'
			debug("append ssid")
			fields.append(ssid)

		if showRssi:
			rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
			debug("append rssi")
			fields.append(str(rssi_val))

		if showBssid:
			debug("append bssid")
			fields.append(bssid)

		if filterMode:
			if mac_address != filterMac:
				debug("[BUILD_PACKET_CALLBACK] [FILTERMODE] mac address do not match filter")
				return

		if noSQL:
			logger.info(delimiter.join([f for f in fields]))
		else:
			if showDuplicates:
				saveToMYSQL(mac_address, vendor, ssid, rssi_val)
			else:
				if not checkSQLDuplicate(ssid, mac_address, bssid):
					saveToMYSQL(mac_address, vendor, ssid, rssi_val, bssid)
				else:
					return
		if showOutput:
			print("|" + mac_address + "|\t|" + vendor[:30].ljust(30) + "|\t|" + ssid[:30].ljust(30) + "|\t|" + str(rssi_val)[:4].ljust(4) + "|\t|" + bssid + "|")
		inDevices = False
		for device in devices:
			if device == mac_address:
				inDevices = True
		if not inDevices:
			devices.append(mac_address)
	return packet_callback

def SQLConncetor():
	try:
		debug("sqlconnector called")
		global db
		db = sqlite3.connect(OUTPUTFILE)
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
		ts = str(int(time.time()))
		if args.time == 'iso':
			ts = datetime.now().isoformat()
		#st = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		st = ts
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

	if daemon:
		debug("[DAEMON] Trying to fork...")
		fpid = os.fork()
		if fpid!=0:
			debug("[DAEMON] fork failed...Exit...")
			sys.exit(0)
		else:
			debug("[DAEMON] fork OK...")

	global exclude
	debug("[EXCLUDE] getting list of mac addresses to exclude...")
	with open(args.exclude) as excludefile:
		exclude = [tuple(line.split(',')) for line in excludefile.readlines()]
	debug("[EXCLUDE] OK...")

	if not noSQL:
		print("[I] Setting up SQLite...")

		try:
			setupDB = sqlite3.connect(OUTPUTFILE)
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
				mac = raw_input("[?] Mac address: ")
				if mac == "":
					print("[!] Please enter a mac address.")
					continue
				nick = raw_input("[?] Nickname for mac '" + str(mac) + "': ")
				if nick == "":
					print("[!] Please enter a nickname.")
					continue
				setNickname(mac, nick)
				addAnother = raw_input("[?] Add another nickname? Y/n: ")
				if addAnother.lower() == "y" or addAnother == "":
					pass
				else:
					break
		print("[I] Saving requests to '" + OUTPUTFILE + "'")

	print("[I] Starting channelhopper in a new thread...")
	path = os.path.realpath(__file__)
	chopper = threading.Thread(target=chopping)
	chopper.daemon = True
	chopper.start()

	statusWidget(len(devices))

	if noSQL:
		debug("setup our rotating logger")
		logger = logging.getLogger(NAME)
		logger.setLevel(logging.INFO)
		handler = RotatingFileHandler(OUTPUTFILE, maxBytes=args.max_bytes, backupCount=args.max_backups)
		logger.addHandler(handler)
	built_packet_cb = build_packet_callback(args.delimiter)
	try:
		print("\n[I] Sniffing started... Please wait for requests to show up...\n")
		if showOutput:
			print("|   MAC ADDRESS   |\t|            VENDOR            |\t|             SSID             |\t|RSSI|\t|      BSSID      |")
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
