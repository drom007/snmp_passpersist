#!/usr/bin/python -u

import snmp_passpersist as snmp 
import sys
import psutil
import re

__MaxOids__ = 512
base_oid = '.1.3.6.1.3.53.8'

class Persist(snmp.PassPersist):
	def main_passpersist(self):
		"""
		Main function that handle SNMP's pass_persist protocol, called by
		the start method.
		Direct call is unnecessary.
		"""
		line = sys.stdin.readline().strip()
		if not line:
			raise EOFError()

		if 'PING' in line:
			print "PONG"
		elif 'getnext' in line:
			oid = self.cut_oid(sys.stdin.readline().strip())
			if oid is None:
				print "NONE"
			elif oid == "":
				# Fallback to the first entry
				print self.get_first()
			else:
				print self.get_next(oid)
		elif 'get' in line:
			oid = self.cut_oid(sys.stdin.readline().strip())
			if oid is None:
				print "NONE"
			else:
				result = self.get(oid)
				if result == 'NONE':
					if self.countOids() < __MaxOids__:
						self.add_int(oid,-1)
				print result
		elif 'set' in line:
			oid = sys.stdin.readline().strip()
			typevalue = sys.stdin.readline().strip()
			self.set(oid, typevalue)
		elif 'DUMP' in line: # Just for debbuging
			from pprint import pprint
			pprint(self.data)
			print 'Number of oids: ',self.countOids()
		else:
			print "NONE"

		sys.stdout.flush()

	def countOids(self):
		return len(self.data)

	@staticmethod
	def decode(oid):
		result="".join([chr(int(char)) for char in oid.split('.')][1:])
		return  "%s" % result

def update():
     commands_list = []
     for proc in psutil.process_iter():
	commands_list.append(' '.join(proc.cmdline))
	commands_list = filter(None,commands_list)

     for oid in pp.data:
	pattern='.*'+pp.decode(oid)+'.*'

	process_count = len(filter(re.compile(pattern).match,commands_list)) 
	pp.add_int(oid, process_count)
    
pp = Persist(base_oid)
pp.start(update,3) # Every 30s

