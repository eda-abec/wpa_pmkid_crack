# wpa_pmkid_crack
Python implementation of the attack discovered by @jsteube, described at https://hashcat.net/forum/thread-7717.html

It calls `wpa_passphrase` to generate a .conf file and a `wpa_supplicant` to obtain the PMKID hash

## Features
- generates a hash file, which can be passed to hashcat (`-m 16800`)
- timeout option
- [Termux](https://termux.com/) compatible (root required, but __not__ monitor mode)
- AP selection from list
- very basic cracker. In Python, rather a PoC, but runs in Termux :)
- more to come :)

# Setup
## Dependencies
- Python3
  - argparse, pexpect, netifaces
  - for cracker: hashlib, hmac, binascii, pbkdf2
- wpa_supplicant, wpa_passphrase
- iw

## Installing
```
git clone https://github.com/eda-abec/wpa_pmkid_crack.git
```

# Usage
```
pmkid_crack.py
2018-08-11, github.com/glezo1
2020 - 2021, github.com/eda-abec

[-h] | [--help]       display this help
[-v] | [--version]    show version
-i   | --interface    managed-mode interface to be used
[-b] | [--bssid]      target BSSID
[-e] | [--essid]      target ESSID
[-t] | [--timeout]    max seconds to wait for a PMKID.         Defaults to 30
[-f] | [--file]       tmp file: wpa_supplicant and pmkid hash. Defaults to ./wpa_passphrase.cnf
[-c] | [--crack]      crack by haschat (or not).               Defaults to 'do-not-crack'
[-d] | [--dictionary] dictionary file to be used by hashcat
[-m] | [--mask]       hashcat mask
[-p] | [--password]   foo password used by wpa_supplicant.     Defaults to 'spameggs'
```

## Example Usage

To scan for networks and select one,
```
sudo python3 pmkid_crack.py -i wlan0
```

Or specify one:
```
sudo python3 pmkid_crack.py -i wlan0 -e w1f1 -b 00:00:0A:BB:28:FC
```

### cracker.py
```
python3 cracker.py "2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a" wordlist_file

or

wordlist_generator | python3 cracker.py "2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a" stdin
```

# Bottom Line

Tested on Python 3.8.2, should work with any 3.*

Thanks to [@glezo1](https://github.com/glezo1) for original script,<br>
And [@drygdryg](https://github.com/drygdryg/) for WiFiScanner class
