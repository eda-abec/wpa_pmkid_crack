# wpa_pmkid_crack
Python implementation of the attack discovered by @jsteube, described at https://hashcat.net/forum/thread-7717.html

It calls wpa_passphrase to generate a conf file and a wpa_supplicant to obtain the PMKID hash

## Features
- generates a hash file, which can be passed to hashcat (`-m 16800`)
- timeout option
- Termux compatible (root required, but __not__ monitor mode)
- more to come :)

## Example usage

To scan for networks and select one,
```
sudo python3 ./pmkid_crack.py -i wlan0
```

Or specify one:
```
sudo python3 ./pmkid_crack.py -i wlan0 -e w1f1 -b 00:00:0A:BB:28:FC
```

## Bottom line

Tested on Python 3.8.2, should work with any 3.*

Thanks to [@glezo1](https://github.com/glezo1) for original script,<br>
And [@drygdryg](https://github.com/drygdryg/) for WiFiScanner class
