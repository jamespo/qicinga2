#!/usr/bin/env python3

# qicinga2 - quick icinga commandline status display
# (C) James Powell jamespo [at] gmail [dot] com 2021
# This software is licensed under the same terms as Python itself

# from urlparse import urlparse
from urllib.request import urlopen, Request, HTTPPasswordMgrWithDefaultRealm, \
        build_opener, HTTPBasicAuthHandler
from urllib.error import HTTPError
import configparser as ConfigParser
import io
import os.path
from datetime import datetime
from optparse import OptionParser
from collections import defaultdict
import logging
import socket
import ssl
import sys
import pprint
import time
import json

logging.basicConfig()
logger = logging.getLogger()

colmap = {      # shell escape codes
    'NORM'      : '\033[0m',
    'CRITICAL'  : '\033[31;1m',
    'WARNING'   : '\033[33;1m',
    'OK'        : '\033[32;1m',
    'UNKNOWN'   : '\033[35;1m',
    'PENDING'   : '\033[36;1m'
}


def get_page(ic_url, user, pw, hostname=None, verify_ssl=True):   # TODO: ignore hostname for now
    '''reads icinga service status page from API and returns json'''
    url = ic_url + 'v1/objects/services'
    logger.debug('url: ' + url)
    # authenticate
    passman = HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, ic_url, user, pw)
    opener = build_opener(HTTPBasicAuthHandler(passman))
    opener.addheaders = [('User-agent', 'qicinga2'), ('Accept', 'application/json'),
                         ('X-HTTP-Method-Override', 'GET')]
    postdata = '{ "attrs": [ "__name", "last_check_result" ] }'
    if not verify_ssl:
        ssl._create_default_https_context = ssl._create_unverified_context
    req = opener.open(url, postdata.encode("utf-8"))
    data = req.read()
    return data


def read_json(icinga_json):
    '''parse json into data structure'''
    icinga_status = json.loads(icinga_json.decode())
    return icinga_status


def cleanuptime(last_checktime):
    '''strip date from last check time if it's today'''
    # if check is not made yet will return N/A
    if ' ' not in last_checktime:
        return last_checktime
    # assumes date in DD-MM-YYYY
    (checkdate, checktime) = last_checktime.split(' ')
    if time.strftime("%d-%m-%Y") == checkdate:
        return checktime
    else:
        return last_checktime


def parse_checks(icinga_status, options):
    '''output from the passed datastructure'''
    rc, summ = parse_checks_individual(icinga_status, options)
    parse_checks_summary(summ, options)
    return rc


def status2str(status):
    '''icinga2 status to string'''
    # TODO: add warning critical etc
    stat2str = ('OK', 'WARNING', 'CRITICAL', 'UNKNOWN')
    return stat2str[int(status)]


def parse_checks_individual(icinga_status, options):
    '''loop round & count status & optionally print results of individual checks'''
    rc = 0
    summ = defaultdict(lambda: 0)
    # print individual check status
    for svc in icinga_status['results']:
        svc_attrs = svc['attrs']
        status = status2str(svc_attrs['last_check_result']['state'])
        summ[status] += 1
        if status != 'OK' or options.showall is True:
            if status != 'OK':
                rc = 1
            if options.colour:
                status = colmap[status] + status + colmap['NORM']
            if not options.quiet:
                name, desc = svc_attrs['__name'].split('!')
                rstr = "[%s]: %s - %s (%s)" % (status, name, desc,
                                               svc_attrs['last_check_result']['output'])
                if options.showtime:
                    lastcheck = int(svc_attrs['last_check_result']['execution_end'])
                    lastcheck_str = cleanuptime(datetime.utcfromtimestamp(lastcheck).strftime('%d-%m-%Y %H:%M'))
                    rstr += " - %s" % lastcheck_str
                print(rstr)
    return rc, summ


def parse_checks_summary(summ, options):
    '''print summary'''
    if not options.quiet:
        summary = ''
        # TODO: colourize if selected
        if not options.shortsumm:
            summary += 'SUMMARY:  '
        for stat in ['OK', 'WARNING', 'CRITICAL', 'UNKNOWN', 'PENDING']:
            prettystat = stat
            if options.colour:
                prettystat = colmap[stat] + str(prettystat) + colmap['NORM']
            if options.shortsumm:
                # color not supported yet
                summary += '%s:%s ' % (stat[0:2], summ[stat])
            else:
                summary += '%s: %s   ' % (prettystat, summ[stat])
        summary = summary.rstrip()
        sys.stdout.write(summary)
        if not options.shortsumm:
            print()


def readconf():
    '''read config file'''
    config = ConfigParser.ConfigParser()
    config.read(['/etc/qicinga2', os.path.expanduser('~/.config/.qicinga2')])
    return (config.get('Main', 'icinga_url'), config.get('Main', 'username'),
            config.get('Main', 'password'),
            config.getboolean('Main', 'colour') if config.has_option('Main', 'colour') else False,
            config.getboolean('Main', 'verify_ssl')
            if config.has_option('Main', 'verify_ssl') else True)


def get_options(colour):
    '''return CLI options'''
    parser = OptionParser()
    parser.add_option("-a", "--all", help="show all statuses",
                      action="store_true", dest="showall", default=False)
    parser.add_option("-s", help="short summary",
                      action="store_true", dest="shortsumm", default=False)
    parser.add_option("-t", help="show time of last check",
                      action="store_true", dest="showtime", default=False)
    parser.add_option("-c", help="colour output",
                      action="store_true", dest="colour", default=colour)
    parser.add_option("-b", help="no colour output",
                      action="store_false", dest="colour")
    parser.add_option("-q", help="quiet - no output, no summary, just return code",
                      action="store_true", dest="quiet", default=False)
    parser.add_option("-x", help="hostname - AUTOSHORT / AUTOLONG",
                      dest="hostname", default="all")
    (options, args) = parser.parse_args()
    if options.hostname == 'AUTOSHORT':
        options.hostname = socket.gethostname()
    elif options.hostname == 'AUTOLONG':
        options.hostname = socket.getfqdn()
    return options


def main():
    logger.setLevel(logging.INFO)
    (icinga_url, username, password, colour, verify_ssl) = readconf()
    options = get_options(colour)
    # TODO: don't verify ssl for now
    data = get_page(icinga_url, username, password, options.hostname, verify_ssl)
    icinga_status = read_json(data)
    logger.debug(pprint.pformat(icinga_status))
    rc = parse_checks(icinga_status, options)
    sys.exit(rc)


if __name__ == '__main__':
    main()
