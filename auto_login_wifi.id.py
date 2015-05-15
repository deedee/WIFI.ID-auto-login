#!/usr/bin/env python
#
# Auto login to Wifi.id
#
# @author: deedee

from lxml import etree
from StringIO import StringIO
from rosapi import RouterboardAPI

import ConfigParser
import requests
import sys
import re
import time
import random

import logging
import logging.handlers


MAX_RETRIES = 2
WAIT = 3 
TIMEOUT = 5
NEXT_TRY_DELTA = 60 * 6

log = logging.getLogger('WIFI.ID Auto Login')
log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
log.setLevel(logging.DEBUG)


def open_url(request, msg, *args, **kwargs):
    count = 0
    req = None
    while count < MAX_RETRIES:
        try:
            req = request(*args, timeout=TIMEOUT, **kwargs)
            if req.status_code != 200:
                log.exception('WIFI.ID - Failed to open url for %s see the response: (%s) %s ... retried' %
                              (msg, str(req.status_code), req.text))
                time.sleep(WAIT)
            else:
                break
        except:
            time.sleep(WAIT)
        count += 1
    if count == MAX_RETRIES:
        return False
    else:
        return req


def save_config(config, config_file):
    with open(config_file, 'w') as f:
        config.write(f)


def update_route(router, config, routing_marks, failsafe_route, config_file, use_wifiid):
    if router and router['use_wifiid'] != use_wifiid:
        try:
            rb = RouterboardAPI(router['host'], username=router['username'], password=router['password'],port=router['port'])
            route = rb.get_resource('/ip/route')
            route_all = route.get()
            route_wifiid = filter(lambda x: x if 'routing-mark' in x and x['routing-mark'] in routing_marks else None, route_all)
            for r in route_wifiid:
                if use_wifiid:
                    route.set(id=r['id'], gateway=router['gateway'])
                else:
                    route.set(id=r['id'], gateway=failsafe_route[routing_marks.index(r['routing-mark'])])
            config.set('mikrotik', 'use_wifiid', use_wifiid)
            save_config(config, config_file)
        except:
            pass


def set_next_try(account, config, config_file):
    next_try = time.time() + NEXT_TRY_DELTA
    config.set(account, 'next_try', next_try)
    save_config(config, config_file)


def read_config(config_file):
    log.debug('WIFI.ID - Parse config file:/etc/auto_login.wifi.id.cfg')
    config = ConfigParser.RawConfigParser()
    if not config.read(config_file):
        log.exception('WIFI.ID - Failed to read config file /etc/auto_login.wifi.id.cfg')
        sys.exit(666)
    return config


def main(config_file='/etc/auto_login.wifi.id.cfg'):
    try:
        config = read_config(config_file)
        test_urls = map(lambda x: x.strip(), config.get('default', 'test_url').split(','))
        login_url = config.get('default', 'login_url')
        check_url = config.get('default', 'check_url')

        accounts = []
        routing_marks = []
        failsafe_route = []
        router = {}
        for section in config.sections():
            now = time.time()
            if section.startswith('account'):
                account = {'username': config.get(section, 'username'), 'password': config.get(section, 'password'),
                           'active': config.getboolean(section, 'active'), 'section': section,
                           'valid_until': config.get(section, 'valid_until'),
                           'next_try': config.getfloat(section, 'next_try')}

                if account['active']:
                    try:
                        time_valid_until = time.mktime(time.strptime(account['valid_until'], '%Y-%m-%d %H:%M:%S'))
                        valid = True if time_valid_until > now else False
                        if account['next_try'] > 0. and account['next_try'] > now:
                            continue
                        elif account['next_try'] > 0.:
                            config.set(section, 'next_try', 0.)
                            save_config(config, config_file)

                        if not valid:
                            config.set(section, 'active', False)
                            save_config(config, config_file)
                            raise Exception('account %s time limit has been reach. Deactivated...' %
                                            account['username'])
                    except Exception as e:
                        log.exception('WIFI.ID - ' + str(e))
                        continue
                    accounts.append(account)
            if section.startswith('mikrotik'):
                router['host'] = config.get(section, 'host')
                router['username'] = config.get(section, 'username')
                router['password'] = config.get(section, 'password')
                router['use_wifiid'] = config.getboolean(section, 'use_wifiid')
                router['gateway'] = config.get(section, 'wifiid_gateway')
                try:
                    router['port'] = config.getint(section, 'port')
                except:
                    router['port'] = 8728
                routing_marks = map(lambda x: x.strip(), config.get(section, 'routing_mark').split(','))
                failsafe_route = map(lambda x: x.strip(), config.get(section, 'failsafe_route').split(','))
                if not routing_marks or not failsafe_route or len(routing_marks) != len(failsafe_route):
                    raise Exception('mikrotik routing-mark and failsafe_route must same item count')

    except Exception as e:
        log.exception('WIFI.ID - Failed to parse config file: ' + str(e))
        sys.exit(666)

    if len(accounts) < 1:
        log.error('WIFI.ID - No active accounts. Exiting')
        sys.exit(666)

    test_url = random.choice(test_urls)
    req = open_url(requests.get, 'test_url', test_url)
    if not req:
        log.exception('WIFI.ID - Failed to open test_url for ' + str(MAX_RETRIES) + ' times. I gave up!')
        update_route(router, config, routing_marks, failsafe_route, config_file, False)
        sys.exit(666)

    log.debug('WIFI.ID - parse html of test url' )
    parser = etree.HTMLParser()
    try:
        doc = etree.parse(StringIO(req.text), parser)
        meta = doc.xpath('/html/head/meta[@http-equiv="Refresh"]')
        if not meta:
            log.info('WIFI.ID - Good News.. We were logged in')
            update_route(router, config, routing_marks, failsafe_route, config_file, True)
            sys.exit(0)

        meta = meta[0]
        if meta.attrib['content'].find('wifi.id') < 1:
            log.error('WIFI.ID - Unknown content :' + meta.attrib['content'])
            sys.exit(666)
    except Exception as e:
        log.exception('WIFI.ID - Failed to parse test url : ' + str(e))
        sys.exit(666)

    try:
        re_url = re.compile('(\d; URL=)(http://welcome[0-9].wifi.id)(.*)', re.IGNORECASE)
        match_wifiid = re.match(re_url, meta.attrib['content'])
        wifiid_login_url = login_url.format(match_wifiid.group(2))
        wifiid_check_url = check_url.format(match_wifiid.group(2))
    except Exception as e:
        log.exception('WIFI.ID - Failed to parse url from meta:' + meta.attrib['content'] + ' with error:' + str(e))
        sys.exit(666)

    logged_in = False
    res = None
    for account in accounts:
        data = {'buttonClicked': 0, 'err_flag': 0, 'username_member': account['username'],
                'password_member': account['password']}
        log.debug('WIFI.ID - Try to login with username: ' + account['username'])

        req = open_url(requests.post, 'login_url', wifiid_login_url, data=data)

        if not req:
            log.exception('WIFI.ID - Failed to login with username ' + account['username'] + '. Try next account')
            set_next_try(account['section'], config, config_file)
            continue
        log.debug('WIFI.ID - Result :' + str(req.json()))
        #check result

        data = {'buttonClicked': 4, 'err_flag': 0, 'username': account['username'] + '@spin2',
                'password': account['password']}
        req = open_url(requests.post, 'check_url', wifiid_check_url, data=data)
        if not req:
            log.exception('WIFI.ID - Failed to login with username ' + account['username'] + '. Try next account')
            set_next_try(account['section'], config, config_file)
            continue
        #check sttaus
        log.debug('WIFI.ID - Result :' + str(req.json()))
        try:
            res = req.json()
            if res['result'] == 1:
                logged_in = True
                break
            else:
                log.error('WIFI.ID - Failed to loggin with this account')
                raise Exception()
        except:
            set_next_try(account['section'], config, config_file)

    if logged_in:
        log.debug('WIFI.ID - Go to redirect url')
        req = open_url(requests.get, 'go to redirect url', res['redirect'])
        log.debug('WIFI.ID - Done. Happy browsinG')
        update_route(router, config, routing_marks, failsafe_route, config_file, True)
    else:
        log.error('WIFI.ID - All account is sucks, please buy one')
        log.error('WIFI.ID - routing will set to failsafe')
        if not router['use_wifiid']:
            sys.exit(0)
        try:
            update_route(router, config, routing_marks, failsafe_route, config_file, False)
        except:
            pass
    

if __name__ == '__main__':
    if len(sys.argv) > 1:
        import os
        if os.path.exists(sys.argv[1]):
            main(sys.argv[1])
        else:
            log.error('WIFI.ID - config file %s is not exist. Exiting' % sys.argv[1])
    else:
        main()
    sys.exit(0)
