#!/usr/bin/env python
# Copyright 2016 Matthew Wall, all rights reserved
"""
Driver to collect data from the SMA "Sunny Webbox".
"""

# FIXME: automatically detect the webbox using zeroconf

from __future__ import with_statement
import json
import syslog
import threading
import time

import weewx.drivers

DRIVER_NAME = 'SunnyWebbox'
DRIVER_VERSION = '0.1'


def loader(config_dict, _):
    return SWBDriver(**config_dict[DRIVER_NAME])

def confeditor_loader():
    return SWBConfigurationEditor()


def logmsg(level, msg):
    syslog.syslog(level, 'swb: %s' % msg)

def logdbg(msg):
    logmsg(syslog.LOG_DEBUG, msg)

def loginf(msg):
    logmsg(syslog.LOG_INFO, msg)

def logerr(msg):
    logmsg(syslog.LOG_ERR, msg)


class SWBDriver(weewx.drivers.AbstractDevice):

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        try:
            self._addr = stn_dict['address']
        except KeyError, e:
            logerr("unspecified parameter '%s'" % e)
            raise

    def hardware_name(self):
        return "Sunny Webbox"

    def genLoopPackets(self):
        while True:
            packet = {'dateTime': int(time.time()+0.5), 'usUnits':weewx.US}
            yield packet


def str2buf(s):
    return bytes(s)
def buf2str(b):
    return unicode(b, 'latin1')

class NotImplemented(Exception):
    def __init__(msg):
        pass


class Counter:
    def __init__(self, start=0):
        self.idx = start

    def __call__(self):
        idx = self.idx
        self.idx += 1
        return idx


class SunnyWebBoxBase(object):
    def __init__(self, host, password=None):
        self.host = host
        self.password = hashlib.md5(password).hexdigest() if password else ''
        self.open_connection()
        self.count = Counter(1)

    def open_connection(self):
        raise NotImplemented('open_connection')

    def new_request(self, name, use_pw=False, **params):
        r = {'version': '1.0', 'proc': name, 'format': 'JSON'}
        r['id'] = str(self.count())
        if use_pw:
            r['passwd'] = self.password
        if params:
            r['params'] = params
        return r

    def _rpc(self, *args):
        raise NotImplemented('_rpc')

    # implement each remote method

    def getPlantOverview(self):
        res = self._rpc(self.new_request('GetPlantOverview'))
        return res['overview']

    def getDevices(self):
        res = self._rpc(self.new_request('GetDevices'))
        return res['devices']

    def getProcessDataChannels(self, device_key):
        res = self._rpc(self.new_request('GetProcessDataChannels',
                                         device=device_key))
        return res[device_key]

    def getProcessData(self, channels):
        res = self._rpc(self.new_request('GetProcessData', devices=channels))
        # reorder data structure: {dev_key: {dict of channels}, ...}
        # return {l['key']: l['channels'] for l in res['devices']}
        r = {}
        for l in res['devices']:
            r[l['key']] = l['channels']
        return r

    def getParameterChannels(self, device_key):
        res = self._rpc(self.new_request('GetParameterChannels',
                                         use_pw=True, device=device_key))
        return res[device_key]

    def getParameter(self, channels):
        res = self._rpc(self.new_request('GetParameter',
                                         use_pw=True, devices=channels))
        # reorder data structure: {dev_key: {dict of channels}, ...}
        # return {l['key']: l['channels'] for l in res['devices']}
        r = {}
        for l in res['devices']:
            r[l['key']] = l['channels']
        return r

    def setParameter(self, *args):
        raise NotImplemented('setParameters is not yet implemented')


class SunnyWebBoxHTTP(SunnyWebBoxBase):
    def open_connection(self):
        from httplib import HTTPConnection
        self.conn  = HTTPConnection(self.host)

    def _rpc(self, request):
        """send rpc request as JSON object via http and read the result"""
        print "rpc request for %s" % request
        js = json.dumps(request)
        self.conn.request('POST', '/rpc', "RPC=%s" % js)
        tmp = buf2str(self.conn.getresponse().read())
        response = json.loads(tmp)
        if response['id'] != request['id']:
            raise Exception('RPC answer has wrong id!')
        return response['result']


class SunnyWebBoxUDPStream(SunnyWebBoxBase):
    """Communication with a 'Sunny WebBox' via UDP Stream."""
    
    def open_connection(self):
        from socket import socket, AF_INET, SOCK_DGRAM
        self.udpPort = 34268
        self.ssock = socket(AF_INET, SOCK_DGRAM)
        self.rsock = socket(AF_INET, SOCK_DGRAM)
        self.rsock.bind(("", self.udpPort))
        self.rsock.settimeout(100.0)

    def _rpc(self, request):
        """send rpc request as JSON via UDP Stream and read the result"""
        js = ''.join(i+'\0' for i in json.dumps(request, separators=(',',':')))
        self.ssock.sendto(str2buf(js), (self.host, self.udpPort))
        while True:
            data, addr = self.rsock.recvfrom(10*1024)
            if addr[0] == self.host:
                break
        tmp = buf2str(data).replace('\0', '')
        response = json.loads(tmp)
        if 'error' in response:
            raise Exception('error : %s\nrequest: %s\nresponse: %s)' %
                            (response['error'], request, response))
        if response['id'] != request['id']:
            raise Exception('RPC answer has wrong id!')
        return response['result']


if __name__ == '__main__':

    def print_response(response, padding=''):
        for v in response:
            if 'unit' in v:
                print("%s%15s (%15s): %s %s" % 
                      (padding, v['name'], v['meta'], v['value'], v['unit']))
            else:
                print("%s%15s (%15s): %s" %
                      (padding, v['name'], v['meta'], v['value']))

    import argparse
    parser = argparse.ArgumentParser(description='SunnyWebBox CLI query')
    parser.add_argument('host', help='host name or address')
    parser.add_argument('-u', '--udp', action='store_true',
                        help='use UDP instead of HTTP')
    parser.add_argument('-p', '--password', action='store', help='password')
    args = parser.parse_args()
    if args.udp:
        swb = SunnyWebBoxUDPStream(args.host, password=args.password)
    else:
        swb = SunnyWebBoxHTTP(args.host, password=args.password)

    print_response(swb.getPlantOverview())
	
    for d in swb.getDevices():
        dev_key = d['key']
        print("\nDevice %s (%s):" % (dev_key, d['name']))
        
        print("\nProcess data:")
        channels = swb.getProcessDataChannels(dev_key)
        data = swb.getProcessData([{'key':dev_key, 'channels':channels}])
        print_response(data[dev_key], '    ')
               
#        print("\nParameters:")
#        channels = swb.getParameterChannels(dev_key)
#        data = swb.getParameter([{'key':dev_key, 'channels':channels}])
#        print_response(data[dev_key], '    ')
