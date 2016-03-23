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

DRIVER_NAME = 'SunnyWebBox'
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


schema = [('dateTime',   'INTEGER NOT NULL UNIQUE PRIMARY KEY'),
          ('usUnits',    'INTEGER NOT NULL'),
          ('interval',   'INTEGER NOT NULL'),
          ('grid_power',  'REAL'),   # Watt
          ('grid_energy', 'REAL')]   # kWh


class SWBDriver(weewx.drivers.AbstractDevice):

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        host = None
        try:
            host = stn_dict['host']
        except KeyError, e:
            msg = "unspecified parameter %s" % e
            logerr(msg)
            raise Exception(msg)
        self.max_tries = int(stn_dict.get('max_tries', 5))
        self.retry_wait = int(stn_dict.get('retry_wait', 30))
        self.polling_interval = int(stn_dict.get('polling_interval', 30))
        if self.polling_interval < 30:
            raise Exception('polling_interval must be 30 seconds or greater')
        password = stn_dict.get('password', None)
        proto = stn_dict.get('protocol', 'udp')
        if proto == 'http':
            self.swb = SunnyWebBoxHTTP(host, password=password)
        else:
            self.swb = SunnyWebBoxUDP(host, password=password)

    def closePort(self):
        self.swb = None

    def hardware_name(self):
        return "Sunny Webbox"

    def genLoopPackets(self):
        ntries = 0
        while ntries < self.max_tries:
            ntries += 1
            try:
                packet = {'dateTime': int(time.time()+0.5), 'usUnits':weewx.US}
                response = self.swb.getPlantOverview()
                logdbg("plant overview: %s" % response)
                for x in response:
                    if x['meta'] in ['GriPwr', 'GriEgyTot']:
                        packet[str(x['meta'])] = float(x['value'])
                devices = self.swb.getDevices()
                logdbg('devices: %s' % devices)
                for d in devices:
                    dev_key = d['key']
                    sn = d['name'][4:]
                    channels = self.swb.getProcessDataChannels(dev_key)
                    logdbg('channels %s: %s' % (dev_key, channels))
                    data = self.swb.getProcessData([{'key':dev_key,
                                                     'channels':channels}])
                    logdbg('data %s: %s' % (dev_key, data))
                    for x in data[dev_key]:
                        if x['meta'] in ['Ipv', 'Upv-Ist', 'Fac', 'Pac', 'h-On', 'h-Total', 'E-Total']:
                            label = "%s_%s" % (x['meta'], sn)
                            packet[str(label)] = float(x['value'])
                ntries = 0
                yield packet
                time.sleep(self.polling_interval)
            except SWBException, e:
                logerr("Failed attempt %d of %d to get LOOP data: %s" %
                       (ntries, self.max_tries, e))
                logdbg("Waiting %d seconds before retry" % self.retry_wait)
                time.sleep(self.retry_wait)
        else:
            msg = "Max retries (%d) exceeded for LOOP data" % self.max_tries
            logerr(msg)
            raise weewx.RetriesExceeded(msg)


def str2buf(s):
    return bytes(s)
def buf2str(b):
    return unicode(b, 'latin1')

class SWBException(Exception):
    pass

class SunnyWebBoxBase(object):
    class Counter:
        def __init__(self, start=0):
            self.idx = start
        def __call__(self):
            idx = self.idx
            self.idx += 1
            return idx

    def __init__(self, host, password=None):
        self.host = host
        self.password = hashlib.md5(password).hexdigest() if password else ''
        self.open_connection()
        self.count = SunnyWebBoxBase.Counter(1)

    def open_connection(self):
        raise NotImplementedError('open_connection')

    def new_request(self, name, use_pw=False, **params):
        r = {'version': '1.0', 'proc': name, 'format': 'JSON'}
        r['id'] = str(self.count())
        if use_pw:
            r['passwd'] = self.password
        if params:
            r['params'] = params
        return r

    def _rpc(self, *args):
        raise NotImplementedError('_rpc')

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
        raise NotImplementedError('setParameters is not yet implemented')


class SunnyWebBoxHTTP(SunnyWebBoxBase):
    def open_connection(self):
        from httplib import HTTPConnection
        self.conn  = HTTPConnection(self.host)

    def _rpc(self, request):
        """send rpc request as JSON object via http and read the result"""
        js = json.dumps(request)
        self.conn.request('POST', '/rpc', "RPC=%s" % js)
        tmp = buf2str(self.conn.getresponse().read())
        response = json.loads(tmp)
        if 'error' in response:
            raise SWBException('error : %s\nrequest: %s\nresponse: %s)' %
                               (response['error'], request, response))
        if response['id'] != request['id']:
            raise SWBException('RPC answer has wrong id!')
        return response['result']


class SunnyWebBoxUDP(SunnyWebBoxBase):
    """Communication with a 'Sunny WebBox' via UDP."""
    
    def open_connection(self):
        from socket import socket, AF_INET, SOCK_DGRAM
        self.udpPort = 34268
        self.ssock = socket(AF_INET, SOCK_DGRAM)
        self.rsock = socket(AF_INET, SOCK_DGRAM)
        self.rsock.bind(("", self.udpPort))
        self.rsock.settimeout(100.0)

    def _rpc(self, request):
        """send rpc request as JSON via UDP and read the result"""
        js = ''.join(i+'\0' for i in json.dumps(request, separators=(',',':')))
        self.ssock.sendto(str2buf(js), (self.host, self.udpPort))
        while True:
            data, addr = self.rsock.recvfrom(10*1024)
            if addr[0] == self.host:
                break
        tmp = buf2str(data).replace('\0', '')
        response = json.loads(tmp)
        if 'error' in response:
            raise SWBException('error : %s\nrequest: %s\nresponse: %s)' %
                               (response['error'], request, response))
        if response['id'] != request['id']:
            raise SWBException('RPC answer has wrong id!')
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
        swb = SunnyWebBoxUDP(args.host, password=args.password)
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