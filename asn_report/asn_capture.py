#!/bin/env python2.7

"""
asn_capture

Description: Performs AS lookup for the destination of every packet processed
             and stores in database for later viewing in web summary.

             Traffic can either be gathered via a live capture with custom
             filter (pcap) or via netflow by sending flows to the process
             (flow).

Usage:       asn_capture (pcap|flow) [options]

Options:

    --help                          Show usage
    -f --filter=<pcap_filter>       PCAP filter syntax. Passed directly to
                                    scapy. [default: ip]
    --nflow=<flow_version>          Version of netflow to collect. Currently
                                    only 'v5' is supported. [default: v5]
    -h --host=<host>                IP address to bind flow collector on
                                    [default: 0.0.0.0]
    -p --port=<port>                Port to listen on for flow collector
                                    [default: 2303]

"""

import sys
import pyasn
import asn_report
from os import path
from docopt import docopt
from sqlalchemy.exc import OperationalError
from IPy import IP
from scapy.all import sniff
from asn_report.main import db
from asn_report.models import ASNCount

asn_db_path = path.abspath(
        path.join(path.dirname(asn_report.__file__), 'resources/ip_to_asn.db'))
asn_db = pyasn.pyasn(asn_db_path)


class IPHeader(object):
    '''Phony IPHeader class to pair with phony Packet class'''
    def __init__(self, saddr, daddr):
        self.src = saddr
        self.dst = daddr

class Packet(object):
    '''Class to very minimally imitate scapy's packet structure

    This is to be able to have the same parse_packet function based on the
    scapy interface regardless of which is used.
    '''
    def __init__(self,
                 saddr,
                 daddr,
                 sport,
                 dport,
                 protocol):
        self.saddr = saddr
        self.daddr = daddr
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        ip_header = IPHeader(saddr, daddr)
        self.headers = {
                'IP': ip_header
        }
    def __getitem__(self, key):
        return self.headers[key]
    def summary(self):
        '''Print packet summary'''
        keys = {
                'proto': self.protocol,
                'saddr': self.saddr,
                'daddr': self.daddr,
                'sport': self.sport,
                'dport': self.dport,
        }
        print '{proto} {saddr}:{sport} > {daddr}:{dport}'.format(**keys)


def netflow_v5_capture(host='0.0.0.0', port=2303, callback=None):
    '''Netflow version 5 collector with callback feature for every flow rcv'd

    Most of code for this collector reused from `devicenull`_

    .. _devicenull:
        http://blog.devicenull.org/2013/09/04/python-netflow-v5-parser.html

    :param host: IP to bind socket to
    :type host: str
    :param port: Port to bind to
    :type port: int
    :param callback: Callback function. Flow record dict will be passed as only
                     argument for each received.
    :type callback: function

    '''


    import socket, struct
    from socket import inet_ntoa

    # Verify ``host`` is a valid IP address
    try:
        IP(host)
    except ValueError:
        sys.exit('ERROR: Invalid IP address provided')

    SIZE_OF_HEADER = 24
    SIZE_OF_RECORD = 48

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    while True:
        buf, addr = sock.recvfrom(1500)

        (version, count) = struct.unpack('!HH',buf[0:4])
        if version != 5:
            print "Not NetFlow v5!"
            continue

        # It's pretty unlikely you'll ever see more then 1000 records in a 
        # 1500 byte UDP packet
        if count <= 0 or count >= 1000:
            print "Invalid count %s" % count
            continue

        uptime = socket.ntohl(struct.unpack('I',buf[4:8])[0])
        epochseconds = socket.ntohl(struct.unpack('I',buf[8:12])[0])

        for i in range(0, count):
            try:
                base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)

                data = struct.unpack('!IIIIHH',buf[base+16:base+36])

                nfdata = {}
                nfdata['saddr'] = inet_ntoa(buf[base+0:base+4])
                nfdata['daddr'] = inet_ntoa(buf[base+4:base+8])
                nfdata['pcount'] = data[0]
                nfdata['bcount'] = data[1]
                nfdata['stime'] = data[2]
                nfdata['etime'] = data[3]
                nfdata['sport'] = data[4]
                nfdata['dport'] = data[5]
                nfdata['protocol'] = ord(buf[base+38])
            except:
                continue

        packet = Packet(
                nfdata['saddr'],
                nfdata['daddr'],
                nfdata['sport'],
                nfdata['dport'],
                nfdata['protocol']
            )
        if callback:
            # If anything is returned, print to stdout
            returned = callback(packet)
            if returned:
                print returned
        else:
            packet.summary()


def add_to_sql(asn, owner, host, parent_pfx):
    '''Add row to database with Flask-SQLAlchemy

    Import model from Flask app for ease.
    '''
    row = ASNCount(asn, owner, host, parent_pfx)
    db.session.add(row)
    try:
        db.session.commit()
    except OperationalError:  # Make sure table is created
        db.create_all()
        db.session.rollback()
        db.session.commit()
    return 0


def lookup_org_asn(asnum):
    '''Uses Mastermind Organization DB to perform lookup'''

    def init():
        with open('GeoIPASNum2.csv') as f:
            maxmind_asnum_list = f.read().splitlines()
        asn_list = set()
        for entry in maxmind_asnum_list:
            # Reference line:
            # 16777216,16777471,"AS15169 Google Inc."
            # Not all lines may have a name associated, so gotta try..expect it
            entry_split = entry.split(',')  # Split CSV line
            asn_and_owner = entry_split[2].strip('"')  # Strip quotes
            try:
                asn, owner = asn_and_owner.split(' ', 1)  # Separate AS and Org
            except ValueError:
                asn, owner = (asn_and_owner, 'MissingOwnerData')
            # Update set to get rid of duplicates
            asn_list.update([(asn, owner)])

    try:
        asn_org_mapping
    except NameError:
        init()


def parse_packet(packet):
    '''Parse basic IP header info from packet and perform AS lookup'''
    global asn_db

    # We want to verify the packet has an IP header in case of bad scapy filter
    try:
        dst_ip = packet['IP'].dst
    except IndexError:
        print packet.summary()
        return '[WARNING]: Non-IP packet captured'

    # This will verify public IP before AS lookup. Flask view won't handle
    # None as AS currently.
    if IP(dst_ip).iptype() is 'PUBLIC':
        dst_asn, dst_pfx = asn_db.lookup(dst_ip)

        # Make sure that None doesn't get returned if db out of date
        if dst_asn is None:
            dst_asn = '00000'
            owner = "IPtoASN Error"
        else:
            # Need to implement AS whois in a way that won't get flagged for
            # too many requests
            owner = 'NotImplemented'
        args = (dst_asn, owner, dst_ip, dst_pfx)
        add_to_sql(*args)
        return "AS%d owned by %s: %s child of %s" % args


def main():

    args = docopt(__doc__)

    # Check whether to packet capture or collect flows
    if args['pcap']:

        scapy_filter = args['--filter']
        sniff(filter=scapy_filter, prn=parse_packet)

    elif args['flow']:

        flow_version = args['--nflow']
        bind_on = args['--host']
        listen_on = int(args['--port'])

        # Call proper netflow collector
        if flow_version == 'v5':
            netflow_v5_capture(host=bind_on,
                               port=listen_on,
                               callback=parse_packet)
        else:
            sys.exit('Only netflow v5 supported')


if __name__ == '__main__':

    main()
