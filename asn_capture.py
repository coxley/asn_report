#!/bin/env python2.7

"""
gather_asn.py

Description: Captures all IP packets (or according to provided scapy filter),
             parses them, and stores ASN info in SQLite DB for reporting in
             Flask application.

Usage:       gather_asn.py ["filter"]

"""

import sys
import pyasn
from sqlalchemy.exc import OperationalError
from IPy import IP
from scapy.all import sniff
from asn_report.main import db
from asn_report.models import ASNCount

asn_db = pyasn.pyasn('ip_to_asn.db')


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
        # Need to implement AS whois in a way that won't get flagged for too
        # many requests
        owner = 'NotImplemented'
        args = (dst_asn, owner, dst_ip, dst_pfx)
        add_to_sql(*args)
        return "AS%d owned by %s: %s child of %s" % args


def main():

    try:  # No reason to have a fancy argparser for one argument
        if sys.argv[1] in ['-h', '--help']:
            sys.exit(__doc__)
        scapy_filter = sys.argv[1]
        sniff(filter=scapy_filter, prn=parse_packet)
    except IndexError:
        sniff(filter="ip", prn=parse_packet)


if __name__ == '__main__':

    main()
