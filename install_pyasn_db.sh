#!/bin/sh

pyasn_util_download.py --latest && \
    pyasn_util_convert.py --single rib.*bz2 ./asn_report/resources/ip_to_asn.db
