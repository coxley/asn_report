#!/bin/sh

RESOURCES=./asn_report/resources
GEOIP_FILE=GeoIPASNum2.csv
PYASN_FILE=ip_to_asn.db
PYASN_PATH=$RESOURCES/$PYASN_FILE
GEOIP_PATH=$RESOURCES/$GEOIP_FILE

pyasn_util_download.py --latest && \
    pyasn_util_convert.py --single rib.*bz2 $PYASN_PATH

curl -L \
    https://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum2.zip\
    > GeoIPASNum2-tmp.zip && unzip GeoIPASNum2-tmp.zip \
                                    -d $RESOURCES/
rm GeoIPASNum2-tmp.zip
git add $PYASN_PATH
git add $GEOIP_PATH
