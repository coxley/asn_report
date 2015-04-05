asn_report
==========

.. image:: screenshot.png
   :scale: 50 %
   :alt: Example Screenshot


Description
-----------

``asn_report`` is a small Flask application that captures live traffic destined
to the internet and displays a chart of to get an idea of which ASes you send
more to.

It's composed of two things: 

    1. Python utility that uses scapy to capture IP traffic (or [X] traffic via
       provided filter argument), parse certain IP header fields, perform AS
       lookup, and store in database.

    2. Flask web application that reads from the database and creates a couple
       charts in javascript with the help of `chartkick`_.

.. _chartkick: https://github.com/mher/chartkick.py

Installation and Usage
----------------------

``asn_report`` is very easy to install. Just make sure you have git installed
and::

    git clone https://github.com/coxley/asn_report
    pip install -r requirements.txt .

Usage is pretty straightforward. There are two binary files that will be
installed into your environment.

To start the packet capture and begin storing data into the database::

    asn_capture [-h | --help | "tcpdump filter"]

Note that if no filter is provided "ip" will be used and also a provided filter
must be enclosed in quotes. Capture should be started before webserver because
it will initialize the db if it doesn't exist yet.

To start the webserver to easily look at summary of the data::

    asn_report

That should spawn a local webserver reachable via http://localhost:5000/

Side Notes
----------

The AS lookup is performed using the pyasn library which uses a view from local
file to map prefixes to ASN's.

Since it's 'only' a 12MB file, I decided to leave it watched by git in the
repo. If you notice error where some prefixes aren't being looked up properly,
it's probably due to this file being out of date.

I've provided a script to update it for you so just get a fresh clone of the
repo and run ``install_pyasn_db.sh``. You shouldn't have to do this, but if
overwriting the current file makes git unwatch it run ``git add .`` otherwise
setuptools-git won't add it to the package.

As of right now, the DB schema looks like:

+------------+---------------------------------------------+
| ASN        | AS advertising prefix                       |
+------------+---------------------------------------------+
| Owner      | Name of Owner (currently not implemented)   |
+------------+---------------------------------------------+
| Host       | /32 host that packet was destined to        |
+------------+---------------------------------------------+
| Parent_pfx | Parent prefix of the host which is actually |
|            | being advertised.                           |
+------------+---------------------------------------------+

AS owner/org_name isn't implemented yet because I didn't want to bombard any
whois/cymru's txt record dns service for every single packet. Currently every
packet fills that column with "NotImplemented".
