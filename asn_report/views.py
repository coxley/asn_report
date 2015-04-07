import sys
import unicodedata
from collections import Counter
from flask import render_template
from asn_report.models import ASNCount


def asn():
    asn_rows = ASNCount.query.all()

    try:
        sys.argv[1]
    except IndexError:  # If no option provided, default to showing just asnum
        counter = Counter([row.asn for row in asn_rows])
        graph = [['AS'+str(asn), cnt] for asn, cnt in counter.iteritems()]
        return render_template('asn.html', asn_data=graph)

    # Chart with combined ASnum and owner string as data labels
    if sys.argv[1] == '--display-name':
        counter = Counter([row.display_name for row in asn_rows])
        graph = [[norm(display), cnt] for display, cnt in counter.iteritems()]

    # Chart with only owner string as the data labels
    elif sys.argv[1] == '--owner':
        counter = Counter([row.owner for row in asn_rows])
        graph = [[norm(org), cnt] for org, cnt in counter.iteritems()]

    else:  # If provided arg is neither, default back to just asnum
        counter = Counter([row.asn for row in asn_rows])
        graph = [['AS'+str(asn), cnt] for asn, cnt in counter.iteritems()]

    return render_template('asn.html', asn_data=graph)


def norm(uni_str):
    '''Normalizes unicode string'''

    return unicodedata.normalize('NFKD', uni_str).encode('ascii', 'ignore')
