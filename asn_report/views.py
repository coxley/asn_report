from collections import Counter
from flask import render_template
from asn_report.models import ASNCount


def asn():
    asn_rows = ASNCount.query.all()
    counter = Counter([row.asn for row in asn_rows])
    graph = [['AS'+str(asn), count] for asn, count in counter.iteritems()]
    return render_template('asn.html', asn_data=graph)
