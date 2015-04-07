from asn_report.main import db


class ASNCount(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    asn = db.Column(db.Integer, nullable=False)
    owner = db.Column(db.String(128))
    host = db.Column(db.String(128), nullable=False)
    parent_pfx = db.Column(db.String(128), nullable=False)
    display_name = db.Column(db.String(256))

    def __init__(self, asn, owner, host, parent_pfx):
        self.asn = asn
        self.owner = owner
        self.host = host
        self.parent_pfx = parent_pfx
        self.display_name = 'AS%d: %s' % (self.asn, self.owner)

    def __repr__(self):
        return '<AS%d %s>' % (self.asn, self.owner)
