import pyasn
import asn_report
from os import path

'''
TODO: Convert to unicode
'''


class reify(object):
    """ Use as a class method decorator.  It operates almost exactly like the
    Python ``@property`` decorator, but it puts the result of the method it
    decorates into the instance dict after the first call, effectively
    replacing the function it decorates with an instance variable.  It is, in
    Python parlance, a non-data descriptor.  An example:

    .. code-block:: python

       class Foo(object):
           @reify
           def jammy(self):
               print('jammy called')
               return 1

    And usage of Foo:

    >>> f = Foo()
    >>> v = f.jammy
    'jammy called'
    >>> print(v)
    1
    >>> f.jammy
    1
    >>> # jammy func not called the second time; it replaced itself with 1
    """
    def __init__(self, wrapped):
        self.wrapped = wrapped
        try:
            self.__doc__ = wrapped.__doc__
        except:  # pragma: no cover
            pass

    def __get__(self, inst, objtype=None):
        if inst is None:
            return self
        val = self.wrapped(inst)
        setattr(inst, self.wrapped.__name__, val)
        return val


class ASNLookup(object):

    def __init__(self, ipaddr=None, asnum=None, orgname=None):
        '''Central ASNLookup class. Instatiate with 1 of 3 values.

        :param ipaddr: IP address to lookup
        :type ipaddr: str
        :param asnum: ASN to lookup
        :type asnum: int
        :param orgname: Organizational name as registered in whois
        :type orgname: str

        Usage is much like::

            >>> lookup = ASNLookup(ipaddr='8.8.8.8')
            >>> lookup.ipaddr
            '8.8.8.8'
            >>> lookup.parent_pfx
            '8.8.8.0/24'
            >>> lookup.asnum
            15169
            >>> lookup.orgname
            'Google Inc.'

        '''

        if (None, None, None) == (ipaddr, asnum, orgname):
            raise ValueError('At least one value must be provided for lookup!')

        self.data = {'ipaddr': ipaddr,
                     'asnum': asnum,
                     'orgname': orgname,
                     'parent_pfx': None}

    def __getattr__(self, attr):
        if self.data[attr] is None:
            self.data[attr] = self._lookup(attr)
            return self.data[attr]
        return self.data[attr]

    @reify
    def _pyasn_db(self):
        '''Return pyasn object after instantiating.'''
        asn_db_path = path.abspath(path.join(
                                   path.dirname(asn_report.__file__),
                                   'resources/ip_to_asn.db'))
        return pyasn.pyasn(asn_db_path)

    @reify
    def _maxmind_org_db(self):
        '''Return CSV contents for Maxmind ASN database'''
        org_db_path = path.abspath(path.join(
                                   path.dirname(asn_report.__file__),
                                   'resources/GeoIPASNum2.csv'))
        with open(org_db_path) as f:
            # Read in as unicode to allow for non-Latin orgnames
            raw_db = f.read().decode('utf-8')
        org_directory = {}
        for line in raw_db.splitlines():
            # Reference line:
            # 16777216,16777471,"AS15169 Google Inc."
            # Not all lines may have a name associated, so gotta try..expect it
            line_split = line.split(',')  # Split CSV
            asn_and_owner = line_split[2].strip('"')  # Strip double-quotes
            # Catch AS without org name associated
            try:
                asn, owner = asn_and_owner.split(' ', 1)  # Sep AS and Org
            except ValueError:
                asn, owner = (asn_and_owner, u'NoOrgAssociated')
            org_directory.update({asn: owner})
        return org_directory

    def _lookup(self, keyword):
        '''Return value of _lookup_X() where X is ipaddr, asnum, or orgname.'''
        return self.__getattribute__('_lookup_' + keyword)()

    def _lookup_ipaddr(self):
        raise NotImplemented('Not implemented yet to get IP from other values')

    def _lookup_asnum(self):
        '''Perform ASN lookup'''

        asnum = self._pyasn_db.lookup(self.ipaddr)[0]
        if asnum is None:  # If successful, will return int. If fail, str
            return 'AS lookup failed: %s' % self.ipaddr

        return asnum

    def _lookup_parent_pfx(self):
        '''Perform parent prefix lookup'''

        pfx = self._pyasn_db.lookup(self.ipaddr)[1]
        if pfx is None:
            return 'Prefix lookup failed: %s' % self.ipaddr

        return pfx

    def _lookup_orgname(self):
        '''Perform Organization Name lookup

        Requires asnum to be available. If hasn't been looked up yet, the below
        calling of `self.asnum` will go to `self.__getattr__` and look it up
        before continuing.
        '''

        return self._maxmind_org_db['AS%d' % self.asnum]
