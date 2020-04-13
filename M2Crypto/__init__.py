from __future__ import absolute_import

"""
M2Crypto is the most complete Python wrapper for OpenSSL featuring RSA, DSA,
DH, EC, HMACs, message digests, symmetric ciphers (including AES); SSL
functionality to implement clients and servers; HTTPS extensions to
Python's httplib, urllib, and xmlrpclib; unforgeable HMAC'ing AuthCookies
for web session management; FTP/TLS client and server; S/MIME; ZServerSSL:
A HTTPS server for Zope and ZSmime: An S/MIME messenger for Zope.
M2Crypto can also be used to provide SSL for Twisted. Smartcards supported
through the Engine interface.

Copyright (c) 1999-2004 Ng Pheng Siong. All rights reserved.

Portions created by Open Source Applications Foundation (OSAF) are
Copyright (C) 2004-2007 OSAF. All Rights Reserved.

Copyright 2008-2011 Heikki Toivonen. All rights reserved.
"""
# noqa
import sys
from distutils.version import StrictVersion
__version__ = '0.33.0'
version = __version__  # type: str
version_info = StrictVersion(__version__).version

# This means "Python 2.7 or higher" so it is True for py3k as well
py27plus = sys.version_info[:2] > (2, 6)  # type: bool

from M2Crypto import (ASN1, AuthCookie, BIO, BN, DH, DSA, EVP, Engine, Err,
                      RSA, Rand, SMIME, SSL, X509, m2crypto, ftpslib,
                      httpslib, m2, m2urllib, m2xmlrpclib, threading,
                      util)

if m2.OPENSSL_VERSION_NUMBER >= 0x90800F and m2.OPENSSL_NO_EC == 0:
    from M2Crypto import EC
if m2.OPENSSL_NO_RC4 == 0:
    from M2Crypto import RC4
# Backwards compatibility.
urllib2 = m2urllib

encrypt = 1
decrypt = 0

m2crypto.lib_init()
