#! /usr/bin/python
# -*- coding: utf-8 -*-
import urlparse
import base64
import time
import hmac
import uuid
import urllib
import hashlib
import json
from restful_lib import Connection

OAUTH_SIGN_METHOD = 'HMAC-SHA1'
OAUTH_VERSION = '1.0'
OAUTH_CONSUMER_KEY = 'd82d4e0c0c3923f7fd024583ca4d0eb204f6bf741'
OAUTH_APP_SECRET = 'f2825987423494548e678af30fc51ab2'
OAUTH_ENDPOINT_URL = 'http://110.76.40.47/passport/oauth'
OAUTH_AUTHORIZE_URL = 'http://110.76.40.47/passport/oauth/authorize'
OAUTH_API_URL = 'http://110.76.40.47/passport/api'


class ChinaMobile(object):

    def __init__(self):
        self.params = dict()
        self.token_secret = None
        self.token = None

    def set_params(self, args=None):
        self.params['oauth_nonce'] = self.nonce()
        self.params['oauth_consumer_key'] = OAUTH_CONSUMER_KEY
        self.params['oauth_signature_method'] = OAUTH_SIGN_METHOD
        self.params['oauth_version'] = OAUTH_VERSION
        self.params['oauth_timestamp'] = str(int(time.time()))
        if args:
            self.params.update(args)

    def set_token(self, token):
        if 'list' in str(type(token)):
            token = token[0]
        self.token = token

    def set_token_secret(self, secret):
        if 'list' in str(type(secret)):
            secret = secret[0]
        self.token_secret = secret

    def get_request_token(self, callback='null'):
        self.set_params( {'oauth_callback' : callback} )
        bs = self.base_string('GET', '%s/%s' % (OAUTH_ENDPOINT_URL, 'request_token'), self.params)
        key = self.quote(OAUTH_APP_SECRET)
        self.params['oauth_signature'] = base64.b64encode(hmac.new('%s&' % key, bs, hashlib.sha1).digest())
        conn = Connection(OAUTH_ENDPOINT_URL)
        params = self.params
        self.params = {}
        result = conn.request_get('request_token', params)
        return urlparse.parse_qs(result['body'])

    def get_authorize_url(self):
        return "%s?oauth_token=%s" % (OAUTH_AUTHORIZE_URL, self.token)

    def get_access_token(self, verifier):
        if 'list' in str(type(verifier)):
            verifier = verifier[0]
        self.set_params( {'oauth_token':self.token, 'oauth_verifier':verifier} )
        bs = self.base_string('GET', '%s/%s' % (OAUTH_ENDPOINT_URL, 'access_token'), self.params)
        key = "%s&%s" % (self.quote(OAUTH_APP_SECRET), self.quote(self.token_secret))
        self.params['oauth_signature'] = self.signature(key, bs)
        conn = Connection(OAUTH_ENDPOINT_URL)
        params = self.params
        self.params = {}
        result = conn.request_get('access_token', params)
        return urlparse.parse_qs(result['body'])

    def api_get(self, resource):
        self.set_params()
        self.params['oauth_token'] = self.token
        bs = self.base_string('GET', '%s/%s' % (OAUTH_API_URL, resource), self.params)
        key = "%s&%s" % (self.quote(OAUTH_APP_SECRET), self.quote(self.token_secret))
        self.params['oauth_signature'] = self.signature(key, bs)
        conn = Connection(OAUTH_API_URL)
        params = self.params
        self.params = {}
        result = conn.request_get(resource=resource, args=params)
        return json.loads(result['body'])

    def api_delete(self, resource):
        self.set_params()
        self.params['oauth_token'] = self.token
        bs = self.base_string('DELETE', '%s/%s' % (OAUTH_API_URL, resource), self.params)
        key = "%s&%s" % (self.quote(OAUTH_APP_SECRET), self.quote(self.token_secret))
        self.params['oauth_signature'] = self.signature(key, bs)
        conn = Connection(OAUTH_API_URL)
        params = self.params
        self.params = {}
        result = conn.request_delete(resource=resource, args=params)
        return json.loads(result['body'])

    def api_post(self, resource, body = None, filename=None, headers={}):
        self.set_params()
        self.params['oauth_token'] = self.token
        bs = self.base_string('POST', '%s/%s' % (OAUTH_API_URL, resource), self.params)
        key = "%s&%s" % (self.quote(OAUTH_APP_SECRET), self.quote(self.token_secret))
        self.params['oauth_signature'] = self.signature(key, bs)
        conn = Connection(OAUTH_API_URL)
        params = self.params
        self.params = {}
        result = conn.request_post(resource=resource, args=params, body = body, filename=filename, headers=headers)
        return json.loads(result['body'])

    def api_put(self, resource, body = None, filename=None, headers={}):
        self.set_params()
        self.params['oauth_token'] = self.token
        bs = self.base_string('PUT', '%s/%s' % (OAUTH_API_URL, resource), self.params)
        key = "%s&%s" % (self.quote(OAUTH_APP_SECRET), self.quote(self.token_secret))
        self.params['oauth_signature'] = self.signature(key, bs)
        conn = Connection(OAUTH_API_URL)
        params = self.params
        self.params = {}
        conn.request_put(resource=resource, args=params, body = body, filename=filename, headers=headers)
        return json.loads(result['body'])

    def quote(self, s):
        if isinstance(s, unicode):
            s = s.encode('utf-8')
        return urllib.quote(str(s), safe='~')

    def nonce(self):
        ' generate random uuid as oauth_nonce '
        return uuid.uuid4().hex

    def signature(self, key, base_string):
        return base64.b64encode(hmac.new(key, base_string, hashlib.sha1).digest())[:-1].decode('utf-8')

    def base_string(self, method, url, params):
        plist = [(self.quote(k), self.quote(v)) for k, v in params.iteritems()]
        plist.sort()
        return '%s&%s&%s' % (method, self.quote(url), self.quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))