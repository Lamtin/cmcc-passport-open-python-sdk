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


class ChinaMobile(object):

    def __init__(self, config={}):
        '''init'''
        self.config = {  \
            'oauth_sign_method'  : 'HMAC-SHA1', \
            'oauth_version'      : '1.0', \
            'oauth_consumer_key' : '', \
            'oauth_app_secret'   : '', \
            'oauth_endpoint_url' : 'http://120.197.230.234/passport/oauth', \
            'api_endpoint_url'   : 'http://120.197.230.234/passport/api', \
        }
        
        # set user config
        self.set_config(config)
        # var params, token_secret, token
        self.params = dict()
        self.token_secret = None
        self.token = None

    def set_config(self, config={}):
        '''config'''
        allow_config_keys = ['oauth_consumer_key', 'oauth_app_secret', 'oauth_endpoint_url', 'api_endpoint_url']
        # set config
        for key in allow_config_keys:
            if key in config.keys():
                self.config[key] = config[key]

    def set_params(self, args=None):
        '''set params'''
        self.params['oauth_nonce'] = self._nonce()
        self.params['oauth_consumer_key'] = self.config['oauth_consumer_key']
        self.params['oauth_signature_method'] = self.config['oauth_sign_method']
        self.params['oauth_version'] = self.config['oauth_version']
        self.params['oauth_timestamp'] = str(int(time.time()))
        if args:
            self.params.update(args)

    def set_token(self, token):
        self.token = token

    def set_token_secret(self, secret):
        self.token_secret = secret

    def get_request_token(self, callback='null'):
        # set params
        self.set_params( {'oauth_callback' : callback} ) 
        # format params
        bs = self._base_string('GET', '%s/%s' % (self.config['oauth_endpoint_url'], 'request_token'), self.params)
        key = self._quote(self.config['oauth_app_secret'])
        # signature
        self.params['oauth_signature'] = base64.b64encode(hmac.new('%s&' % key, bs, hashlib.sha1).digest())
        # conn
        conn = Connection(self.config['oauth_endpoint_url'])
        result = conn.request_get('request_token', self.params)
        # reset params
        self.params = {}
        # return
        return urlparse.parse_qs(result['body'])

    def get_authorize_url(self):
        return "%s/authorize?oauth_token=%s" % (self.config['oauth_endpoint_url'], self.token)

    def get_access_token(self, verifier):
        # set params
        self.set_params( {'oauth_token':self.token, 'oauth_verifier':verifier} ) 
        # format params
        bs = self._base_string('GET', '%s/%s' % (self.config['oauth_endpoint_url'], 'access_token'), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        conn = Connection(self.config['oauth_endpoint_url'])
        result = conn.request_get('access_token', self.params)
        # reset params
        self.params = {}
        # return
        return urlparse.parse_qs(result['body'])

    def api_get(self, resource):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('GET', '%s/%s' % (self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        conn = Connection(self.config['api_endpoint_url'])
        result = conn.request_get(resource=resource, args=self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result['body'])

    def api_delete(self, resource):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('DELETE', '%s/%s' % (self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        conn = Connection(self.config['api_endpoint_url'])
        result = conn.request_delete(resource=resource, args=self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result['body'])

    def api_post(self, resource, body = None, filename=None, headers={}):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('POST', '%s/%s' % (self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        conn = Connection(self.config['api_endpoint_url'])
        result = conn.request_post(resource=resource, args=self.params, body = body, filename=filename, headers=headers)
        # reset params
        self.params = {}
        # return
        return json.loads(result['body'])

    def api_put(self, resource, body = None, filename=None, headers={}):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('PUT', '%s/%s' % (self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        conn = Connection(self.config['api_endpoint_url'])
        result = conn.request_put(resource=resource, args=self.params, body = body, filename=filename, headers=headers)
        # reset params
        self.params = {}
        # return
        return json.loads(result['body'])

    def _check_resource(self, resource):
        if resource.startswith('/'):
            resource = resource[1:]
        return resource

    def _quote(self, s):
        if isinstance(s, unicode):
            s = s.encode('utf-8')
        return urllib.quote(str(s), safe='~')

    def _nonce(self):
        ' generate random uuid as oauth_nonce '
        return uuid.uuid4().hex

    def _signature(self, key, base_string):
        return base64.b64encode(hmac.new(key, base_string, hashlib.sha1).digest())[:-1].decode('utf-8')

    def _base_string(self, method, url, params):
        plist = [(self._quote(k), self._quote(v)) for k, v in params.iteritems()]
        plist.sort()
        return '%s&%s&%s' % (method, self._quote(url), self._quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))
