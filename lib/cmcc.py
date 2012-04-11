#! /usr/bin/python
# -*- coding: utf-8 -*-
import urlparse
import base64
import time
import hmac
import uuid
import urllib
import urllib2
import hashlib
import httplib
import json

class ChinaMobile(object):

    def __init__(self, config={}):
        '''构造函数'''
        self.config = {  \
            'oauth_sign_method'  : 'HMAC-SHA1', \
            'oauth_version'      : '1.0', \
            'oauth_consumer_key' : '', \
            'oauth_app_secret'   : '', \
            'oauth_endpoint_url' : 'passport/oauth', \
            'api_endpoint_url'   : 'passport/api', \
            'api_host'           : '120.197.230.234', \
        }
        
        # set user config
        self.set_config(config)
        # var params, token_secret, token
        self.params = dict()
        self.token_secret = None
        self.token = None

    def set_config(self, config=None):
        '''设置'''
        allow_config_keys = ['oauth_consumer_key', 'oauth_app_secret']
        # set config
        if config:
            for key in allow_config_keys:
                if key in config.keys():
                    self.config[key] = config[key]

    def set_params(self, args=None):
        '''设置提交参数'''
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
        bs = self._base_string('GET', 'http://%s/%s/%s' % (self.config['api_host'], self.config['oauth_endpoint_url'], 'request_token'), self.params)
        key = self._quote(self.config['oauth_app_secret'])
        # signature
        self.params['oauth_signature'] = base64.b64encode(hmac.new('%s&' % key, bs, hashlib.sha1).digest())
        # conn
        result = self._request(self.config['oauth_endpoint_url'], 'GET', 'request_token', self.params)
        # reset params
        self.params = {}
        # return
        return urlparse.parse_qs(result)

    def get_authorize_url(self):
        return "http://%s/%s/authorize?oauth_token=%s" % (self.config['api_host'], self.config['oauth_endpoint_url'], self.token)

    def get_access_token(self, verifier):
        # set params
        self.set_params( {'oauth_token':self.token, 'oauth_verifier':verifier} ) 
        # format params
        bs = self._base_string('GET', 'http://%s/%s/%s' % (self.config['api_host'], self.config['oauth_endpoint_url'], 'access_token'), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        result = self._request(self.config['oauth_endpoint_url'], 'GET', 'access_token', self.params)
        # reset params
        self.params = {}
        # return
        return urlparse.parse_qs(result)

    def api_get(self, resource):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('GET', 'http://%s/%s/%s' % (self.config['api_host'], self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        result = self._request(self.config['api_endpoint_url'], 'GET', resource, self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result)

    def api_delete(self, resource):
        # set params
        self.set_params() 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('DELETE', 'http://%s/%s/%s' % (self.config['api_host'], self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        result = self._request(self.config['api_endpoint_url'], 'DELETE', resource, self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result)

    def api_post(self, resource, body = None):
        # set params
        self.set_params(body) 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('POST', 'http://%s/%s/%s' % (self.config['api_host'], self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        result = self._request(self.config['api_endpoint_url'], 'POST', resource, self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result)

    def api_put(self, resource, body = None):
        # set params
        self.set_params(body) 
        self.params['oauth_token'] = self.token
        # format params
        resource = self._check_resource(resource)
        bs = self._base_string('PUT', 'http://%s/%s/%s' % (self.config['api_host'], self.config['api_endpoint_url'], resource), self.params)
        key = "%s&%s" % (self._quote(self.config['oauth_app_secret']), self._quote(self.token_secret))
        # signature
        self.params['oauth_signature'] = self._signature(key, bs)
        # conn
        result = self._request(self.config['api_endpoint_url'], 'PUT', resource, self.params)
        # reset params
        self.params = {}
        # return
        return json.loads(result)

    def _request(self, url, method, path, data={}, headers={}):
        '''执行查询'''
        conn = httplib.HTTPConnection(self.config['api_host'])
        body = urllib.urlencode(data)
        headers['Accept'] = "application/json"
        headers['Authorization'] = "OAuth %s" % self._auth_string(data)
        
        if method == 'GET':
            url = "/%s/%s?%s" %(url, path, body)
        else:
            url = "/%s/%s" %(url, path)
            headers['Content-Type'] = "application/json"

        conn.request(method=method, url=url , body=self._body_string(data), headers=headers)
        result = conn.getresponse()
        return result.read()

    def _check_resource(self, resource):
        '''验证并格式化resource'''
        if resource.startswith('/'):
            resource = resource[1:]
        return resource

    def _quote(self, s):
        '''转义'''
        if isinstance(s, unicode):
            s = s.encode('utf-8')
        return urllib.quote(str(s), safe='~')

    def _nonce(self):
        '''生成oauth_nonce'''
        return uuid.uuid4().hex

    def _signature(self, key, base_string):
        '''生成oauth_signature'''
        return base64.b64encode(hmac.new(key, base_string, hashlib.sha1).digest())[:-1].decode('utf-8')

    def _auth_string(self, params):
        '''生成auth'''
        plist = [(self._quote(k), self._quote(v)) for k, v in params.iteritems()]
        plist.sort()
        return ','.join(['%s="%s"' % (k, v) for k, v in plist])

    def _body_string(self, params):
        '''格式化body'''
        for key in ['oauth_nonce', 'oauth_consumer_key', 'oauth_signature_method', 'oauth_version', 'oauth_timestamp', 'oauth_signature', 'oauth_token']:
            if params.has_key(key):
                del params[key]

        plist = [(self._quote(k), self._quote(v)) for k, v in params.iteritems()]
        plist.sort()
        return '{%s}' % ','.join(['"%s":"%s"' % (k, v) for k, v in plist])

    def _base_string(self, method, url, params):
        '''格式化字符串为生成oauth_signature做准备'''
        plist = [(self._quote(k), self._quote(v)) for k, v in params.iteritems()]
        plist.sort()
        return '%s&%s&%s' % (method, self._quote(url), self._quote('&'.join(['%s=%s' % (k, v) for k, v in plist])))