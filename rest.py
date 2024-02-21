#############################################################
#                                                           #
# FMC REST API Session                                      #
# Author: Brennan Bouchard                                  #
#                                                           #
# Date: 2/20/24                                             #
#                                                           #
#############################################################

import base64
import json
from urllib.parse import urlencode
import requests


class FmcSession:

    def get(self, uri, **kwargs):
        resp = self.session.get(f'{self.base_url}{uri}', params=urlencode(kwargs), verify=self.verify_ssl)
        if resp.status_code == 200:
            return resp.json()

    def post(self, uri, data, **kwargs):
        resp = self.session.post(f'{self.base_url}{uri}', params=urlencode(kwargs), data=json.dumps(data),
                                 verify=self.verify_ssl)
        if 199 < resp.status_code < 300:
            return resp.json()

    def put(self, uri, data, **kwargs):
        resp = self.session.put(f'{self.base_url}{uri}', params=urlencode(kwargs), data=json.dumps(data),
                                verify=self.verify_ssl)
        if 199 < resp.status_code < 300:
            return resp.json()

    def patch(self, uri, data, **kwargs):
        resp = self.session.patch(f'{self.base_url}{uri}', params=urlencode(kwargs), data=json.dumps(data),
                                  verify=self.verify_ssl)
        if 199 < resp.status_code < 300:
            return resp.json()

    def delete(self, uri, **kwargs):
        resp = self.session.delete(f'{self.base_url}{uri}', params=urlencode(kwargs), verify=self.verify_ssl)
        if 199 < resp.status_code < 300:
            return resp.json()

    def get_token(self):
        headers = {
            'Authorization': 'Basic ' + base64.b64encode((self.username + ':' + self.password).encode()).decode()
        }
        url = f'{self.base_url}/fmc_platform/v1/auth/generatetoken'
        response = requests.request("POST", url, headers=headers, data={}, verify=self.verify_ssl)
        if response.status_code == 204:
            return {
                'domain': response.headers.get('DOMAIN_UUID'),
                'access_token': response.headers.get('X-auth-access-token'),
                'refresh_token': response.headers.get('X-auth-refresh-token')
            }

    def __init__(self, hostname, username, password, verify_insecure_ssl=False, domain_uuid=None):
        self.verify_ssl = verify_insecure_ssl
        self.base_url = f'https://{hostname}/api'
        self.username = username
        self.password = password
        login_data = self.get_token()
        if domain_uuid:
            self.domain_uuid = domain_uuid
        else:
            self.domain_uuid = login_data['domain']
        self.session = requests.session()
        self.session.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-auth-access-token': login_data['access_token'],
            'X-auth-refresh-token': login_data['refresh_token']
        })
