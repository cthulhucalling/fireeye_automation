#!/usr/bin/python

import requests
from requests.auth import HTTPBasicAuth
import sys

requests.packages.urllib3.disable_warnings()


def login():
        c=requests.post('https://fireeye.server/wsapis/v1.1.0/auth/login?',auth=HTTPBasicAuth('api_analyst','<password>'),verify=False)
        print c.headers['X-FeApi-Token']
        #print c.status_code
        if c.status_code==200:
                return c.headers['X-FeApi-Token']
        else:
                print "Not logged in"
                sys.exit()

def logout(token):
        auth_header={'X-FeApi-Token':token}
        #print auth_header
        c=requests.post('https://fireeye.server/wsapis/v1.1.0/auth/logout?',headers=auth_header,verify=False)
        #print c.status_code
        if int(c.status_code)==204:
                return "Logged out"
        else:
                return "Error logging out"

def getconfig(token):
        auth_header={'X-FeApi-Token':token}
        c=requests.get('https://fireeye.server/wsapis/v1.1.0/config',headers=auth_header,verify=False)
        print c.text


def submit_for_analysis(token,file):
        auth_header={'X-FeApi-Token':token}
        payload = {
                        'filename':'evildoc.docm',
                        'options':'{"application":"0","timeout":"500","priority":"0","profiles":["win7-sp1"],"analysistype":"1","force":"true","prefetch":"1"}'
        }
        submitted_file={'file':open(file,'rb')}
        c=requests.post('https://fireeye.server/wsapis/v1.1.0/submissions',headers=auth_header,verify=False,data=payload,files=submitted_file)
        print c.text
