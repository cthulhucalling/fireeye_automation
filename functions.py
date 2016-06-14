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

def fe_submit_for_analysis(token,file):
        auth_header={'X-FeApi-Token':token}
        payload = {
                        'filename':'evildoc.docm',
                        'options':'{"application":"0","timeout":"500","priority":"0","profiles":["win7-sp1"],"analysistype":"1","force":"true","prefetch":"1"}'
        }
        submitted_file={'file':open('/root/scripts/fireeye/doc.docm','rb')}
        c=requests.post('https://fireeye.server/wsapis/v1.1.0/submissions',headers=auth_header,verify=False,data=payload,files=submitted_file)
        #print c.text
        id=json.loads(c.text)
        return id['ID']

def fe_check_submission(token,id):
        auth_header={'X-FeApi-Token':token}
        c=requests.get('https://fireeye.server/wsapis/v1.1.0/submissions/status/'+str(id),headers=auth_header,verify=False)
        #print c.text
        if c.status_code==200:
                if c.text=="Done":
                        print "Analysis of %s is complete" %id
                        return c.text
                elif c.text=="Submission not found":
                        print "Could not find status for id %s" %id
                elif c.text=="In progress":
                        print "Analysis for job %s is still running" %id
        elif c.status_code==401:
                print "Could not retrieve job status due to incorrect token"
        elif c.status_code==404:
                print "Could not retrieve job status due to incorrect submission key"

def fe_get_results(token,id):
        auth_header={'X-FeApi-Token':token}
        c=requests.get('https://fireeye.server/wsapis/v1.1.0/submissions/results/'+str(id)+'?info_level=normal',headers=auth_header,verify=False)
        #print c.text
        if c.status_code==200:
                #print c.text
                import xmltodict
                tree=xmltodict.parse(c.text)
                #print tree
                if tree['alerts']['ns2:alert']['@severity']=='majr':
                        print "Report URL: %s" %tree['alerts']['@xmlns:ns2']
                        print "Malware name(s):"
                        for element in tree['alerts']['ns2:alert']['ns2:explanation']['ns2:malware-detected']['ns2:malware']:
                                print"\t%s" %element['@name']
        elif c.status_code==401:
                print "Request unsuccessful due to incorrect session token (not logged in)"
        elif c.status_code==404:
                print "request unsuccessful due to incorrect submission key"
