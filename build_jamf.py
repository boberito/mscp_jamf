#!/usr/bin/env python3

import urllib3
import os
import requests
import base64
import json
import ssl
import getpass
import glob

urllib3.disable_warnings()

jamfURL = input("Enter Jamf URL(ex: https://jamfpro:8443): ")
username = input("Enter your username: ")
password = getpass.getpass("Password: ")
buildpath = input("Enter full path to baseline build directory: ")

buildpath = buildpath.replace("'","")

if jamfURL[-1] != "/":
  jamfURL = jamfURL + "/"


auth = "{}:{}".format(username,password)
auth_bytes = auth.encode('ascii')
base64_bytes = base64.b64encode(auth_bytes)
base64_auth = base64_bytes.decode('ascii')


headers = {
  'Authorization': 'Basic ' + base64_auth
}


tokenURL = jamfURL + "api/v1/auth/token"
response = requests.request("POST", tokenURL, headers=headers, verify=False)
if response.status_code == 401:
  print("Bad username/password")
  exit()

tokenData = json.loads(response.content.decode('utf-8'))

headers = {
  'Accept': 'application/json',
  'Authorization': 'Bearer ' + tokenData['token']
}

for item in sorted(glob.glob('{}/*/*.xml'.format(buildpath))):
  if item.split("/")[-2] == "1.categories":
    with open(item) as r:
      xmldata = r.read() 
      jamfcategory = "{}JSSResource/categories/id/0".format(jamfURL)
      response = requests.request("POST", jamfcategory, headers=headers, data=xmldata, verify=False)
      if response.status_code == 201:
        print("category: " + item.split("/")[-1].split(".")[0] + " added")
      else:
        print("category {} not added - error: ".format(item.split("/")[-1].split(".")[0]) + str(response.status_code))

  if item.split("/")[-2] == "2.ea":
    with open(item, encoding="utf-8") as r:
      xmldata = r.read() 
      jamfea = "{}JSSResource/computerextensionattributes/id/0".format(jamfURL)
      response = requests.request("POST", jamfea, headers=headers, data=xmldata, verify=False)
      if response.status_code == 201:
        print("ea: " + item.split("/")[-1].split(".")[0] + " added")
      else:
        print("ea {} not added - error: ".format(item.split("/")[-1].split(".")[0]) + str(response.status_code))
      
  if item.split("/")[-2] == "3.scripts":
    with open(item, encoding="utf-8") as r:
      xmldata = r.read() 
      jamfscripts = "{}JSSResource/scripts/id/0".format(jamfURL)
      response = requests.request("POST", jamfscripts, headers=headers, data=xmldata, verify=False)
      if response.status_code == 201:
        print("script: " + item.split("/")[-1].split(".")[0] + " added")
      else:
        print("script {} not added - error: ".format(item.split("/")[-1].split(".")[0]) + str(response.status_code))

  if item.split("/")[-2] == "4.smartgroups":
    with open(item, encoding="utf-8") as r:
      xmldata = r.read() 
      jamfsmartgroups = "{}JSSResource/computergroups/id/0".format(jamfURL)
      response = requests.request("POST", jamfsmartgroups, headers=headers, data=xmldata, verify=False)
      if response.status_code == 201:
        print("smartgroup: " + item.split("/")[-1].split(".")[0] + " added")
      else:
        print("smartgroup {} not added - error: ".format(item.split("/")[-1].split(".")[0]) + str(response.status_code))

  if item.split("/")[-2] == "5.policies":
    with open(item, encoding="utf-8") as r:
      xmldata = r.read() 
      jamfpolicies = "{}JSSResource/policies/id/0".format(jamfURL)
      response = requests.request("POST", jamfpolicies, headers=headers, data=xmldata, verify=False)
      if response.status_code == 201:
        print("policy: " + item.split("/")[-1].split(".")[0] + " added")
      else:
        print("policy {} not added - error: ".format(item.split("/")[-1].split(".")[0]) + str(response.status_code))

invalidateURL = jamfURL + "api/v1/auth/invalidate-token"
requests.request("POST", invalidateURL, headers=headers)

