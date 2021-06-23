#Copyright 2008-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

#Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
#http://aws.amazon.com/apache2.0/
#or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

from __future__ import print_function
import sys
import argparse
import requests
import json
import subprocess
import getpass
import time
import boto3


HOST = 'https://console.cloudendure.com'
headers = {'Content-Type': 'application/json'}
session = {}
endpoint = '/api/latest/{}'

with open('FactoryEndpoints.json') as json_file:
    endpoints = json.load(json_file)

serverendpoint = '/prod/user/servers'
appendpoint = '/prod/user/apps'

def Factorylogin(username, password, LoginHOST):
    login_data = {'username': username, 'password': password}
    r = requests.post(LoginHOST + '/prod/login',
                  data=json.dumps(login_data))
    if r.status_code == 200:
        print("Migration Factory : You have successfully logged in")
        print("")
        token = str(json.loads(r.text))
        return token
    if r.status_code == 502:
        print("ERROR: Incorrect username or password....")
        sys.exit(1)
    else:
        print(r.text)
        sys.exit(2)

def CElogin(userapitoken, endpoint):
    login_data = {'userApiToken': userapitoken}
    r = requests.post(HOST + endpoint.format('login'),
                  data=json.dumps(login_data), headers=headers)
    if r.status_code == 200:
        print("CloudEndure : You have successfully logged in")
        print("")
    if r.status_code != 200 and r.status_code != 307:
        if r.status_code == 401 or r.status_code == 403:
            print('ERROR: The CloudEndure login credentials provided cannot be authenticated....')
        elif r.status_code == 402:
            print('ERROR: There is no active license configured for this CloudEndure account....')
        elif r.status_code == 429:
            print('ERROR: CloudEndure Authentication failure limit has been reached. The service will become available for additional requests after a timeout....')
    
    # check if need to use a different API entry point
    if r.history:
        endpoint = '/' + '/'.join(r.url.split('/')[3:-1]) + '/{}'
        r = requests.post(HOST + endpoint.format('login'),
                      data=json.dumps(login_data), headers=headers)
                      
    session['session'] = r.cookies['session']
    try:
       headers['X-XSRF-TOKEN'] = r.cookies['XSRF-TOKEN']
    except:
       pass

def GetCEProject(projectname):
    r = requests.get(HOST + endpoint.format('projects'), headers=headers, cookies=session)
    if r.status_code != 200:
        print("ERROR: Failed to fetch the project....")
        sys.exit(2)
    try:
        # Get Project ID
        project_id = ""
        projects = json.loads(r.text)["items"]
        project_exist = False
        for project in projects:
            if project["name"] == projectname:
               project_id = project["id"]
               project_exist = True
        if project_exist == False:
            print("ERROR: Project Name: " + projectname + " does not exist in CloudEndure....")
            sys.exit(3)
        return project_id
    except:
        print("ERROR: Failed to fetch the project....")
        sys.exit(4)

def ServerList(waveid, projectname, token, UserHOST):
# Get all Apps and servers from migration factory
    auth = {"Authorization": token}
    servers = json.loads(requests.get(UserHOST + serverendpoint, headers=auth).text)
    #print(servers)
    apps = json.loads(requests.get(UserHOST + appendpoint, headers=auth).text)
    #print(apps)
    newapps = []
    # Get app list in the wave
    for app in apps:
        if 'wave_id' in app:
            if str(app['wave_id']) == str(waveid):
                newapp = {}
                newservers = []
                if 'cloudendure_projectname' in app:
                    newapp['app_name'] = app['app_name']
                    for server in servers:
                        if app['app_id'] == server['app_id']:
                            if 'server_fqdn' in server:
                                newservers.append(server)
                            else:
                                print("ERROR: server_fqdn for server: " + server['server_name'] + " doesn't exist")
                                sys.exit(4)
                    newapp['servers'] = newservers
                else:
                    print("ERROR: App " + app['app_name'] + " is not linked to any CloudEndure project....")
                    sys.exit(5)
                newapps.append(newapp)
    for app in newapps:
        print("Application - " + app["app_name"])
        for server in app['servers']:
             print("  - " + server['server_name'])
    print("")
    return newapps

def CreatingAppInHub(newapps, access_key_id, secret_access_key):
    # Creating Application in Hub
    ads_client = boto3.client('discovery', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name='us-west-2')
    ads_apps_response = ads_client.list_configurations(configurationType='APPLICATION')
    ads_servers_response = ads_client.list_configurations(configurationType='SERVER')
    for newapp in newapps:
        app_exist = False
        for ads_app in ads_apps_response['configurations']:
            if newapp['app_name'].lower() == ads_app['application.name'].lower():
                app_exist = True
        if app_exist == False:
           create_app = ads_client.create_application(name=newapp['app_name'].lower())
           print("Creating Application: " + newapp['app_name'] + " in Migration Hub")
        ads_apps_response_new = ads_client.list_configurations(configurationType='APPLICATION')
        for ads_app2 in ads_apps_response_new['configurations']:
            if newapp['app_name'].lower() == ads_app2['application.name'].lower():
                for newserver in newapp['servers']:
                    for ads_server in ads_servers_response['configurations']:
                        if ads_server['server.hostName'].lower() == newserver['server_fqdn'].lower() or ads_server['server.hostName'].lower() == newserver['server_name'].lower():
                            response = ads_client.associate_configuration_items_to_application(applicationConfigurationId=ads_app2['application.configurationId'],
                                                                                                configurationIds=[ads_server['server.configurationId']])

def UpdatingAppStatus(newapps, access_key_id, secret_access_key):
    # Creating Application in Hub
    ads_client = boto3.client('discovery', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name='us-west-2')
    ads_apps_response = ads_client.list_configurations(configurationType='APPLICATION')
    hub_client = boto3.client('mgh', aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name='us-west-2')
    print("")
    for newapp in newapps:
        appid = ""
        for ads_app in ads_apps_response['configurations']:
            if newapp['app_name'].lower() == ads_app['application.name'].lower():
                appid = ads_app['application.configurationId']
        app_complete = True
        server_inprogress = False
        for server in newapp['servers']:
            if '2/2 status checks : Passed' not in server['migration_status']:
                app_complete = False
            if 'launched' in server['migration_status'] or 'CE Agent Install - Success' in server['migration_status']:
                server_inprogress = True
        print("Updating Application status: " + newapp['app_name'] + " in Migration Hub")
        if app_complete:
            update_app_state = hub_client.notify_application_state(ApplicationId=appid, Status='COMPLETED')
        elif server_inprogress:
            update_app_state = hub_client.notify_application_state(ApplicationId=appid, Status='IN_PROGRESS')
        else:
            update_app_state = hub_client.notify_application_state(ApplicationId=appid, Status='NOT_STARTED')

def main(arguments):
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--Waveid', required=True)
    parser.add_argument('--CEProjectName', required=True)
    args = parser.parse_args(arguments)
    LoginHOST = endpoints['LoginApiUrl']
    UserHOST = endpoints['UserApiUrl']
    print("")
    print("****************************")
    print("*Login to Migration factory*")
    print("****************************")
    token = Factorylogin(input("Factory Username: ") , getpass.getpass('Factory Password: '), LoginHOST)

    print("*****************************")
    print("*** Getting Server status ***")
    print("*****************************")
    Apps = ServerList(args.Waveid, args.CEProjectName, token, UserHOST)

    print("****************************")
    print("** Updating Migration hub **")
    print("****************************")
    Access_key = input("AWS Access key id: ")
    Secret_access_key = getpass.getpass('Secret access key: ')
    CreatingAppInHub(Apps, Access_key, Secret_access_key)

    UpdatingAppStatus(Apps, Access_key, Secret_access_key)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))