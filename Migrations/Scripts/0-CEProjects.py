#!/usr/bin/python

import argparse
import requests
import getpass
import json
import csv
import base64
import sys


#create a region dictionary
ce_region = {
			"gov-east-2": "AWS GovCloud (US)",
            "eu-west-1": "AWS EU (Ireland)",
            "ap-east-1": "AWS Asia Pacific (Hong Kong)",
            "ap-southeast-1": "AWS Asia Pacific (Singapore)",
            "ap-southeast-2": "AWS Asia Pacific (Sydney)",
            "us-west-2": "AWS US West (Oregon)",
            "sa-east-1": "AWS South America (Sao Paulo)",
            "us-east-2": "AWS US East (Ohio)",
            "ca-central-1": "AWS Canada (Central)",
            "us-west-1": "AWS US West (Northern California)",
            "eu-west-3": "AWS EU (Paris)",
            "ap-northeast-1": "AWS Asia Pacific (Tokyo)",
            "me-south-1": "AWS Middle East (Bahrain)",
            "eu-central-1": "AWS EU (Frankfurt)",
            "ap-south-1": "AWS Asia Pacific (Mumbai)",
            "eu-west-2": "AWS EU (London)",
            "gov-east-1": "AWS GovCloud (US-East)",
            "ap-northeast-2": "AWS Asia Pacific (Seoul)",
            "eu-north-1": "AWS EU (Stockholm)",
            "us-east-1": "AWS US East (Northern Virginia)",
}



HOST = 'https://console.cloudendure.com'

def read_config_csv(input_file):
	# new_name,publicKey,privateKey,region,subnet
	result = []
	with open(input_file, mode='r') as infile:
		reader = csv.DictReader(infile)
		for row in reader:
			result.append(row)
	return result

def login(username, password):
	endpoint = '/api/latest/{}'
	session = requests.Session()
	session.headers.update({'Content-type': 'application/json', 'Accept': 'text/plain'})
	
	resp = session.post(url=HOST+endpoint.format('login'),
									data=json.dumps({'username': username,
													'password': password}))
	if resp.status_code != 200 and resp.status_code != 307:
		print('Could not login!')
		sys.exit(2)
		
	# check if need to use a different API entry point
	if resp.history:
		endpoint = '/' + '/'.join(resp.url.split('/')[3:-1]) + '/{}'
		resp = session.post(url=HOST+endpoint.format('login'),
						data=json.dumps({'username': username, 'password': password}))
	if resp.status_code != 200:
		raise Exception('login error')
		
	session.headers['X-XSRF-TOKEN'] = session.cookies.get('XSRF-TOKEN')
		
	return session, endpoint


def main(args):
	
	session, endpoint = login(args.user, getpass.getpass(prompt='CloudEndure Password: '))
	
	new_projects = read_config_csv(args.inputfile)

	# Get ID for AWS cloud
	aws_cloud_id = None
	resp = session.get(url=HOST+endpoint.format('/clouds'))
	for clouds_item in json.loads(resp.content)['items']:
		if clouds_item['name'] == 'AWS':
			aws_cloud_id = clouds_item['id']
			break
	assert aws_cloud_id

	# Get ID for CloudEndure Migration License
	license_id = None
	resp = session.get(url=HOST+endpoint.format('/licenses'))
	for license_item in json.loads(resp.content)['items']:
		if license_item['type'] == 'MIGRATION':
			license_id = license_item['id']
	assert license_id
	
	# Get ID for on-prem region
	onprem_region_id = None
	resp = session.get(url=HOST+endpoint.format('/cloudCredentials/00000000-0000-0000-0000-000000000000/regions'))
	for region_items in json.loads(resp.content)['items']:
		onprem_region_id = region_items['id']
	assert onprem_region_id


	#create projects as listed in the CSV input file
	for new_project in new_projects:
		config = { 'name': new_project['new_name'],
					'type': 'MIGRATION',
					'licensesIDs': [license_id],
					'targetCloudId': aws_cloud_id,
					'sourceRegion': onprem_region_id
				}

		new_project_resp = session.post(url=HOST+endpoint.format('/projects'), data = json.dumps(config))
		if new_project_resp.status_code != 201:
			print('failed creating project {} {}'.format(new_project['new_name'], json.loads(new_project_resp.content)['code']))
		else:
			#get project ID
			project = json.loads(new_project_resp.content)
			project_id =  project['id']

			#setup the cloud credentials
			creds = {
				'publicKey': new_project['publicKey'],
				'privateKey': base64.b64encode(new_project['privateKey'].encode('utf-8')).decode('utf-8'),
				'cloudId': aws_cloud_id
				}

			creds_resp = session.post(url=HOST+endpoint.format('/cloudCredentials'), data=json.dumps(creds))
			if creds_resp.status_code != 201:
				print('Failed setting credentials for project {}. Error:{} {}'.format(new_project['new_name'],creds_resp.content, creds_resp.status_code))
			else:
				cloud_credentials_id = json.loads(creds_resp.content)['id']
				data = {
					'cloudCredentialsIDs': [cloud_credentials_id]
					}
				resp = session.patch(url=HOST+endpoint.format('/projects/{}'.format(project_id)), data=json.dumps(data))				
				if resp.status_code != 200:
					print('Failed patch project {} with new credentials {} credentails. Error:{} {}'.format(new_project['new_name'],cloud_credentials_id ,resp.content, resp.status_code))
				else:

					#get list of regions (move oustide of the loop)
					CEregion = ce_region.get(new_project['region'])
					rep = session.get(HOST + endpoint.format('/cloudCredentials/{}/regions').format(cloud_credentials_id))
					for region in json.loads(rep.content)['items']:
						if region['name'] == CEregion:
							region_id = region['id']
					assert region_id


					#create replication configuration to attach later to project
					data = {
						'volumeEncryptionKey': '',	
						'volumeEncryptionAllowed': False,
						'bandwidthThrottling': 0,
						'disablePublicIp': False,
						'replicationServerType': 'Default',
						'useLowCostDisks': False,
						'useDedicatedServer': False,
						'usePrivateIp': False,
						'replicatorSecurityGroupIDs': [],
						'proxyUrl': '',
						'storageLocationId': '',
						'objectStorageLocation': '',
						'archivingEnabled': False,
						'replicationTags': [{'key':'CloudEndureProject', 'value':new_project['new_name']}],
						'subnetId': new_project['subnet'],
						'subnetHostProject': '',
						'cloudCredentials': cloud_credentials_id,
						'region': region_id
					}

					rep = session.post(url=HOST+endpoint.format('/projects/{}/replicationConfigurations'.format(project_id)), data=json.dumps(data))
					if rep.status_code !=201:
						print ('Failed to create replication configuration - {}'.format(rep.status_code))
					else:
						replicationConfiguration_ID = None
						replicationConfiguration_ID = json.loads(rep.content)['id']

						#attach configuration to the project
						data = {
							'replicationConfiguration': replicationConfiguration_ID
						}

						rep = session.patch(url=HOST+endpoint.format('/projects/{}'.format(project_id)), data=json.dumps(data))
						if rep.status_code != 200:
							print ('Failed patching current project with new replication configuration - {}'.format(rep.status_code))	
						else:				
							#output for main function
							print('--------------------------------------------------------------------------------')
							print('Project ' + new_project['new_name'] + ' created successfully')
							apiToken_resp = session.post(url=HOST+endpoint.format('/replaceApiToken'))
							apiToken_resp = session.get(url=HOST+endpoint.format('/me'), data=json.dumps(creds))
							print('API Token: {}'.format(json.loads(apiToken_resp.content)['apiToken']))
							print('--------------------------------------------------------------------------------')

	return 0


if __name__ == '__main__':
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', '--user', required=True, help='User name')
	parser.add_argument('-i', '--inputfile', required=True, help='Input CSV file')

	main(parser.parse_args())
