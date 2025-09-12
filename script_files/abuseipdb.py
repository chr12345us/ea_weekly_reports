import requests
from urllib3.exceptions import InsecureRequestWarning
import json
import os


#open file run.sh and find string aipdb_key

run_file = 'run.sh'

with open (run_file) as f:
    for line in f:
    #find line starting with aipdb_key
        if line.startswith('abuseipdb_key'):
            #print value after = sign
            
            aipdb_key = line.split('=')[1].replace('"','').replace('\n','')

            continue

aipdb_dict = {}
aipdb_dict['Src IP details'] = []


def internet_conn():

    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': '8.8.8.8',
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': aipdb_key
    }
    
    # Disable only the InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    try:
        response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
        print(response.status_code)
        if response.status_code == 200:
            print('Internet connection is available.')
            return True
        
        else:
            print(f'Healtcheck response is {response.status_code}')
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        print("No internet connection")
        return False

def abuseipdb_call(ipAddress, cust_id):

    raw_data_path = "./tmp_files/" + cust_id + "/"
    
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ipAddress,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': aipdb_key
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)

    # Formatted output
    decodedResponse = json.loads(response.text)
    # print(json.dumps(decodedResponse, sort_keys=True, indent=4))

    aipdb_dict['Src IP details'].append(decodedResponse)

    with open(raw_data_path + 'AbuseIPDB.json', 'w') as outfile:
        json.dump(aipdb_dict,outfile)