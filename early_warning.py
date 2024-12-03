import os
import re
import requests
import json
import uuid
import ast
import azure.cosmos.cosmos_client as cosmos_client
from datetime import datetime, timedelta
from azure.cosmos import CosmosClient
from azure.cosmos.exceptions import CosmosResourceNotFoundError, CosmosResourceExistsError
import time
import subprocess
from bs4 import BeautifulSoup


# Configuration Variables
HOST = os.environ.get('ACCOUNT_HOST', '{account-host}')
MASTER_KEY = os.environ.get('ACCOUNT_KEY', '{account-key}')
EARLY_WARNING = os.environ.get('COSMOS_CONTAINER', '{cosmos-container}')
GITHUB_API_TOKEN = '{github-api-token}'

# OK
def upload_to_cosmos(data, container_client):
    for item in data:
        try:
            container_client.create_item(body=item)
        except CosmosResourceExistsError:
            pass

# OK
def convert_cpe_to_readable(cpe):
    if cpe != "":
        components = cpe.split(':')
        vendor = components[3].title()
        product = components[4].title()
        if len(components) > 5:
            version = components[5]
            readable_cpe = f"{vendor} {product} {version}"
        else:
            readable_cpe = f"{vendor} {product}"
    else:
        readable_cpe = ""
    return readable_cpe

# OK
def extract_vulnerable_versions(cpe):
    components = cpe['criteria'].split(':')
    specific_version = components[5] if len(components) > 5 and components[5] != '*' else ""
    additional_qualifiers = components[6] if len(components) > 6 and components[6] != '*' else ""
     
    version_info = ""
    if specific_version:
        version_info = specific_version
        if additional_qualifiers:
            version_info += f" {additional_qualifiers}"  
            return version_info  
    elif additional_qualifiers:
        version_info = f"{additional_qualifiers}"  
        return version_info   
    elif 'versionStartIncluding' in cpe and 'versionEndIncluding' in cpe:
        version_info = f"Da {cpe['versionStartIncluding']} a {cpe['versionEndIncluding']} (inclusa)"
    elif 'versionStartIncluding' in cpe and 'versionEndExcluding' in cpe:
        version_info = f"Da {cpe['versionStartIncluding']} a {cpe['versionEndExcluding']} (esclusa)"
    elif 'versionEndIncluding' in cpe and 'versionStartIncluding' not in cpe:
        version_info = f"Fino a {cpe['versionEndIncluding']} (inclusa)"
    elif 'versionEndExcluding' in cpe and 'versionStartIncluding' not in cpe:
        version_info = f"Fino a {cpe['versionEndExcluding']} (esclusa)"
            
    return version_info
    
# OK
def last_published(response_pub):   
    if response_pub.status_code == 200:
        cve_data_pub = response_pub.json()
        vulnerabilities = cve_data_pub.get('vulnerabilities',[])
        
        extracted_info_pub = []
        stato = "New"
        for vuln in vulnerabilities:
            vuln_status = vuln['cve']['vulnStatus']
            if vuln_status != "Rejected":
                cve_id = vuln['cve']['id']
                id = uuid.uuid5(uuid.NAMESPACE_DNS, cve_id).hex
                published_date = vuln['cve']['published']
                modified_date = vuln['cve']['lastModified']
                description_en = next((desc['value'] for desc in vuln['cve']['descriptions'] if desc['lang'] == 'en'), '')

                metrics = {}
                for version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in vuln['cve']['metrics']:
                        metrics = vuln['cve']['metrics'][version][0]
                        break
              
                cpe_data = []
                vendor = ""
                product_list = []
                affected_cpe_string = ""
                products_string = ""
                url_string = ""
                affected_os_list = []
                affected_os_string = ""
                first_vendor = None
                if 'configurations' in vuln['cve']:
                    for node in vuln['cve']['configurations'][0]['nodes']:
                        for cpe in node['cpeMatch']:                           
                            cpe_string = cpe.get('criteria', '')
                            cpe_components = cpe_string.split(':')
                            vulnerable_versions = extract_vulnerable_versions(cpe)                            
                            readable_cpe = convert_cpe_to_readable(cpe_string)                          
                            if not vendor:
                                vendor = readable_cpe.split(' ')[0]
                                
                            current_vendor = readable_cpe.split(' ')[0] if readable_cpe.split(' ') else ''
                            if first_vendor is None:
                                first_vendor = current_vendor
                                
                            if current_vendor == first_vendor:                            
                                product = readable_cpe.split(' ')[1] if len(readable_cpe.split(' ')) > 1 else ''
                                if product and product not in product_list:
                                    product_list.append(product)                             
                            
                            if cpe_components[2].lower() == 'o' and cpe_components[5] == '-':
                                vendor_os = cpe_components[3].title()
                                product_os = cpe_components[4].title()
                                affected_os_list.append(f"{vendor_os} {product_os}")
                            else:
                                vulnerable_versions = extract_vulnerable_versions(cpe)
                                cpe_entry = f"{cpe_string} {vulnerable_versions}"
                                cpe_data.append(cpe_entry)
                                                
                        affected_cpe_string = "\n".join(cpe_data)
                        products_string = ", ".join(product_list)   
                        affected_os_string = ", ".join(affected_os_list)                	
                
                required_action = "{required-action}"
                urls = [ref['url'] for ref in vuln['cve']['references']] if 'references' in vuln['cve'] else []
                url_string = "\n".join(urls)
                
                weaknesses = vuln.get('cve', {}).get('weaknesses', [])
                if weaknesses:
                    cwe_description = weaknesses[0].get('description', [])
                    if cwe_description:
                        cwe_id = cwe_description[0].get('value', '').replace('CWE-', '')
                    else:
                        cwe_id = ""
                else:
                    cwe_id = ""                   
                        
                extracted_info_pub.append({
                    'id': id,
                    'Cve_id': cve_id,
                    'Published_date': published_date,
                    'Modified_date': modified_date,
                    'Description': description_en,
                    'Base_severity': metrics.get('cvssData', {}).get('baseSeverity', ''),
                    'Base_score': metrics.get('cvssData', {}).get('baseScore', ''),
                    'Vector_string': metrics.get('cvssData', {}).get('vectorString', ''),
                    'Affected_cpe': affected_cpe_string,
                    'Affected_os': affected_os_string,
                    'Vendor': vendor,
                    'Product': products_string,
                    'Required_action': required_action,
                    'Urls': url_string,
                    'Status': stato,
                    'Exploit': '',
                    'KEV': 'NO',
                    'KnownRansomwareCampaignUse': '',
                    'KVE_Notes': '',
                    'Category': cwe_id,
                    'Analisys': ''
                })
        return extracted_info_pub

    else:
        print(f"Error in Last Published request: {response_pub.status_code}")
        return []

# OK
def last_modified(response_mod):
    if response_mod.status_code == 200:
        cve_data_pub = response_mod.json()
        
        vulnerabilities = cve_data_pub.get('vulnerabilities', [])

        extracted_info_mod = []
        for vuln in vulnerabilities:
            vuln_status = vuln['cve']['vulnStatus']
            if vuln_status != "Rejected":
                cve_id = vuln['cve']['id']
                published_date = vuln['cve']['published']
                modified_date = vuln['cve']['lastModified']
                id = uuid.uuid5(uuid.NAMESPACE_DNS, cve_id).hex
                description_en = next((desc['value'] for desc in vuln['cve']['descriptions'] if desc['lang'] == 'en'), '')

                metrics = {}
                for version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in vuln['cve']['metrics']:
                        metrics = vuln['cve']['metrics'][version][0]
                        break
                        
                base_severity = metrics.get('baseSeverity', '')
                base_score = metrics.get('cvssData', {}).get('baseScore', '')
                vector_string = metrics.get('cvssData', {}).get('vectorString', '')
                required_action = "{required-action}"
                
                cpe_data = []
                vendor = ""
                product_list = []
                affected_cpe_string = ""
                products_string = ""
                url_string = ""
                affected_os_list = []
                affected_os_string = ""
                first_vendor = None
                affected_os_list = []
                affected_os_string = ""
                if 'configurations' in vuln['cve']:
                    for node in vuln['cve']['configurations'][0]['nodes']:
                        for cpe in node['cpeMatch']:                           
                            cpe_string = cpe.get('criteria', '')
                            cpe_components = cpe_string.split(':')
                            vulnerable_versions = extract_vulnerable_versions(cpe)                            
                            readable_cpe = convert_cpe_to_readable(cpe_string)                          
                            if not vendor:
                                vendor = readable_cpe.split(' ')[0]
                                
                            current_vendor = readable_cpe.split(' ')[0] if readable_cpe.split(' ') else ''
                            if first_vendor is None:
                                first_vendor = current_vendor
                                
                            if current_vendor == first_vendor:                            
                                product = readable_cpe.split(' ')[1] if len(readable_cpe.split(' ')) > 1 else ''
                                if product and product not in product_list:
                                    product_list.append(product)                            
                            
                            if cpe_components[2].lower() == 'o' and cpe_components[5] == '-':
                                vendor_os = cpe_components[3].title()
                                product_os = cpe_components[4].title()
                                affected_os_list.append(f"{vendor_os} {product_os}")
                            else:
                                vulnerable_versions = extract_vulnerable_versions(cpe)
                                cpe_entry = f"{cpe_string} {vulnerable_versions}"
                                cpe_data.append(cpe_entry)
                                                
                        affected_cpe_string = "\n".join(cpe_data)
                        products_string = ", ".join(product_list)   
                        affected_os_string = ", ".join(affected_os_list)	                     

                urls = [ref['url'] for ref in vuln['cve']['references']] if 'references' in vuln['cve'] else []
                url_string = "\n".join(urls)
                weaknesses = vuln.get('cve', {}).get('weaknesses', [])
                if weaknesses:
                    cwe_description = weaknesses[0].get('description', [])
                    if cwe_description:
                        cwe_id = cwe_description[0].get('value', '').replace('CWE-', '')
                    else:
                        cwe_id = ""
                else:
                    cwe_id = ""
                    
                extracted_info_mod.append({
                    'id': id,
                    'Cve_id': cve_id,
                    'Published_date': published_date,
                    'Modified_date': modified_date,
                    'Description': description_en,
                    'Base_severity': base_severity,
                    'Base_score': base_score,
                    'Vector_string': vector_string,
                    'Affected_cpe': affected_cpe_string,
                    'Affected_os': affected_os_string,
                    'Vendor': vendor,
                    'Product': products_string,
                    'Required_action': required_action,
                    'Urls': url_string,
                    'Status': 'New',
                    'Exploit': '',
                    'KEV': 'NO',
                    'KnownRansomwareCampaignUse': '',
                    'KVE_Notes': '',
                    'Category': cwe_id,
                    'Analisys': ''
                })
        return extracted_info_mod  
            
    else:
        print(f"Error in Last Modified request: {response_mod.status_code}")       
        return []

# OK
def DB_check(extracted_info_mod, container_client):
    for mod_item in extracted_info_mod:
        cve_id = mod_item['Cve_id']
        query = f"SELECT * FROM c WHERE c.Cve_id = '{cve_id}'"
        items = list(container_client.query_items(query=query, enable_cross_partition_query=True))
        
        if items:
            db_item = items[0]
            db_item['Base_severity'] = mod_item['Base_severity']
            db_item['Base_score'] = mod_item['Base_score']
            db_item['Vector_string'] = mod_item['Vector_string']
            db_item['Exploitability_score'] = mod_item.get('Exploitability_score', '')
            db_item['Affected_cpe'] = mod_item['Affected_cpe']
            db_item['Description'] = mod_item['Description']
            db_item['Status'] = "Modified"
            container_client.upsert_item(db_item)
        else:
            container_client.create_item(body=mod_item)

# OK            
def search_github_cve(cve_search):
    api_url = "https://api.github.com/search/repositories?q="+cve_search

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {GITHUB_API_TOKEN}",
    }

    cve_response = requests.get(api_url, headers=headers)
    exploit_urls = []

    if cve_response.status_code == 200:
        data = json.loads(cve_response.text)
        
        for item in data.get("items", []):
            html_url = item.get("html_url")
            if html_url:
                exploit_urls.append(html_url)
        time.sleep(10)
    else:
        print(f"Error {cve_search} {cve_response.status_code}")

    return exploit_urls

# OK
def exploit_update(container_client):
    query = "SELECT * FROM c WHERE c.exploit = ''"
    items = list(container_client.query_items(query=query, enable_cross_partition_query=True))
    
    for item in items:
        cve_id = item['Cve_id']
        exploit_urls = search_github_cve(cve_id)
        if exploit_urls:
            item['exploit'] = exploit_urls
            container_client.upsert_item(item)
   
# OK   
def kev_check(container_client):
    kev_url = "https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_response = requests.get(kev_url)
    
    if kev_response.status_code == 200:
        kev_data = kev_response.json()
        kev_vulnerabilities = {vuln['cveID']: vuln for vuln in kev_data.get('vulnerabilities', [])}
        
        items = list(container_client.read_all_items(max_item_count=-1))
        for item in items:
            cve_id = item['Cve_id']
            if cve_id in kev_vulnerabilities:
                kev_info = kev_vulnerabilities[cve_id]
                item['KEV'] = 'YES'
                item['KnownRansomwareCampaignUse'] = kev_info.get('KnownRansomwareCampaignUse', '')
                item['Notes'] = kev_info.get('notes', '')
                                                
                container_client.upsert_item(item)
            else:
                pass
    else:
        print(f"Errore KEV: {kev_response.status_code}")  

# OK
def get_cwe_description(container_client):
    items = list(container_client.read_all_items(max_item_count=-1))
    cwe_ids = set()
    cwe_descriptions = {}
    for item in items:
        cwe_id = item.get('Category')        
        if cwe_id and cwe_id not in cwe_ids and cwe_id != "NVD-noinfo":           
            cwe_numeric = ''.join(filter(str.isdigit, cwe_id))
            if cwe_numeric and cwe_numeric not in cwe_ids:
                cwe_ids.add(cwe_numeric)
    cwe_descriptions = {cwe_id: f"CWE-{cwe_id}" for cwe_id in cwe_ids}
    while cwe_ids:
        cwe_id_string = ','.join(cwe_ids)

        cwe_url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id_string}"
        response = requests.get(cwe_url)
    
        if response.status_code == 200:
            cwe_data = response.json()
            for weakness in cwe_data.get('Weaknesses', []):           
                cwe_descriptions = {str(weakness['ID']): f"CWE-{weakness['ID']}: {weakness['Name']}" for weakness in cwe_data.get('Weaknesses', [])}
                cwe_ids.remove(str(weakness['ID']))
 	
        else:
            missing_cwe_match = re.search(r"for weakness: cwe \((\d+)\) not found", response.text)
            if missing_cwe_match:
                missing_cwe_id = missing_cwe_match.group(1)               
                cwe_descriptions[missing_cwe_id] = f"CWE-{missing_cwe_id}"  
                cwe_ids.remove(missing_cwe_id)  
    
    for item in items:
        cwe_id = item.get('Category')
        if cwe_id and cwe_id != "NVD-noinfo":
            cwe_numeric = ''.join(filter(str.isdigit, cwe_id))
            if cwe_numeric in cwe_descriptions:
                item['Category'] = cwe_descriptions[cwe_numeric]
                container_client.upsert_item(item)
        else:
            item['Category'] = f"CWE-{cwe_id}"

# OK
def update_records(container_client):
    query = "SELECT * FROM c WHERE c.Vendor = '' OR c.Product = ''"
    items = list(container_client.query_items(query=query, enable_cross_partition_query=True))    
    
    for item in items:
        affected_cpe = item.get('Affected_cpe', '').lower()
        found_vendor = None
        found_product = None
        
        if affected_cpe:
            for cpe in affected_cpe.split('\n'):
                components = cpe.split(' ')
                print(f"Components: {components}")
                if len(components) >= 5:
                    vendor = components[3]
                    product = components[4] 
                    print(f"Vendor: {vendor}, product: {product}")                  
                    found_vendor = vendor.lower()
                    found_product = product.lower()
                    item['Vendor'] = found_vendor
                    item['Product'] = found_product
                    
                    container_client.upsert_item(item)
                    continue

        if found_vendor:
            item['Vendor'] = found_vendor
        if found_product:
            item['Product'] = found_product
            
        if found_vendor or found_product:
            container_client.upsert_item(item)
# ---------------------------------------------------------------------------------------------------------------------------
tag = r"""
    ______           __         _       __                 _            
   / ____/___ ______/ /_  __   | |     / /___ __________  (_)___  ____ _
  / __/ / __ `/ ___/ / / / /   | | /| / / __ `/ ___/ __ \/ / __ \/ __ `/
 / /___/ /_/ / /  / / /_/ /    | |/ |/ / /_/ / /  / / / / / / / / /_/ / 
/_____/\__,_/_/  /_/\__, /     |__/|__/\__,_/_/  /_/ /_/_/_/ /_/\__, /  
                   /____/                                      /____/   
"""
print(tag)

end_date = datetime.now()
start_date_pub = end_date - timedelta(days=1)
start_date_mod = end_date - timedelta(days=1)

lastPubStartDate = start_date_pub.strftime('%Y-%m-%dT%H:%M:%S.000')
lastPubEndDate = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
url_pub = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={lastPubStartDate}&pubEndDate={lastPubEndDate}"
response_pub = requests.get(url_pub)

lastModStartDate = start_date_mod.strftime('%Y-%m-%dT%H:%M:%S.000Z')
lastModEndDate = end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
url_mod = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={lastModStartDate}&lastModEndDate={lastModEndDate}"
response_mod = requests.get(url_mod)

client = cosmos_client.CosmosClient(HOST, {'masterKey': MASTER_KEY}, user_agent='CosmosDBPythonQuickStart', user_agent_overwrite=True)
databases = list(client.list_databases())

for database in databases:
    db = client.get_database_client(database['id'])
    if database['id'] == '{database}':
        container_enti = db.get_container_client({container-client})
        
        print("Last Published search...")
        extracted_info_pub = last_published(response_pub)
        print("Last Published: OK")
        
        print("DB Upload...")
        upload_to_cosmos(extracted_info_pub, container_enti) 
        print("DB Upload: OK")
        
        print("Last Modified search...")
        extracted_info_mod = last_modified(response_mod)
        print("Last Modified: OK")
        
        print("DB update...")
        DB_check(extracted_info_mod, container_enti)
        print("DB update: OK")
        
        print("Exploit update")
        exploit_update(container_enti)
        print("Exploit update: OK")
        
        print("KEV check")
        kev_check(container_enti)
        print("KEV check: OK")
        
        print("CWE check")
        get_cwe_description(container_enti)
        print("CWE check: OK")
        
        print("Vendor-product check")
        update_records(container_enti)
        print("Vendor-product check: OK")

