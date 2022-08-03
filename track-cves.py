# track-cves.py

# To implement:
# 1. Download most recent cve data from nvd. Done
# 2. Add parameters that ask for the user to specify relative time period cves should be displayed for.
# 3. From that time period only show CVEs relating to specific vendors.
# 4. Display impact info for cve.

import argparse
import datetime
import io
import json
import sys
import urllib.request
import zipfile


def readVendorsFile(vendor_filename="vendors.txt"):
    vendor_list = []

    with open(vendor_filename) as vendors:
        vendor_list = vendors.read().splitlines()
        
    return vendor_list





def getCVEData():

    print("Downloading the yearly NVD CVE feeds.")

    cve_recent_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
    cve_recent_feed_file = ''

    # Attempts to download the most recent CVE feed in json format.
    try:
        with urllib.request.urlopen(cve_recent_url) as cves:
            cve_recent_feed_file = cves.read()
        print("Successfully downloaded recent CVE feed")
    except Exception as e:
        print(e)
        print("Error attempting to download the NVD recent CVE feed.")
        sys.exit(0)

    # Unzips the cve feed file
    cve_zip_file = zipfile.ZipFile(io.BytesIO(cve_recent_feed_file), mode='r')
    unzipped_cve_data = cve_zip_file.open("nvdcve-1.1-recent.json")


    cve_json_data = json.load(unzipped_cve_data)

    return cve_json_data

def sortData():
    for cve in cve_json_data['CVE_Items']:
        cve_id = cve['cve']['CVE_data_meta']['ID']
        cve_pub_date = cve['publishedDate'].split('T')[0]
        cve_last_mod = cve['lastModifiedDate'].split('T')[0]
        for cve_desc_item in cve['cve']['description']['description_data']:
            #print("new item")
            #print(cve_desc_item)
            if cve_desc_item['lang'] == 'en':
                cve_desc = cve_desc_item['value']

                if "** REJECT **" not in cve_desc:
                    break#print(cve_id + "\n  Published date:" + cve_pub_date + "\n  Last modified: " + cve_last_mod + "\n  Description: " + cve_desc + "\n\n")

        #for cve_impact_item in cve['cve']['configurations']['impact']:
        #    print(cve_impact_item)

#print(cve_jason_data['CVE_Items'][50])

if __name__ == '__main__':
    cve_json_data = getCVEData()
    readVendorsFile()
    sortData()

"""
example json cve format

{'cve': {'data_type': 'CVE', 'data_format': 'MITRE', 'data_version': '4.0', 'CVE_data_meta': {'ID': 'CVE-2022-35672', 'ASSIGNER': 'psirt@adobe.com'}, 'problemtype': {'problemtype_data': [{'description': [{'lang': 'en', 'value': 'CWE-125'}]}]}, 'references': {'reference_data': [{'url': 'https://helpx.adobe.com/security/products/acrobat/apsb22-16.html', 'name': 'https://helpx.adobe.com/security/products/acrobat/apsb22-16.html', 'refsource': 'MISC', 'tags': []}]}, 'description': {'description_data': [{'lang': 'en', 'value': 'Adobe Acrobat Reader version 22.001.20085 (and earlier), 20.005.30314 (and earlier) and 17.012.30205 (and earlier) are affected by an out-of-bounds read vulnerability when parsing a crafted file, which could result in a read past the end of an allocated memory structure. An attacker could leverage this vulnerability to execute code in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.'}]}}, 'configurations': {'CVE_data_version': '4.0', 'nodes': []}, 'impact': {'baseMetricV3': {'cvssV3': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'attackVector': 'LOCAL', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'REQUIRED', 'scope': 'UNCHANGED', 'confidentialityImpact': 'HIGH', 'integrityImpact': 'HIGH', 'availabilityImpact': 'HIGH', 'baseScore': 7.8, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 1.8, 'impactScore': 5.9}}, 'publishedDate': '2022-07-27T17:15Z', 'lastModifiedDate': '2022-07-27T17:15Z'}
"""
