# track-cves.py

# To implement:
# 1. Add parameters that ask for the user to specify relative time period cves should be displayed for.
# 2. Use argparse to allow a user to specify a vendor file via command line arguments.
# 3. Display NVD link with CVE.
# 4. Search for vendor name within cve ASSIGNER.
# 5. Refactor code.


import argparse
import datetime
import io
import json
import sys
import urllib.request
import zipfile

from datetime import datetime, timedelta


def read_vendor_file(vendor_filename):
    vendor_list = []

    try:
        if vendor_filename == None:
            vendor_filename = 'vendors.txt'
        with open(vendor_filename, 'r') as vendors:
            vendor_list = vendors.read().splitlines()
    except:
        print("The Vendor file you specified does not exist.")
        sys.exit()

    return vendor_list


def get_cve_data():

    print("Downloading the most recent CVE data.")

    cve_recent_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
    cve_recent_feed_file = ''

    # Attempts to download the most recent CVE feed in json format.
    try:
        with urllib.request.urlopen(cve_recent_url) as cves:
            cve_recent_feed_file = cves.read()
        print("Successfully downloaded recent CVE feed from NVD")
    except Exception as e:
        print(e)
        print("Error attempting to download the NVD recent CVE feed.")
        sys.exit(0)

    # Unzips the cve feed file
    cve_zip_file = zipfile.ZipFile(io.BytesIO(cve_recent_feed_file), mode='r')
    unzipped_cve_data = cve_zip_file.open("nvdcve-1.1-recent.json")

    cve_json_data = json.load(unzipped_cve_data)

    return cve_json_data


def sort_cve_data(cve_json_data, days):

    cve_dictionary = {}

    if days == None:
        days = 7
    else:
        days = int(days)

    oldest_date = datetime.today() - timedelta(days=days)

    for cve in cve_json_data['CVE_Items']:
        cve_modified_date = datetime.strptime(
            cve['lastModifiedDate'].split('T')[0], '%Y-%m-%d')

        if oldest_date <= cve_modified_date:

            cve_id = cve['cve']['CVE_data_meta']['ID']
            cve_pub_date = cve['publishedDate'].split('T')[0]
            cve_last_mod = cve['lastModifiedDate'].split('T')[0]

            cve_dictionary[cve_id] = {}
            cve_dictionary[cve_id]['published'] = cve_pub_date
            cve_dictionary[cve_id]['last_modified'] = cve_last_mod
            for cve_desc_item in cve['cve']['description']['description_data']:
                if cve_desc_item['lang'] == 'en':
                    cve_desc = cve_desc_item['value']
                    cve_dictionary[cve_id]['description'] = cve_desc

            for key in cve['impact']:
                if key == 'baseMetricV3':
                    cve_dictionary[cve_id]['exploitabilityScore'] = cve['impact']['baseMetricV3']['exploitabilityScore']
                    cve_dictionary[cve_id]['impactScore'] = cve['impact']['baseMetricV3']['impactScore']
                    cve_dictionary[cve_id]['baseScore'] = cve['impact']['baseMetricV3']['cvssV3']['baseScore']
                    cve_dictionary[cve_id]['baseSeverity'] = cve['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                    cve_dictionary[cve_id]['attackVector'] = cve['impact']['baseMetricV3']['cvssV3']['attackVector']
                    cve_dictionary[cve_id]['attackComplexity'] = cve['impact']['baseMetricV3']['cvssV3']['attackComplexity']
                    cve_dictionary[cve_id]['privilegesRequired'] = cve['impact']['baseMetricV3']['cvssV3']['privilegesRequired']
                    cve_dictionary[cve_id]['userInteraction'] = cve['impact']['baseMetricV3']['cvssV3']['userInteraction']

    return cve_dictionary


def filter_cve_by_vendor(cve_dictionary, vendor_list):
    filtered_cves = {}
    for vendor in vendor_list:
        for cve in cve_dictionary:
            if vendor.lower() in cve_dictionary[cve]['description'].lower():

                filtered_cves[cve] = {}
                for key in cve_dictionary[cve]:
                    filtered_cves[cve][key] = cve_dictionary[cve][key]

    return filtered_cves


def output_cves(filtered_cves):
    print("\nFILTERED CVEs:")

    print("\nHigh Severity: ")
    for cve in filtered_cves:
        if filtered_cves[cve].get('baseSeverity') != None and filtered_cves[cve]['baseSeverity'] == 'HIGH':
            print("\n" + cve)
            for key in filtered_cves[cve]:
                print(key + ": " + str(filtered_cves[cve][key]))

    print("\nMedium Severity: ")
    for cve in filtered_cves:
        if filtered_cves[cve].get('baseSeverity') != None and filtered_cves[cve]['baseSeverity'] == 'MEDIUM':
            print("\n" + cve)
            for key in filtered_cves[cve]:
                print(key + ": " + str(filtered_cves[cve][key]))

    print("\nLow Severity: ")
    for cve in filtered_cves:
        if filtered_cves[cve].get('baseSeverity') != None and filtered_cves[cve]['baseSeverity'] == 'LOW':
            print("\n" + cve)
            for key in filtered_cves[cve]:
                print(key + ": " + str(filtered_cves[cve][key]))

    print("Unspecified Severity: ")
    for cve in filtered_cves:
        if filtered_cves[cve].get('baseSeverity') == None:
            print("\n" + cve)
            for key in filtered_cves[cve]:
                print(key + ": " + str(filtered_cves[cve][key]))

def generate_web_report(filtered_cves, days):
    high_sev_count = 0
    med_sev_count = 0
    low_sev_count = 0
    report_details = ''

    for cve in filtered_cves:
        if filtered_cves[cve].get('baseSeverity') != None and filtered_cves[cve]['baseSeverity'] == 'HIGH':
            high_sev_count += 1
            report_details += '<br><br><a href="https://nvd.nist.gov/vuln/detail/' + cve + '">' + cve + '</a>: '
            report_details += str(filtered_cves[cve]['description'])
            print(filtered_cves[cve]['description'])
            for key in filtered_cves[cve]:
                break#print(key + ": " + str(filtered_cves[cve][key]))

    report = '<h2>' + str(high_sev_count) + ' HIGH severity CVEs relating to your vendor list over the past ' + str(days) + ' days:</h2>\n'

    report += report_details


    try:
        high_sev_report = 'high_sev_report.html'
        with open(high_sev_report, 'w') as htmlfile:
            htmlfile.write(report)

        print("High severity CVE report saved to", high_sev_report)
    except:
        print("Error when writing to report file")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='TrackCVE')
    parser.add_argument(
        '-f', '--file', help='Text file from which Vendor names are read.')
    parser.add_argument(
        '-d', '--days', help='Used to only display CVEs that were released x number of days in the past')
    args = parser.parse_args()

    if args.days != None:
        if int(args.days) > 7:
            print("Please pass a ''--days' argument value of less than 8.\nOnly 7 days of the most recent CVE data is downloaded")
            sys.exit()

    cve_json_data = get_cve_data()
    vendor_list = read_vendor_file(args.file)
    cve_dictionary = sort_cve_data(cve_json_data, args.days)
    filtered_cves = filter_cve_by_vendor(cve_dictionary, vendor_list)
    #output_cves(filtered_cves)
    generate_web_report(filtered_cves, 7)

# https://nvd.nist.gov/vuln/detail/CVE-2022-23733  example vuln URL

"""
example json cve format

{'cve': {'data_type': 'CVE', 'data_format': 'MITRE', 'data_version': '4.0', 'CVE_data_meta': {'ID': 'CVE-2022-35672', 'ASSIGNER': 'psirt@adobe.com'}, 'problemtype': {'problemtype_data': [{'description': [{'lang': 'en', 'value': 'CWE-125'}]}]}, 'references': {'reference_data': [{'url': 'https://helpx.adobe.com/security/products/acrobat/apsb22-16.html', 'name': 'https://helpx.adobe.com/security/products/acrobat/apsb22-16.html', 'refsource': 'MISC', 'tags': []}]}, 'description': {'description_data': [{'lang': 'en', 'value': 'Adobe Acrobat Reader version 22.001.20085 (and earlier), 20.005.30314 (and earlier) and 17.012.30205 (and earlier) are affected by an out-of-bounds read vulnerability when parsing a crafted file, which could result in a read past the end of an allocated memory structure. An attacker could leverage this vulnerability to execute code in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.'}]}}, 'configurations': {
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           'CVE_data_version': '4.0', 'nodes': []}, 'impact': {'baseMetricV3': {'cvssV3': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'attackVector': 'LOCAL', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'REQUIRED', 'scope': 'UNCHANGED', 'confidentialityImpact': 'HIGH', 'integrityImpact': 'HIGH', 'availabilityImpact': 'HIGH', 'baseScore': 7.8, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 1.8, 'impactScore': 5.9}}, 'publishedDate': '2022-07-27T17:15Z', 'lastModifiedDate': '2022-07-27T17:15Z'}
"""
