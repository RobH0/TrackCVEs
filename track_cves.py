# track_cves.py
import argparse
import datetime
import io
import json
import sys
import urllib.request
import zipfile
import os
import webbrowser

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
        print("Successfully downloaded recent CVE feed from NVD.\n")
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

    # Loop grabs all relevent CVE data for all recent CVEs and organizes it into cve_dictionary.
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

# filters out CVEs that aren't related to vendors read from the vendors file.
def filter_cve_by_vendor(cve_dictionary, vendor_list):
    filtered_cves = {}
    for vendor in vendor_list:
        for cve in cve_dictionary:
            if vendor.lower() in cve_dictionary[cve]['description'].lower() and vendor != '':

                filtered_cves[cve] = {}
                for key in cve_dictionary[cve]:
                    filtered_cves[cve][key] = cve_dictionary[cve][key]

    return filtered_cves

# generates CVE reports by severty.
def report_generation(filtered_cves, severity, days):
    report_details = ''
    sev_count = 0
    string_severity = str(severity)
    report_name = string_severity.lower() + '_sev_report_' + \
        str(datetime.today().date()) + '.html'
    report_file_path = ''

    if days == None:
        days = 7

    # Loop adds an entry for each vendor related CVE with a given severity.
    for cve in filtered_cves:
        cve_string_sev = str(filtered_cves[cve].get('baseSeverity'))
        if cve_string_sev == string_severity:
            sev_count += 1
            report_details += '<br><br><b><a href="https://nvd.nist.gov/vuln/detail/' + \
                cve + '">' + cve + '</a></b>:<br> '
            report_details += '<b>Last modified: </b>' + \
                filtered_cves[cve]['last_modified'] + '<br>'
            report_details += str(filtered_cves[cve]['description'])

    report = '<h2>' + str(sev_count) + ' ' + string_severity + \
        ' severity CVEs relating to your vendor list over the past ' + \
        str(days) + ' days:</h2>\n'

    report += report_details

    # Attempts to write the html report to disk.
    try:
        with open(report_name, 'w') as htmlfile:
            htmlfile.write(report)

        if sys.platform == 'win32':
            report_file_path = os.path.dirname(os.path.realpath(report_name)) + '\\' + report_name
        else:
            report_file_path = os.path.dirname(os.path.realpath(report_name)) + '/' + report_name

        print(string_severity + " severity CVE report saved to " + report_file_path)
    except:
        print("Error when writing to report file")



    return report_file_path

# Initiates the generation of the vulnerabiity reports for each severity level.
def generate_web_reports(filtered_cves, days):
    high_sev_file_path = report_generation(filtered_cves, 'HIGH', days)
    med_sev_file_path = report_generation(filtered_cves, 'MEDIUM', days)
    low_sev_file_path = report_generation(filtered_cves, 'LOW', days)
    na_sev_file_path = report_generation(filtered_cves, None, days)

    report_file_path_list = [
        high_sev_file_path, med_sev_file_path, low_sev_file_path, na_sev_file_path]

    return report_file_path_list

# Opens the CVE html reports in the default browser if the user requests this.
def open_reports_in_browser(reports_list):
    correct_input = False
    print('\n')

    while correct_input == False:
        user_response = input(
            "Do you want the above reports to be open in your default browser (y/n)? ")

        if user_response.lower() == 'y':
            print("Opening reports in your default browser")
            correct_input = True
            for path in reports_list:
                webbrowser.open('file://' + path)
        elif user_response.lower() == 'n':
            print("Exiting")
            correct_input = True
        else:
            print("Invalid input!")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='TrackCVE - A python script that helps you keep up to date with the latest CVEs for vendors of your choice')
    parser.add_argument(
        '-f', '--file', help='text file from which vendor names are read. If no file aurgument is passed, vendor names will be read from vendors.txt by default')
    parser.add_argument(
        '-d', '--days', help='used to only display CVEs that were released x number of days in the past.')
    args = parser.parse_args()

    if args.days != None:
        if int(args.days) > 7:
            print("Please pass a '--days' argument value of less than 8.\nOnly 7 days of the most recent CVE data is downloaded")
            sys.exit()

    cve_json_data = get_cve_data()
    vendor_list = read_vendor_file(args.file)
    cve_dictionary = sort_cve_data(cve_json_data, args.days)
    filtered_cves = filter_cve_by_vendor(cve_dictionary, vendor_list)
    report_file_path_list = generate_web_reports(filtered_cves, args.days)
    open_reports_in_browser(report_file_path_list)
