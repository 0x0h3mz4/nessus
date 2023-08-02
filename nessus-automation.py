#!/usr/bin/env python3

import requests
import json
import ssl
import pandas as pd
import io
import argparse


# Print message on stdout
def printMessage(msg, flag=1):
    if flag == 1:
        print("[+] " + msg)
    elif flag == 0:
        print("[-] " + msg)
    elif flag == 2:
        print("[*] " + msg)
    else:
        print(msg)

# Check response code for an HTTP Response and print req message


def checkStatus(resp, status_msg, error_msg):
    if resp.status_code == 200:
        printMessage(status_msg, 1)
        return True
    else:
        printMessage(error_msg, 0)
        return False


def main():
    parser = argparse.ArgumentParser(description="A python script for automating exporting from nessus server to excel",
                                     epilog="written by 0x0h3mz4",
                                     prog='python script.py', usage='%(prog)s -i <127.0.0.1> -u <nessus_user> -p <nessus_pass> ')

    parser.add_argument(
        "-i", "--server", help="IP[:PORT] of nessus server", required=True)
    parser.add_argument(
        "-u", "--user", help="username of nessus server", required=True)
    parser.add_argument(
        "-p", "--passwd", help="password of nessus server", required=True)
    args = parser.parse_args()

    if ":" in args.server:
        ip = args.server.split(":")[0]
        port = args.server.split(":")[1]
    else:
        ip = args.server
        port = "8834"

    base_url = "https://" + ip + ":" + port
    creds = {'username': args.user, 'password': args.passwd}
    #creds = {'username': '0x0h3mz4', 'password': 'n3ssUs1010%%'}

    response1 = requests.post(base_url + "/session", creds, verify=False)
    if checkStatus(response1, "Login successful", "Invalid Login credentials"):
        token = json.loads(response1.text)
        response2 = requests.get(
            base_url + "/scans", headers={'X-Cookie': 'token=' + token['token']}, verify=False)
        if checkStatus(response2, "Fetching scans data\n", "Unable to fetch nessus scan"):
            scans = json.loads(response2.text)
            # test vulnerabilities critisisity
            vuln = requests.get(
                base_url + "/analysis", headers={'X-Cookie': 'token=' + token['token']}, verify=False)
            vulnscan = json.loads(vuln.text)
            # print(json.dumps(scans))
            # convert to excel
            df_json = pd.io.json.json_normalize(scans["scans"])
            df_json.to_excel('DATAFILE.xlsx')


if __name__ == '__main__':
    main()
