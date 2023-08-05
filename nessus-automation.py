#!/usr/bin/env python3

import requests
import json
import ssl
import pandas as pd
import io
import argparse
import warnings

#warnings.filterwarnings("ignore", message="Unverified HTTPS request is being made to host 'kali'.*")


def printFolderMenu(folders):
    for folder in folders:
        print(folder.get("id"), "--", folder.get("name"))


def printScanMenu(scans, folder_id):
    for scan in scans:
        if(scan.get("folder_id") == folder_id):
            print(scan.get("id"), "--", scan.get("name"))

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
                                     prog="python script.py", usage="%(prog)s -i <127.0.0.1> -u <nessus_user> -p <nessus_pass> ")

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
        print("ip: "+ip+"\nport: "+port)
    else:
        ip = args.server
        port = "8834"

    base_url = "http://" + ip + ":" + port
    creds = {"username": args.user, "password": args.passwd}
    #creds = {"username": "0x0h3mz4", "password": "n3ssUs1010%%"}

    response1 = requests.post(base_url + "/session", creds, verify=False)
    if checkStatus(response1, "Login successful", "Invalid Login credentials"):
        token = json.loads(response1.text)
        response2 = requests.get(
            base_url + "/scans", headers={"X-Cookie": "token=" + token["token"]}, verify=False)
        if checkStatus(response2, "Fetching scans data\n", "Unable to fetch nessus scan"):
            allscans = json.loads(response2.text)

            printFolderMenu(allscans["folders"])
            print("\n")
            folder_id = int(input("Enter the folder you want : "))
            print("\n \n")
            printScanMenu(allscans["scans"], folder_id)
            print("\n")
            scan = int(input("Enter the scan you want : "))
            response3 = requests.get(base_url + "/scans/"+str(scan),
                                     headers={"X-Cookie": "token=" + token["token"]}, verify=False)
            if checkStatus(response1, "Fetching data from the choosen scan", "Unable to fetch the choosen scan"):

                scans = json.loads(response3.text)
                file = json.dumps(scans)
                fhosts = json.dumps(scans["hosts"])
                fvulnerabilities = json.dumps(scans["vulnerabilities"])
                f = open("allscans.json", "a")
                f.write(file)
                f.close()
                f = open("hosts.json", "a")
                f.write(fhosts)
                f.close()
                f = open("vulnerabilities.json", "a")
                f.write(fvulnerabilities)
                f.close()
                finalList = []
                l = [dict(zip(["vulnerabilities"], [x.get("plugin_name")]))
                     for x in scans["vulnerabilities"]]
                for i in l:
                    i["adress_ip"] = []
                for j in l:
                    j["recommendation"] = []
                for n in l:
                    n["severity"] = []

                for host in scans["hosts"]:

                    response4 = requests.get(base_url + "/scans/"+str(scan)+"/hosts/"+str(host.get(
                        "host_id")), headers={"X-Cookie": "token=" + token["token"]}, verify=False)
                    # if checkStatus(response4, "nice", "nope"):
                    vuln_host = json.loads(response4.text)
                    for i in l:
                        for vuln in vuln_host.get("vulnerabilities"):
                            match vuln.get("severity"):
                                case 0:
                                    i["severity"] = "info"

                                case 1 | 2 | 3:
                                    i["severity"] = "low"

                                case 4 | 5 | 6:
                                    i["severity"] = "medium"

                                case 7 | 8:
                                    i["severity"] = "high"

                                case 9 | 10:
                                    i["severity"] = "critical"
                                case _:
                                    print("Unknown")

                            if(i.get("vulnerabilities") == vuln.get("plugin_name")):
                                i["adress_ip"].append([host.get("hostname")])

                # convert to excel
                df_json = pd.json_normalize(l)
                df_json.to_excel("DATAFILE.xlsx")

                print("check your folder for the file DATAFILE.xlsx")


if __name__ == "__main__":
    main()
