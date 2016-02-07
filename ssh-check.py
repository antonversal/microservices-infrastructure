#!/usr/bin/env python
from __future__ import print_function
import json
import shlex
import subprocess
import sys

# get the hosts
try:
    hosts = subprocess.check_output(shlex.split("plugins/inventory/terraform.py --hostfile"))
except subprocess.CalledProcessError as e:
    print("getting data from terraform.py failed, here is the error: ", e)
    sys.exit(1)

# loop through IPs
hosts = dict(line.split() for line in hosts.split("\n") if line != '' and not line.startswith("#"))
tainted = []

# for each ip, try to connect
for host, name in hosts.iteritems():
    cmd = shlex.split("ssh root@%s -o NumberOfPasswordPrompts=0 -C 'echo test' 2&>1" % host)
    ssh = subprocess.Popen(cmd, stderr=subprocess.PIPE)
    _, err = ssh.communicate()

    # if error, parse stderr
    if ssh.returncode != 0 and 'permission denied' in err.lower():

        # load in tfstate directly to get module name
        with open('terraform.tfstate') as json_file:
            state = json.load(json_file)
            meta = subprocess.check_output(shlex.split('plugins/inventory/terraform.py --host {}'.format(name)))
            meta = json.loads(meta)
            for module in state['modules']:
                for key, resource in module['resources'].items():
                    if 'attributes' in resource['primary']:
                        if 'ipv4_address' in resource['primary']['attributes']:
                            if meta['ipv4_address'] == resource['primary']['attributes']['ipv4_address']:
                                tainted.append((module['path'][-1], key))

# if any hosts are tainted, reapply and exit 1
if len(tainted) == 0:
    print("no ssh permission errors found, no reapply required")
    sys.exit(0)
else:
    for name, resource in tainted:
        cmd = shlex.split("terraform taint -module={} {}".format(name, resource))
        print(cmd)
        ret_code = subprocess.call(cmd)
        if ret_code != 0:
            print("subprocess exited with nonzero")
            sys.exit(0)

    subprocess.call(shlex.split("terraform apply"))
    sys.exit(1)
