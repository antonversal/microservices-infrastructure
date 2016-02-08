#!/usr/bin/env python
from __future__ import print_function
import json
import shlex
import subprocess
import sys

try:
    # get the hosts
    cmd = shlex.split("plugins/inventory/terraform.py --hostfile")
    hosts = subprocess.check_output(cmd)

    # loop through IPs
    hosts = dict(line.split() for line in hosts.split("\n")
                 if line != '' and not line.startswith("#"))
    tainted = []

    # for each ip, try to connect
    for host, name in hosts.iteritems():
        cmd = "ssh root@{} -oBatchMode=yes -C 'echo test' 2&>1".format(host)
        ssh = subprocess.Popen(shlex.split(cmd.format(host)),
                               stderr=subprocess.PIPE)
        _, err = ssh.communicate()

        # if error, parse stderr
        if ssh.returncode != 0 and 'permission denied' in err.lower():

            # load in tfstate directly to get module name
            with open('terraform.tfstate') as json_file:
                print("loaded file:", json_file)
                state = json.load(json_file)
                cmd = "plugins/inventory/terraform.py --host {}".format(name)
                meta = subprocess.check_output(shlex.split(cmd))
                meta = json.loads(meta)
                for module in state['modules']:
                    for key, resource in module['resources'].items():
                        primary = resource['primary']

                        # because
                        if 'attributes' in primary:
                            if 'ipv4_address' in primary['attributes']:
                                address = primary['attributes']['ipv4_address']
                                if address == meta['ipv4_address']:
                                    tainted.append((module['path'][-1], key))

    # if any hosts are tainted, reapply and exit 1
    if len(tainted) == 0:
        print("no ssh permission errors found, no reapply required")
        sys.exit(0)
    else:
        for name, resource in tainted:
            cmd = "terraform taint -module={} {}".format(name, resource)
            print(cmd)
            ret_code = subprocess.call(shlex.split(cmd))
            if ret_code != 0:
                print("subprocess exited with nonzero")
                sys.exit(1)

        subprocess.call(shlex.split("terraform apply"))
        sys.exit(0)
except subprocess.CalledProcessError as e:
    print("error calling subprocess:\n", e)
    sys.exit(1)
except IOError as e:
    print("error opening file:\n", e)
    sys.exit(1)
