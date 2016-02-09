#!/usr/bin/env python
from __future__ import print_function
import json
import shlex
from subprocess import Popen, PIPE
import sys


def main():
    # get the hosts
    _, hosts, _ = call_cmd("plugins/inventory/terraform.py --hostfile")
    to_taint = []

    # loop through IPs
    hosts = dict(line.split() for line in hosts.split("\n")
                 if line != '' and not line.startswith("#"))

    # connect to the ips, looking for resources to taint
    for host, name in hosts.iteritems():
        cmd = "ssh root@{} -oBatchMode=yes -C 'echo hi'".format(host)
        returncode, _, err = call_cmd(cmd)

        if returncode != 0 and 'permission denied' in err.lower():
            to_taint = get_modules_to_taint(host, name)

    # if any hosts are tainted, reapply and exit 1
    if len(to_taint) == 0:
        print("no ssh permission errors found, no reapply required")
        sys.exit(0)
    else:
        print("ssh permission errors found, running taint & reapply")
        for name, resource in to_taint:
            cmd = "terraform taint -module={} {}".format(name, resource)
            returncode, _, _ = call_cmd(cmd)
            if returncode != 0:
                print("subprocess exited with nonzero")
                sys.exit(1)

        _, out, _ = call_cmd("terraform apply")
        print(out)
        sys.exit(1)


def call_cmd(cmd):
    print("RUNNING\t{}".format(cmd))
    cmd = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)

    out, err = cmd.communicate()

    return (cmd.returncode, out, err)


def get_modules_to_taint(host, name):
    to_taint = []
    with open('terraform.tfstate') as json_file:
        cmd = "plugins/inventory/terraform.py --host {}".format(name)
        _, meta, _ = call_cmd(cmd)

        meta = json.loads(meta)
        state = json.load(json_file)

        for module in state['modules']:
            for key, resource in module['resources'].items():
                primary = resource['primary']
                if 'attributes' in primary:
                    if 'ipv4_address' in primary['attributes']:
                        address = primary['attributes']['ipv4_address']
                        if address == meta['ipv4_address']:
                            to_taint.append((module['path'][-1], key))

    return to_taint


if __name__ == "__main__":
    main()
