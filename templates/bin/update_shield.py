#!/usr/bin/env python3

import requests
import ipaddress
import os
import json
import sys
import argparse
import subprocess

from jinja2 import (
    Environment,
    PackageLoader,
    select_autoescape,
    FileSystemLoader,
    TemplateNotFound,
)
from os.path import join, exists, getmtime

r2_public = "defense-shield"

parser = argparse.ArgumentParser(
    prog="IP Defense Shield", description="Allows SSH-in from preconfigured IP location"
)

parser.add_argument(
    "-b", "--base-url", dest="base", required=True
)  # option that takes a value
parser.add_argument("-v", "--verbose", action="store_true")  # on/off flag


args = parser.parse_args()

r2_base = args.base

ipv4_public = list()
ipv6_public = list()


def log_fatal_error(exception, contents):
    print(f"Fatal Error: {exception}")
    ## Log PD Error
    sys.exit(0)


def parse_public():
    global ipv4_public
    global ipv6_public
    r = requests.get("/".join([r2_base, r2_public]))
    if r.status_code != 200:
        log_fatal_error(f"HTTP {r.status_code}", r.text)
    for line in r.text.splitlines():
        try:
            if "/" in line:
                i = ipaddress.ip_network(line)
            else:
                i = ipaddress.ip_address(line)
        except ValueError as a:
            log_fatal_error(a, r.text)
        if "IPv4" in str(type(i)) and not i.is_private:
            ipv4_public.append(str(i))
        elif "IPv6" in str(type(i)) and not i.is_private:
            ipv6_public.append(str(i))
    return


# nft = nftables.Nftables()
# nft.set_json_output(True)
# rc, output, error = nft.cmd("list ruleset")
# print(json.loads(output))

parse_public()
# print(ipv6_public)

template_dir = os.path.abspath(os.path.dirname(__file__))

env = Environment(
    loader=FileSystemLoader(f"{template_dir}/../etc/"), autoescape=select_autoescape()
)
try:
    template = env.get_template("nftables.conf.j2")
    rendered = template.render(ipv6=ipv6_public, ipv4=ipv4_public)
except Exception as b:
    log_fatal_error(b, "nftables.conf.j2")

# print(rendered)
try:
    p = subprocess.run(["nft", "-c", "-f", "-"], input=rendered, encoding="utf8")
except Exception as b:
    log_fatal_error(b, rendered)

if p.returncode != 0:
    log_fatal_error(f"NFT bad return code {p.returncode}", rendered)
### now for real
try:
    p = subprocess.run(["nft", "-f", "-"], input=rendered, encoding="utf8")
except Exception as b:
    log_fatal_error(b, rendered)
