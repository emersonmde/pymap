#!/usr/bin/env python3

import re

def read_services():
    services = []
    f = open('data/pymap-services')
    for line in f:
        line = line.strip()
        if line[0] == "#":
            continue
        line = re.sub("\t*#.*$", "", line)
        services.append(re.split("\t|/", line))
    f.close()
    print(services)
    return services
