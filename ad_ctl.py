#!/usr/local/bin/python

from middlewared.client import Client
from middlewared.client.utils import Struct

import os
import pwd
import re
import sys
import socket
import subprocess
import tempfile
import time
import logging
import logging.config

sys.path.extend([
    '/usr/local/www',
    '/usr/local/www/freenasUI'
])

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[%(name)s:%(lineno)s] %(message)s'
        },
    },
    'handlers': {
        'syslog': {
            'level': 'DEBUG',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'simple',
        }
    },
    'loggers': {
        '': {
            'handlers': ['syslog'],
            'level': 'DEBUG',
            'propagate': True,
        },
    }
})

from freenasUI.common.pipesubr import pipeopen
from freenasUI.common.log import log_traceback
from freenasUI.common.freenassysctl import freenas_sysctl as fs

log = logging.getLogger('ad_ctl')

def validate_hosts(client):
    hosts = open('/etc/hosts','r')
    cifs = Struct(client.call('datastore.query', 'services.cifs', None, {'get': True}))
    for line in hosts:
        if str(cifs.cifs_srv_netbiosname) in str(line):
            return True

    return False

def service_launcher(service, command):
    p = pipeopen("/usr/sbin/service %s %s" % (service, command))
    output = p.communicate()
    if p.returncode != 0:
        print("Service %s failed on command %s " % (service, command))
        return False

    return True


def main():
    client = Client()
    if not validate_hosts(client):
        print("restarting ix-hostname service")
        service_launcher("ix-hostname", "quietstart")

if __name__ == '__main__':
    main()
