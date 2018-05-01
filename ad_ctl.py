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

def validate_hosts(cifs_config):
    hosts = open('/etc/hosts','r')
    for line in hosts:
        if str(cifs_config.cifs_srv_netbiosname) in str(line):
            return True

    return False

def validate_klist(krb_config):
    p = pipeopen("/usr/bin/klist")
    output = p.communicate()
    print(output)

def service_launcher(service, command):
    p = pipeopen("/usr/sbin/service %s %s" % (service, command))
    output = p.communicate()
    if p.returncode != 0:
        print("Service %s failed on command %s " % (service, command))
        return False

    return True


def main():
    client = Client()
    cifs_config = Struct(client.call('datastore.query', 'services.cifs', None, {'get': True}))
    krb_config = Struct(client.call('datastore.query', 'services.cifs', None, {'get': True}))

    if not validate_hosts(cifs_config):
        print("restarting ix-hostname service")
        service_launcher("ix-hostname", "quietstart")
    
   # validate_klist("krb_config.krb_realm")

    service_launcher("ix-kerberos", "quietstart")

    service_launcher("ix-nsswitch", "quietstart")

    if not service_launcher("ix-kinit", "status"):
        if not service_launcher("ix-kinit", "quietstart"):
             print("ix-kinit failed")

    service_launcher("ix-pre-samba", "quietstart")

    service_launcher("ix-activedirectory", "quietstart")

    service_launcher("samba_server", "restart")

    service_launcher("ix-pam", "quietstart")
    service_launcher("ix-cache", "quietstart")
    
if __name__ == '__main__':
    main()
