#!/usr/local/bin/python

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
import ntplib
import datetime
import sqlite3


def validate_time(ntp_server):
    # to do: should use UTC instead of local time. On other hand,
    # this is not a big con for a manual smoke-test.

    truenas_time = datetime.datetime.now()
    c = ntplib.NTPClient()
    try:
        response = c.request(ntp_server)
    except:
        return "error querying ntp_server"

    ntp_time = datetime.datetime.fromtimestamp(response.tx_time)

    # I'm only concerned about clockskew and not who is to blame.
    if ntp_time > truenas_time:
        clockskew = ntp_time - truenas_time
    else:
        clockskew = truenas_time - ntp_time

    return clockskew

def main():
    ad_domain_controllers = []
    dns_servers = []
    kerberos_domain_controllers = []
    global_catalog_servers = []

    FREENAS_DB = '/data/freenas-v1.db'
    conn = sqlite3.connect(FREENAS_DB)
    conn.row_factory = lambda cursor, row: row[0]
    c = conn.cursor()
    c.execute('SELECT ntp_address FROM system_ntpserver')
    ntp_servers = c.fetchall()
    conn.close()

    for ntp_server in ntp_servers:
       clockskew = validate_time(ntp_server)
       print("%s clockskew is: %s" % (ntp_server,clockskew))



if __name__ == '__main__':
    main()
