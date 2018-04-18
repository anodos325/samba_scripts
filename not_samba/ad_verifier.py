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
import dns.resolver

def get_domain_controllers(ad_domain):
    ad_domain_controllers = []
    answers = dns.resolver.query('_ldap._tcp.dc._msdcs.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       ad_domain_controllers.append(formatted_rdata)

    return ad_domain_controllers

def get_kerberos_servers(ad_domain):
    kerberos_servers = []
    answers = dns.resolver.query('_kerberos._tcp.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       kerberos_servers.append(formatted_rdata)

    return kerberos_servers

def get_name_servers(ad_domain):
    name_servers = []
    answers = dns.resolver.query(ad_domain, 'NS')
    for rdata in answers:
       formatted_rdata= str(rdata)
       name_servers.append(formatted_rdata)

    return name_servers 
    
def get_kerberos_domain_controllers(ad_domain):
    kerberos_domain_controllers = []
    answers = dns.resolver.query('_kerberos._tcp.dc._msdcs.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       kerberos_domain_controllers.append(formatted_rdata)

    return kerberos_domain_controllers

def get_kpasswd_servers(ad_domain):
    kpasswd_servers = []
    answers = dns.resolver.query('_kpasswd._tcp.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       kpasswd_servers.append(formatted_rdata)

    return kpasswd_servers

def get_global_catalog_servers(ad_domain):
    global_catalog_servers = []
    answers = dns.resolver.query('_gc._tcp.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       global_catalog_servers.append(formatted_rdata)

    return global_catalog_servers

def get_ldap_servers(ad_domain):
    ldap_servers = []
    answers = dns.resolver.query('_ldap._tcp.' + ad_domain, 'SRV')
    for rdata in answers:
       formatted_rdata= str(rdata).split()[3]
       ldap_servers.append(formatted_rdata)

    return ldap_servers

def service_is_listening(host, port):
    ret = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        ret = True

    except Exception as e:
        errors.append(e)
        ret = False

    s.close()
    return ret

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

    #####################################
    # Grab information from Config File #
    #####################################
    FREENAS_DB = '/data/freenas-v1.db'
    conn = sqlite3.connect(FREENAS_DB)
    conn.row_factory = lambda cursor, row: row[0]
    c = conn.cursor()

    # Get NTP Servers
    c.execute('SELECT ntp_address FROM system_ntpserver')
    config_ntp_servers = c.fetchall()

    # Get AD domain name
    c.execute('SELECT ad_domainname FROM directoryservice_activedirectory')
    ad_domainname = c.fetchone()

    # Get Global Configuration Domain Network
    c.execute('SELECT gc_domain FROM network_globalconfiguration')
    gc_domain = c.fetchone()

    # Get config DNS servers
    c.execute('SELECT gc_nameserver1 FROM network_globalconfiguration')
    config_nameserver1 = c.fetchone()
    c.execute('SELECT gc_nameserver2 FROM network_globalconfiguration')
    config_nameserver2 = c.fetchone()
    c.execute('SELECT gc_nameserver3 FROM network_globalconfiguration')
    config_nameserver3 = c.fetchone()
    conn.close()

    #####################################
    # DNS query all the things          #
    #####################################
    ad_domain_controllers = get_domain_controllers(ad_domainname)
    kerberos_domain_controllers = get_kerberos_domain_controllers(ad_domainname)
    name_servers = get_name_servers(ad_domainname)
    ldap_servers = get_ldap_servers(ad_domainname)
    kpasswd_servers = get_kpasswd_servers(ad_domainname)
    global_catalog_servers = get_global_catalog_servers(ad_domainname)
    kerberos_servers = get_kerberos_servers(ad_domainname)

    #############################
    # CONFIG SANITY CHECKS      #
    #############################

    # See if domain name is set inconsistently
    if ad_domainname != gc_domain:
        print("WARNING: AD domain name %s does not match global configuration domain %s" % (ad_domainname, gc_domain))

    # See if we've set name servers that aren't for our domain
    name_server_ips = []
    for name_server in name_servers:
       name_server_ips.append(socket.gethostbyname(name_server))

    if (config_nameserver1) and (config_nameserver1 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver1,ad_domainname))

    if (config_nameserver2) and (config_nameserver2 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver2,ad_domainname))

    if (config_nameserver3) and (config_nameserver3 not in name_server_ips):
       print("WARNING: name server %s is not a name server for AD domain %s" % (config_nameserver3,ad_domainname))


    #############################
    #  NTP CHECKS               #
    #############################

    ## Compare clockskew between system time and config ntp server time ##
    config_permitted_clockskew = datetime.timedelta(minutes=1)
    print("DEBUG: determining clock skew between system and configured NTP servers")
    for ntp_server in config_ntp_servers:
       config_clockskew = validate_time(ntp_server)
       print("CONFIG_NTP_SERVERS: %s clockskew is: %s" % (ntp_server,config_clockskew))
       try: 
           if config_clockskew > config_permitted_clockskew:
               print("   WARNING: clockskew between configured NTP server and system time is greater than 1 minute")
       except:
           pass

    ## Compare clock skew between system time and DC time ##
    ad_permitted_clockskew = datetime.timedelta(minutes=1)
    for ad_domain_controller in ad_domain_controllers:
       ad_clockskew = validate_time(ad_domain_controller)
       print("AD_NTP_SERVERS: %s clockskew is: %s" % (ad_domain_controller,ad_clockskew))
       try: 
           if ad_clockskew > ad_permitted_clockskew:
               print("   WARNING: clock skew between AD DC and system time is greater than 1 minute")
       except:
           pass

    #############################
    # DNS  CHECKS               #
    #############################

    # Verify that we can open sockets to the various AD components
    for name_server in name_servers:
       if service_is_listening(name_server, 53):
          print("DEBUG: open socket to name server %s reports - SUCCESS" % (name_server))
       else:
          print("DEBUG: open socket to name server %s reports - FAIL" % (name_server))

    for domain_controller in ad_domain_controllers:
       if service_is_listening(domain_controller, 389):
          print("DEBUG: open socket to AD/DC %s reports - SUCCESS" % (domain_controller))
       else:
          print("DEBUG: open socket to AD/DC %s reports - FAIL" % (domain_controller))

    for server in ldap_servers:
       if service_is_listening(server, 389):
          print("DEBUG: open socket to LDAP Server %s reports - SUCCESS" % (server))
       else:
          print("DEBUG: open socket to LDAP Server %s reports - FAIL" % (server))

    for server in kerberos_servers:
       if service_is_listening(server, 88):
          print("DEBUG: open socket to Kerberos Server %s reports - SUCCESS" % (server))
       else:
          print("DEBUG: open socket to Kerberos Server %s reports - FAIL" % (server))

    for server in kerberos_domain_controllers:
       if service_is_listening(server, 88):
          print("DEBUG: open socket to KDC %s reports - SUCCESS" % (server))
       else:
          print("DEBUG: open socket to KDC %s reports - FAIL" % (server))

    for server in global_catalog_servers:
       if service_is_listening(server, 3269):
          print("DEBUG: open socket to Global Catalog Server %s reports - SUCCESS" % (server))
       else:
          print("DEBUG: open socket to Global Catalog Server %s reports - FAIL" % (server))

if __name__ == '__main__':
    main()
