import argparse
import datetime
import enum
import json
import ldap
import ldap.sasl
import ntplib
import os
import sys
import ssl

import pwd
import socket
import subprocess

from dns import resolver
from middlewared.client import Client
from multiprocessing import Pool, TimeoutError


class SRV(enum.Enum):
    DOMAINCONTROLLER = '_ldap._tcp.dc._msdcs.'
    FORESTGLOBALCATALOG = '_ldap._tcp.gc._msdcs.'
    GLOBALCATALOG = '_gc._tcp.'
    KERBEROS = '_kerberos._tcp.'
    KERBEROSDOMAINCONTROLLER = '_kerberos._tcp.dc._msdcs.'
    KPASSWD = '_kpasswd._tcp.'
    LDAP = '_ldap._tcp.'
    PDC = '_ldap._tcp.pdc._msdcs.'
            

class SSL(enum.Enum):
    NOSSL = 'OFF'
    USESSL = 'ON'
    USESTARTTLS = 'START_TLS'


class ActiveDirectory_DNS(object):
    def __init__(self, **kwargs):
        super(ActiveDirectory_DNS, self).__init__()
        self.ad = kwargs.get('conf')
        return

    def _get_SRV_records(self, host, dns_timeout):
        """
        Set resolver timeout to 1/3 of the lifetime. The timeout defines
        how long to wait before moving on to the next nameserver in resolv.conf
        """
        srv_records = []
        
        if not host:
            return srv_records

        r = resolver.Resolver()
        r.lifetime = dns_timeout
        r.timeout = r.lifetime / 3
        
        try:

            answers = r.query(host, 'SRV')
            srv_records = sorted(
                answers,
                key=lambda a: (int(a.priority), int(a.weight))
            )

        except Exception:
            srv_records = []

        return srv_records

    def port_is_listening(self, host, port, timeout=1):
        ret = False

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout:
            s.settimeout(timeout)

        try:
            s.connect((host, port))
            ret = True

        except Exception as e:
            raise CallError(e)

        finally:
            s.close()

        return ret

    def _get_servers(self, srv_prefix):
        """
        We will first try fo find servers based on our AD site. If we don't find
        a server in our site, then we populate list for whole domain. Ticket #27584
        Domain Controllers, Forest Global Catalog Servers, and Kerberos Domain Controllers
        need the site information placed before the 'msdcs' component of the host entry.t
        """
        servers = []
        if not self.ad['domainname']:
            return servers

        if self.ad['site'] and self.ad['site'] != 'Default-First-Site-Name':
            if 'msdcs' in srv_prefix.value:
                parts = srv_prefix.value.split('.')
                srv = '.'.join([parts[0], parts[1]])
                msdcs = '.'.join([parts[2], parts[3]])
                host = f"{srv}.{self.ad['site']}._sites.{msdcs}.{self.ad['domainname']}"
            else:
                host = f"{srv_prefix.value}{self.ad['site']}._sites.{self.ad['domainname']}"
        else:
            host = f"{srv_prefix.value}{self.ad['domainname']}"

        servers = self._get_SRV_records(host, self.ad['dns_timeout'])

        if not servers and self.ad['site']:
            host = f"{srv_prefix.value}{self.ad['domainname']}"
            servers = self._get_SRV_records(host, self.ad['dns_timeout'])

        if SSL(self.ad['ssl'].upper()) == SSL.USESSL:
            for server in servers:
                if server.port == 389:
                    server.port = 636

        return {'srv': str(srv_prefix.name), 'servers': servers}

    def get_n_working_servers(self, srv=SRV['DOMAINCONTROLLER'], number=1):
        """
        :get_n_working_servers: often only a few working servers are needed and not the whole
        list available on the domain. This takes the SRV record type and number of servers to get
        as arguments.
        """
        res = self._get_servers(srv)
        found_servers = []
        for server in res['servers']:
            if len(found_servers) == number:
                break

            host = server.target.to_text(True)
            port = int(server.port)
            if self.port_is_listening(host, port, timeout=1):
                server_info = {'host': host, 'port': port}
                found_servers.append(server_info)

        return {
            'type': srv.name.lower(),
            'server_list': found_servers,
            'status': 'PASS' if found_servers else 'FAIL'
        }

def parse_args():
    global args

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-j', '--json',
        help='output results in JSON format',
        action='store_true')
    parser.add_argument(
        '-t', '--time',
        help='check clockskew from PDC emulator.',
        action='store_true')
    parser.add_argument(
        '-o', '--online',
        help='verfiy AD components are reachable.',
        action='store_true')
    parser.add_argument(
        '-d', '--dump',
        help='list all connectable servers in the domain.',
        action='store_true')
    parser.add_argument(
        '-r', '--records',
        help='output SRV records for domain.',
        action='store_true')
    parser.add_argument(
        '-s', '--ssl',
        help='check whether LDAPs is used in the domain.',
        action='store_true')
    args = parser.parse_args(sys.argv[1:])

def check_clockskew(ad):
    pdc = ActiveDirectory_DNS(conf=ad).get_n_working_servers(SRV.PDC, 1)
    if not pdc:
        return {'pdc': '<unknown>', 'timestamp': '<unknown>', 'clockskew': '<unknown>', 'status': 'FAULTED'}

    permitted_clockskew = datetime.timedelta(minutes=3) 
    nas_time = datetime.datetime.now()
    c = ntplib.NTPClient()
    response = c.request(pdc['server_list'][0]['host'])
    ntp_time = datetime.datetime.fromtimestamp(response.tx_time)
    clockskew = abs(ntp_time - nas_time)
    return {
        'pdc': str(pdc['server_list'][0]['host']),
        'timestamp': str(ntp_time),
        'clockskew': str(clockskew),
        'status': 'PASS' if clockskew < permitted_clockskew else 'FAIL'
    }

def check_servers_exist(ad, pool, number=1):
    """
    give 60 second timeout on checking if server is up
    """
    server_data = {}
    results = [pool.apply_async( ActiveDirectory_DNS(conf=ad).get_n_working_servers, (s, number)) for s in SRV]
    for res in results:
        try:
            entry = res.get(timeout=60)
            server_data[entry['type']] = {
                'server_list': entry['server_list'],
                'status':  entry['status']
            }
        except TimeoutError:
            pass

    for s in SRV:
        if not server_data.get(s.name.lower()):
            server_data[s] = ['<unknown>']
    return server_data

def get_srv_records(ad, pool):
    srv_records = {} 
    results = [pool.apply_async( ActiveDirectory_DNS(conf=ad)._get_servers, (s,)) for s in SRV]
    for res in results:
        try:
            ret = res.get(timeout=60)
            srv = ret.get('srv').lower()
            srv_records[srv] = []
            for server in ret['servers']:
                srv_records[srv].append(
                   {'host': server.target.to_text(True), 'port': int(server.port)}
                )
           
        except TimeoutError:
            pass
    return srv_records 

def check_supports_ssl(ad):
    """
    This may fail with ECONNRESET or something different depending on firewall rules.
    For now just assume an exception means failure.
    """
    ldap = ActiveDirectory_DNS(conf=ad).get_n_working_servers(SRV.LDAP, 1)
    try:
        server_cert = ssl.get_server_certificate((ldap['server_list'][0]['host'], 636))
        ret =  {
            'server': str(ldap['server_list'][0]['host']),
            'cert': str(server_cert),
            'status': 'PASS' if server_cert else 'FAIL'
        }
    except Exception:
        ret = {
            'server': str(ldap['server_list'][0]['host']),
            'cert': '',
            'status': 'FAIL'
        } 

    return ret

def outputtotext(output):
    for k,v in output.items():
        print(f'\n{k}')
        print('-------------------------')
        if k == 'ssl':
            print(f'{v["server"]} -- {v["status"]}')
        elif k in ['server_data', 'connectable_servers']:
            for s, srvdata in v.items():
               print(f'-{s.upper()}-')
               for i in srvdata['server_list']:
                   print(f'{v[s]["status"]} -- {i["host"]}:{i["port"]}') 
        else:
            print(v)
    
def main():
    parse_args()
    permitted_clockskew = datetime.timedelta(minutes=3) 
    ad = Client().call(
        'datastore.query',
        'directoryservice.activedirectory',
        [],
        {'get': True, 'prefix': 'ad_'}
    )
    output = {} 
    with Pool(processes=8) as pool:
        if args.online:
           output['server_data'] = check_servers_exist(ad, pool)
        if args.dump:
           output['connectable_servers'] = check_servers_exist(ad, pool, -1)
        if args.records:
           output['srv_records'] = get_srv_records(ad, pool)

    if args.time:
        output['time'] = check_clockskew(ad)

    if args.ssl:
        output['ssl'] = check_supports_ssl(ad)

    if args.json:
        print(json.dumps(output, sort_keys=True, indent=2))
    else:
        outputtotext(output)

if __name__ == '__main__':
    main()
