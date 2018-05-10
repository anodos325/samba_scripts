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

def get_id_output(username):
    p = subprocess.Popen(["/usr/bin/id", username], stdout=subprocess.PIPE)
    output = p.communicate()
    if p.returncode !=0:
        print(output[0])
        return False

    return output

def xid_to_sid(xid_type, xid):
    if xid_type is "uid":
        p = pipeopen("/usr/local/bin/wbinfo -U %s" % xid)
    else:
        p = pipeopen("/usr/local/bin/wbinfo -G %s" % (xid))

    output = p.communicate()
    return output[0].rstrip()

############################################################################
# Retrieve a de-facto smb.conf via middleware calls. This will also set    #
# correct idmap backends for the AD domain and BUILTIN domain.             #
############################################################################

def get_samba_config_data(client):
    samba_config = []
    cifs_config = Struct(client.call('datastore.query', 'services.cifs', None, {'get': True}))
    ad_config = Struct(client.call('datastore.query', 'directoryservice.activedirectory', None, {'get': True}))
    default_idmap_config = Struct(client.call('datastore.query', 'directoryservice.idmap_tdb', None, {'get': True}))

    idmap_backend_call = "directoryservice.idmap_%s" % ad_config.ad_idmap_backend

    try:
        idmap_config = Struct(client.call('datastore.query', idmap_backend_call, None, {'get': True}))
    except:
        print("failed to get idmap data via middleware calls")
        return False

    for item in [cifs_config, ad_config, idmap_config, default_idmap_config]:
        samba_config.append(item) 

    return samba_config

############################################################################
# Retrieve domain SID for a given domain via wbinfo --domain-info.         #
# Opted not to use 'net getdomainsid                                       #
############################################################################

def get_domain_sid(domain):
    p = pipeopen("/usr/local/bin/wbinfo --domain-info=%s" % domain)

    output = p.communicate()
    split_output = output[0].splitlines()
    domain_sid = split_output[2].split(': ')
    return domain_sid[1]

############################################################################
# Generate list of three lists: user, primary group, supplementary groups. #
# Supplemntary group list contains lists containing xid data (formatted    #
# same as "user" and "primary group". Each xid data list contains three    #
# members: xid, name, sid                                                  #
############################################################################

def convert_id_to_lists(id_out):
    output_list = []
    user = []
    pri_group = []
    supp_groups = []
    
     
    split_output = id_out[0].decode('utf-8').rstrip().split(') ')

    # Generate list of data for 'User' 
    norm_uid_data = split_output[0].strip('uid=').split('(')
    uid_to_sid = xid_to_sid("uid",norm_uid_data[0]) 

    for item in [norm_uid_data[0], norm_uid_data[1], uid_to_sid]:
        user.append(item)

    output_list.append(user)

    # ditto for primary group
    norm_pri_gid_data = split_output[1].strip('gid=').split('(')
    pri_gid_to_sid = xid_to_sid("gid",norm_pri_gid_data[0]) 

    for item in [norm_pri_gid_data[0], norm_pri_gid_data[1], uid_to_sid]:
        pri_group.append(item)

    output_list.append(pri_group)

    # ditto for supplementary groups
    sup_group_list = split_output[2].strip('groups=').split('),')
    for group in sup_group_list:
        group_data = []
        norm_sup_group = group.split('(')
        sup_group_sid = xid_to_sid("gid",norm_sup_group[0])
        
        for item in [norm_sup_group[0], norm_sup_group[1], sup_group_sid]:
            group_data.append(item)

        supp_groups.append(group_data)

    output_list.append(supp_groups)
         
    return output_list

############################################################################
# Verify that each user / group in 'id' output lies within the idmap range #
# that has been set for the domain in question                             #
############################################################################

def validate_xid_ranges(samba_config, id_lists):

    if samba_config[1].ad_idmap_backend == 'autorid':
       high_range = samba_config[2].idmap_autorid_range_high
       low_range = samba_config[2].idmap_autorid_range_low
    elif samba_config[1].ad_idmap_backend == "rid":
       high_range = samba_config[2].idmap_rid_range_high
       low_range = samba_config[2].idmap_rid_range_low
    elif samba_config[1].ad_idmap_backend == "ad":
       high_range = samba_config[2].idmap_ad_range_high
       low_range = samba_config[2].idmap_ad_range_low
    else:
       print("danger will robinson")
       return False

    if samba_config[1].ad_idmap_backend != 'autorid':
        default_high_range = samba_config[3].idmap_tdb_range_high
        default_low_range = samba_config[3].idmap_tdb_range_low 

    # validate the UID #
    if not (low_range <= int(id_lists[0][0]) <= high_range):
        return False
 
    # validate the primary GID #
    if not (low_range <= int(id_lists[1][0]) <= high_range):
        return False
 
    # validate the supplementary groups
    for i in id_lists[2]:
        domain_split = i[1].split('\\')
        if (domain_split[0] == "BUILTIN" and samba_config[1].ad_idmap_backend != 'autorid'):
            if not (default_low_range <= int(i[0]) <= default_high_range):
                return False 
            else:
                continue

        if not (low_range <= int(i[0]) <= high_range):
            return False

    return True
       

def validate_domain_sids(samba_config, id_lists):
    domain_sid = get_domain_sid(samba_config[1].ad_domainname) 
    
    # validate user SID
    if domain_sid not in id_lists[0][2]:
        return False

    # validate primary group SID
    if domain_sid not in id_lists[1][2]:
        return False

    # validate supplementary groups
    for i in id_lists[2]:
        domain_split = i[1].split('\\')
        domain_sid = get_domain_sid(domain_split[0])
        if domain_sid not in i[2]:
            return False

    return True


def main():
    client = Client()
    samba_config = get_samba_config_data(client)
    if not samba_config:
        print("failed to get samba config from middleware")
        return False   
    else:
        print("Generate samba_config via middleware calls: SUCCESS")

    # By default check data on administrator account. This *should* exist in ad environment
    # optionally override by passing and argument to the script
    username = "%s\Administrator" % samba_config[1].ad_domainname

    if (len(sys.argv) > 1):
        username = sys.argv[1]
    
    id_output = get_id_output(username)

    # If we return something in stderr, exit and print error
    if not id_output:
        return False

    id_lists = convert_id_to_lists(id_output)
    if not validate_xid_ranges(samba_config, id_lists):
        print("Validate idmap ranges: FAIL")
        return False
    else:
        print("Validate idmap ranges: SUCCESS")
    
    if not validate_domain_sids(samba_config, id_lists):
        print("Validate SIDs: FAIL")
        return False
    else:
        print("Validate SIDs: SUCCESS")
    
    col_width = max(len(word) for row in id_lists[2] for word in row) + 2 # padding 
    header = ['XID', 'NAME', 'SID']
    print("Dumping ID information for user %s" % username)
    print("UID: %s     Name: %s     SID: %s" % (id_lists[0][0],id_lists[0][1],id_lists[0][2]))
    print("Primary Group")
    print("GID: %s     Name: %s     SID: %s" % (id_lists[1][0],id_lists[1][1],id_lists[1][2]))
    print("Supplementary Groups")
    for i in id_lists[2]:
        print("GID: %s     Name: %s    SID: %s" % (i[0], i[1], i[2]))

if __name__ == '__main__':
    main()
