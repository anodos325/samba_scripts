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

    return output

def xid_to_sid(xid_type, xid):
    if xid_type is "uid":
        p = pipeopen("/usr/local/bin/wbinfo -U %s" % xid)
    else:
        p = pipeopen("/usr/local/bin/wbinfo -G %s" % (xid))

    output = p.communicate()
    return output[0].rstrip()

def get_samba_config_data(client):
    samba_config = []
    cifs_config = Struct(client.call('datastore.query', 'services.cifs', None, {'get': True}))
    ad_config = Struct(client.call('datastore.query', 'directoryservice.activedirectory', None, {'get': True}))
    
    if ad_config.ad_idmap_backend == "rid":
        idmap_config = Struct(client.call('datastore.query', 'directoryservice.idmap_rid', None, {'get': True}))
    elif str(ad_config.ad_idmap_backend) == 'autorid':
        idmap_config = Struct(client.call('datastore.query', 'directoryservice.idmap_autorid', None, {'get': True}))
    elif ad_config.ad_idmap_backend == "ad":
        idmap_config = Struct(client.call('datastore.query', 'directoryservice.idmap_ad', None, {'get': True}))
    else:
        print("Error: idmap backend is set to %s" % ad_config.ad_idmap_backend)
        return False

    samba_config.append(cifs_config)
    samba_config.append(ad_config)
    samba_config.append(idmap_config)

    return samba_config

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
    user.append(norm_uid_data[0])
    user.append(norm_uid_data[1])
    user.append(uid_to_sid)
    output_list.append(user)

    # ditto for primary group
    norm_pri_gid_data = split_output[1].strip('gid=').split('(')
    pri_gid_to_sid = xid_to_sid("gid",norm_pri_gid_data[0]) 
    pri_group.append(norm_pri_gid_data[0])
    pri_group.append(norm_pri_gid_data[1])
    pri_group.append(uid_to_sid)
    output_list.append(pri_group)

    # ditto for supplementary groups
    sup_group_list = split_output[2].strip('groups=').split('),')
    for group in sup_group_list:
        group_data = []
        norm_sup_group = group.split('(')
        sup_group_sid = xid_to_sid("gid",norm_sup_group[0])
        group_data.append(norm_sup_group[0])
        group_data.append(norm_sup_group[1])
        group_data.append(sup_group_sid)
        supp_groups.append(group_data)

    output_list.append(supp_groups)
         
    return output_list

def validate_xid_ranges(samba_config, id_lists):
    if samba_config[1].ad_idmap_backend == 'autorid':
       high_range = samba_config[2].idmap_autorid_range_high
       low_range = samba_config[2].idmap_autorid_range_low
    elif samba_config[1].ad_idmap_backend == "rid":
       high_range = samba_config[2].idmap_rid_range_high
       low_range = samba_config[2].idmap_rid_range_low
    else:
       print("danger will robinson")
       return False

    return True
       

def main():
    client = Client()
    samba_config = get_samba_config_data(client)
    if not samba_config:
        print("failed to get samba config from middleware")
        return False   

    # By default check data on administrator account. This *should* exist in ad environment
    # optionally override by passing and argument to the script
    username = "%s\Administrator" % samba_config[1].ad_domainname
    id_output = get_id_output(username)

    # If we return something in stderr, exit and print error
    if id_output[1]:
        print(id_output)
        return False

    id_lists = convert_id_to_lists(id_output)
    validate_xid_ranges(samba_config, id_lists)
    
    print(id_lists)


if __name__ == '__main__':
    main()
