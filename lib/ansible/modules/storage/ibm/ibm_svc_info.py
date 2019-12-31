#!/usr/bin/python
# Copyright (C) 2019 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ibm_svc_info
short_description: IBM SVC information gatherer
version_added: "2.10"
description:
- Gathers the list of specified IBM SVC Storage System entities, like the
  list of nodes, pools, volumes, hosts, host clusters, fc ports, iscsi ports,
  io groups, nvme fabric, array, system etc.
author:
- Peng Wang (wangpww@cn.ibm.com)
options:
    state:
        type: str
        required: False
        description:
            - Returns "info"
        default: "info"
        choices: ['info']
    gather_subset:
        type: list
        required: False
        description:
        - List of string variables to specify the IBM SVC entities for which
          information is required.
        - List of all SVC entities supported by the module - 
        - vol - vdisks
        - pool - mdiskgrps
        - node - nodes
        - iog - io groups
        - host - hosts
        - hc - host clusters
        - fcport - fc ports
        - iscsiport - iscsi ports
        - nf - nvme fabric
        - array - array MDisks info
        - system - storage system info
        choices: [vol, pool, node, iog , host, hc, fcport, iscsiport, 
                  nf, array, system]
        default: "all"
'''

RETURN = '''
'''

import logging
from traceback import format_exc

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec
from ansible.module_utils._text import to_native


class IBMSVCGatherInfo(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', default='info', choices=['info']),
                gather_subset=dict(type='list', required=False,
                                   choices=['vol',
                                            'pool',
                                            'node',
                                            'iog',
                                            'host',
                                            'hc',
                                            'fcport',
                                            'iscsiport',
                                            'nf',
                                            'array',
                                            'system'
                                            ]),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        self.log = logging.getLogger(self.__class__.__name__)
        if log_path:
            logging.basicConfig(level=logging.DEBUG, filename=log_path)
        self.name = self.module.params['name']

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path
        )

    def get_volumes_list(self):
        try:
            vols = self.restapi.svc_obj_info(cmd='lsvdisk', cmdopts=None,
                                             cmdargs=None)
            self.log.info('Successfully listed {0} volumes from array '
                          '{1}' .format(len(vols),
                                        self.module.params['clustername']))
            return vols
        except Exception as e:
            msg = 'Get Volumes for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_pools_list(self):
        try:
            pools = self.restapi.svc_obj_info(cmd='lsmdiskgrp', cmdopts=None,
                                              cmdargs=None)
            self.log.info('Successfully listed {0} pools from array '
                          '{1}'.format(len(pools),
                                       self.module.params['clustername']))
            return pools
        except Exception as e:
            msg = 'Get Pools for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_nodes_list(self):
        try:
            nodes = self.restapi.svc_obj_info(cmd='lsnode', cmdopts=None,
                                              cmdargs=None)
            self.log.info('Successfully listed {0} nodes from array '
                          '{1}'.format(len(nodes),
                                       self.module.params['clustername']))
            return nodes
        except Exception as e:
            msg = 'Get Nodes for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_hosts_list(self):
        try:
            hosts = self.restapi.svc_obj_info(cmd='lshost', cmdopts=None,
                                              cmdargs=None)
            self.log.info('Successfully listed {0} hosts from array '
                          '{1}'.format(len(hosts),
                                       self.module.params['clustername']))
            return hosts
        except Exception as e:
            msg = 'Get Hosts for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_iogroups_list(self):
        try:
            iogrps = self.restapi.svc_obj_info(cmd='lsiogrp', cmdopts=None,
                                               cmdargs=None)
            self.log.info('Successfully listed {0} io groups from array '
                          '{1}'.format(len(iogrps),
                                       self.module.params['clustername']))
            return iogrps
        except Exception as e:
            msg = 'Get io groups for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_host_clusters_list(self):
        try:
            hcs = self.restapi.svc_obj_info(cmd='lshostcluster', cmdopts=None,
                                            cmdargs=None)
            self.log.info('Successfully listed {0} host clusters from array '
                          '{1}'.format(len(hcs),
                                       self.module.params['clustername']))
            return hcs
        except Exception as e:
            msg = 'Get host clusters for array {0} failed with error ' \
                  '{1} '.format(self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_fc_ports_list(self):
        try:
            fcports = self.restapi.svc_obj_info(cmd='lsportfc', cmdopts=None,
                                                cmdargs=None)
            self.log.info('Successfully listed {0} fc ports from array '
                          '{1}'.format(len(fcports),
                                       self.module.params['clustername']))
            return fcports
        except Exception as e:
            msg = 'Get fc ports for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_iscsi_ports_list(self):
        try:
            ipports = self.restapi.svc_obj_info(cmd='lsportip', cmdopts=None,
                                                cmdargs=None)
            self.log.info('Successfully listed {0} iscsi ports from array '
                          '{1}'.format(len(ipports),
                                       self.module.params['clustername']))
            return ipports
        except Exception as e:
            msg = 'Get ip ports for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_nvme_fabric_list(self):
        try:
            nf = self.restapi.svc_obj_info(cmd='lsnvmefabric', cmdopts=None,
                                           cmdargs=None)
            self.log.info('Successfully listed {0} nvme fabric from array '
                          '{1}'.format(len(nf),
                                       self.module.params['clustername']))
            return nf
        except Exception as e:
            msg = 'Get nvme fabric for array {0} failed with error ' \
                  '{1} '.format(self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_array_list(self):
        try:
            array = self.restapi.svc_obj_info(cmd='lsarray', cmdopts=None,
                                              cmdargs=None)
            self.log.info('Successfully listed {0} array info from array '
                          '{1}'.format(len(array),
                                       self.module.params['clustername']))
            return array
        except Exception as e:
            msg = 'Get array info for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def get_system_list(self):
        try:
            system = self.restapi.svc_obj_info(cmd='lssystem', cmdopts=None,
                                               cmdargs=None)
            self.log.info('Successfully listed {0} system info from array '
                          '{1}'.format(len(system),
                                       self.module.params['clustername']))
            return system
        except Exception as e:
            msg = 'Get array info for array {0} failed with error {1} '.format(
                self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def apply(self):

        subset = self.module.params['gather_subset']
        if len(subset) == 0 or 'all' in subset:
            self.log.info("The default value for gather_subset is all")
            subset = ['vol', 'pool', 'node', 'iog', 'host', 'hc', 'fcport',
                      'iscsiport', 'nf', 'array', 'system']

        vol = []
        pool = []
        node = []
        iog = []
        host = []
        hc = []
        fcport = []
        iscsiport = []
        nf = []
        array = []
        system = []

        if 'vol' in subset:
            vol = self.get_volumes_list()
        if 'pool' in subset:
            pool = self.get_pools_list()
        if 'node' in subset:
            node = self.get_nodes_list()
        if 'iog' in subset:
            iog = self.get_iogroups_list()
        if 'host' in subset:
            host = self.get_hosts_list()
        if 'hc' in subset:
            hc = self.get_host_clusters_list()
        if 'fcport' in subset:
            fcport = self.get_fc_ports_list()
        if 'iscsiport' in subset:
            iscsiport = self.get_iscsi_ports_list()
        if 'nf' in subset:
            nf = self.get_nvme_fabric_list()
        if 'array' in subset:
            array = self.get_array_list()
        if 'system' in subset:
            system = self.get_system_list()

        self.module.exit_json(
            Volumes=vol,
            Pools=pool,
            Nodes=node,
            IOGroup=iog,
            Hosts=host,
            HostClusters=hc,
            FCPorts=fcport,
            iSCSIPorts=iscsiport,
            NvMeFabric=nf,
            Array=array,
            System=system)


def main():
    v = IBMSVCGatherInfo()
    try:
        v.apply()
    except Exception as e:
        v.debug("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
