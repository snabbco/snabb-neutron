# Copyright (c) 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
# @author: Nikolay Nikolaev
# @author: Luke Gorrie

import collections

from netaddr.ip import IPNetwork
from netaddr import IPAddress
from neutron.extensions import portbindings
from neutron.plugins.common import constants
from neutron.plugins.ml2 import config as config
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mechanism_snabb
from neutron.tests.unit import test_db_plugin as test_plugin

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class SnabbTestCase(test_plugin.NeutronDbPluginV2TestCase):

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     ['logger', 'snabb'],
                                     'ml2')
        super(SnabbTestCase, self).setUp(PLUGIN_NAME)
        self.port_create_status = 'DOWN'
        self.segment = {'api.NETWORK_TYPE': ""}
        self.mech = mechanism_snabb.SnabbMechanismDriver()
        self.mech.vif_type = portbindings.VIF_TYPE_VHOSTUSER
        self.mech.allocated_bandwidth = None
        self.mech.props = FakeSnabbMechanismDriverProps()

    def test_check_segment(self):
        """Validate the check_segment call."""
        self.segment[api.NETWORK_TYPE] = constants.TYPE_LOCAL
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_FLAT
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VLAN
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_GRE
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = constants.TYPE_VXLAN
        self.assertFalse(self.mech.check_segment(self.segment))
        self.segment[api.NETWORK_TYPE] = 'zone'
        self.assertTrue(self.mech.check_segment(self.segment))
        # Validate a network type not currently supported
        self.segment[api.NETWORK_TYPE] = 'mpls'
        self.assertFalse(self.mech.check_segment(self.segment))


class SnabbMechanismTestZoneChoosePort(SnabbTestCase):

    def test_choose_port_any(self):
        """Pick any port when they are all equally good."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('201::/64'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertIsNotNone(port, 'port0')

    def test_choose_port_loaded(self):
        """Pick the most loaded port that has capacity available."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('201::/64'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {('host1', 'port0'): {'p1': 0},
                                         ('host1', 'port1'): {'p2': 1},
                                         ('host1', 'port2'): {'p3': 0}}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertEqual(port, 'port1')

    def test_choose_port_not_overloaded(self):
        """Don't pick the port that will be overloaded."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('201::/64'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {('host1', 'port0'): {'p1': 1},
                                         ('host1', 'port1'): {'p2': 6},
                                         ('host1', 'port1'): {'p2': 0}}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertNotEqual(port, 'port1')

    def test_choose_least_overloaded_ipv6(self):
        """Pick the least-overloaded port."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('201::/64'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {('host1', 'port0'): {'p1': 99},
                                         ('host1', 'port1'): {'p2': 42},
                                         ('host1', 'port2'): {'p3': 76}}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertEqual(port, 'port1')

    def test_choose_least_overloaded_ipv4(self):
        """Pick the least-overloaded port when there is IPv4."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('192.168.201.0/24'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {('host1', 'port0'): {'p1': 99},
                                         ('host1', 'port1'): {'p2': 42},
                                         ('host1', 'port2'): {'p3': 76}}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertEqual(port, 'port2')

    def test_choose_least_overloaded_ipv4_2(self):
        """Pick the least-overloaded port when there is IPv4 zone."""
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('102::/64'),
                        101,
                        []),
                    'zone2': (
                        IPNetwork('192.168.201.0/24'),
                        201,
                        [])},
                'port2': {
                    'zone1': (
                        IPNetwork('301::/64'),
                        301,
                        [])}}}
        self.mech.allocated_bandwidth = {('host1', 'port0'): {'p1': 1},
                                         ('host1', 'port1'): {'p2': 0},
                                         ('host1', 'port2'): {'p3': 2}}
        port = self.mech._choose_port('host1', 'zone1', 6, 5)
        self.assertEqual(port, 'port2')


class SnabbMechanismTestBasicGet(test_plugin.TestBasicGet, SnabbTestCase):
    pass


class SnabbMechanismTestNetworksV2(test_plugin.TestNetworksV2, SnabbTestCase):
    pass


class SnabbMechanismTestPortsV2(test_plugin.TestPortsV2, SnabbTestCase):
    pass


class FakePlugin(object):

    """To generate plug for testing purposes only."""

    def __init__(self, ports):
        self._ports = ports

    def get_ports(self, dbcontext):
        return self._ports


class FakeNetworkContext(object):

    """To generate network context for testing purposes only."""

    def __init__(self, network, segments=None, original_network=None):
        self._network = network
        self._original_network = original_network
        self._segments = segments

    @property
    def current(self):
        return self._network

    @property
    def original(self):
        return self._original_network

    @property
    def network_segments(self):
        return self._segments


class FakePortContext(object):

    """To generate port context for testing purposes only."""

    def __init__(self, ports, host):
        self._plugin = FakePlugin(ports)
        self._plugin_context = None

        network = {'id': 'network_id'}
        network_segments = [{'id': 'zone_id',
                             'network_type': 'zone'}]
        self._network_context = FakeNetworkContext(
            network,
            network_segments,
            network)
        self._original_port = {portbindings.PROFILE: {},
                               portbindings.VIF_DETAILS: {}}
        self._port = {portbindings.VIF_TYPE: portbindings.VIF_TYPE_VHOSTUSER,
                      'binding:host_id': host,
                      portbindings.PROFILE: {},
                      portbindings.VIF_DETAILS: {},
                      'fixed_ips': [{'subnet_id': 'subnet_id'}],
                      'tenant_id': 'tenant_id'}
        pass

    @property
    def current(self):
        return self._port

    @property
    def original(self):
        return self._original_port

    @property
    def network(self):
        return self._network_context

    def set_id_zone_gbps_ip(self, id, zone, gbps, ip):
        self._network_context._segments[0]['segmentation_id'] = zone
        self._original_port[portbindings.VIF_DETAILS]['zone_gbps'] = gbps
        self._port['fixed_ips'][0]['ip_address'] = ip
        self._port['id'] = id
        self._port[portbindings.VIF_DETAILS]['zone_ip'] = IPAddress(ip)
        self._original_port[portbindings.VIF_DETAILS].pop('zone_ip', None)

    def set_binding(self, segment_id, vif_type, vif_details, status):
        self._plugin._ports.append(
            {'id': self._port['id'],
             portbindings.VIF_DETAILS: dict.copy(vif_details)})
        self._original_port[portbindings.VIF_DETAILS] = vif_details

    def last_bound(self):
        return self._plugin._ports[len(self._plugin._ports) - 1]


class FakeSnabbMechanismDriverProps(object):

    def __init__(self):
        self._tenants = collections.defaultdict(set)

    def remember_ip(self, tenant_id, subnet, ip):
        self._tenants[tenant_id].add(ip)

    def remove_ip(self, tenant_id, ip):
        self._tenants[tenant_id].discard(ip)

    def get_free_ip(self, tenant_id, subnet):
        for ip in subnet.iter_hosts():
            if ip not in self._tenants[tenant_id]:
                return ip


class SnabbMechanismTestZoneBind(SnabbTestCase):

    def test_bind_port_ipv6(self):
        """Bind ports."""
        context = FakePortContext([], 'host1')
        self.mech.networks = {'host1': {
            'port0': {
                'zone1': (IPNetwork('101::/64'), 101, []),
                'zone63': (IPNetwork('163::/64'), 163, [])},
            'port1': {
                'zone1': (IPNetwork('201::/64'), 201, [IPAddress("201::1")]),
                'zone63': (IPNetwork('263::/64'), 263, [])}
        }}

        # bind 10Gbps port
        context.set_id_zone_gbps_ip('port_id_0', 'zone1', 9, '0::10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('101::1'))

        # bind 2.5Gbps port in same zone
        context.set_id_zone_gbps_ip('port_id_1', 'zone1', 2.5, '0::10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('201::2'))

        # bind 2.5Gbps port in different zone
        context.set_id_zone_gbps_ip('port_id_2', 'zone63', 2.5, '0::10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('263::1'))

    def test_bind_port_ipv4(self):
        """Bind ports."""
        context = FakePortContext([], 'host1')
        self.mech.networks = {
            'host1': {
                'port0': {
                    'zone1': (
                        IPNetwork('101::/64'),
                        101,
                        []),
                    'zone63': (
                        IPNetwork('163::/64'),
                        163,
                        []),
                    'zone65': (
                        IPNetwork('165::/64'),
                        165,
                        [])},
                'port1': {
                    'zone1': (
                        IPNetwork('201::/64'),
                        201,
                        []),
                    'zone63': (
                        IPNetwork('263::/64'),
                        263,
                        []),
                    'zone65': (
                        IPNetwork('192.168.111.0/24'),
                        265,
                        [
                            IPAddress("192.168.111.1"),
                            IPAddress("192.168.111.3")])}}}

        # bind 1Gbps IPv4 port
        context.set_id_zone_gbps_ip('port_id_0', 'zone65', 1, '0.0.0.10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('192.168.111.2'))

        context.set_id_zone_gbps_ip('port_id_1', 'zone65', 1, '0.0.0.10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('192.168.111.4'))

        context.set_id_zone_gbps_ip('port_id_0', 'zone65', 1, '192.168.111.2')
        self.mech.delete_port_postcommit(context)

        context.set_id_zone_gbps_ip('port_id_2', 'zone65', 1, '0.0.0.10')
        self.mech.bind_port(context)
        self.assertEqual(
            context.last_bound()[
                portbindings.VIF_DETAILS]['zone_ip'],
            IPAddress('192.168.111.2'))


class SnabbMechanismTestZoneValidatePortBind(SnabbTestCase):

    def test_validate_port_binding(self):
        port = {
            portbindings.PROFILE: {
                'tx_police_gbps': 'false'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'tx_police_gbps')

        port = {
            portbindings.PROFILE: {
                'rx_police_gbps': 'false'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'rx_police_gbps')

        port = {
            portbindings.PROFILE: {
                'l2tpv3_remote_ip': 'false'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'l2tpv3_remote_ip')

        port = {
            portbindings.PROFILE: {
                'l2tpv3_next_hop': 'false'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'l2tpv3_next_hop')

        port = {
            portbindings.PROFILE: {
                'l2tpv3_local_cookie': '12345678901234567890'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'l2tpv3_local_cookie')

        port = {
            portbindings.PROFILE: {
                'l2tpv3_remote_cookie': '12345678901234567890'},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'l2tpv3_remote_cookie')

        port = {
            portbindings.PROFILE: {
                'l2tpv3_session': (
                    0xffffffff +
                    1)},
            portbindings.VIF_DETAILS: {}}
        result = self.mech._validate_port_binding(port)
        self.assertEqual(result, 'l2tpv3_session')
