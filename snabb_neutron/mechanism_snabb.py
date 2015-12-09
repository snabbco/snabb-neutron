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
# @author: Rahul Mohan Rekha
# @author: Luke Gorrie
# @author: Nikolay Nikolaev

import logging
import netaddr
import neutron.db.api as db
import neutron.db.model_base as model_base
import neutron.db.models_v2 as models_v2
import sqlalchemy as sa

from oslo_serialization import jsonutils
from neutron.common import constants as n_const
from neutron.common import exceptions as exc
from neutron.extensions import portbindings
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import driver_api as api

from netaddr.ip import IPAddress
from oslo_config import cfg

LOG = logging.getLogger(__name__)

snabb_opts = [
    cfg.StrOpt('zone_definition_file',
               default='',
               help=_("File containing <host>|<port>|<zone>|<vlan>|<subnet> "
                      "tuples defining all physical ports used for zones."))
]

cfg.CONF.register_opts(snabb_opts, "ml2_snabb")

# Assume 10G network ports.
PORT_GBPS = 10

# Default bandwidth reservation (Gbps) when not specified.
DEFAULT_GBPS_ALLOCATION = 1.0


class SnabbMechanismDriverProps(model_base.BASEV2, models_v2.HasTenant):

    """Internal representation of allocated IP addresses from snabb.
    """
    __tablename__ = 'snabb_mechanism_props'
    subnet = sa.Column(sa.String(64), nullable=False, primary_key=False)
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)

    def remember_ip(self, tenant_id, subnet, ip):
        """Stores all relevant information about a VM in repository."""

        session = db.get_session()
        with session.begin():
            model = SnabbMechanismDriverProps
            props = session.query(model).filter(model.tenant_id == tenant_id,
                                                model.subnet == subnet,
                                                model.ip_address == ip).first()
            if props is None:
                props = SnabbMechanismDriverProps(tenant_id=tenant_id,
                                                  subnet=subnet,
                                                  ip_address=ip)
                session.add(props)

    def remove_ip(self, tenant_id, ip):
        """Remove all relevant information about a VM in repository."""

        session = db.get_session()
        with session.begin():
            model = SnabbMechanismDriverProps
            props = session.query(model).filter(model.tenant_id == tenant_id,
                                                model.ip_address == ip).first()
            if props:
                session.delete(props)

    def get_free_ip(self, tenant_id, subnet):
        """Returns the IP address for the tenant
        """
        session = db.get_session()
        result = None

        # enumerate all hosts in the subnet and check if already used
        for ip in subnet.iter_hosts():
            props = None
            with session.begin():
                model = SnabbMechanismDriverProps
                props = session.query(model).filter(
                    model.tenant_id == tenant_id,
                    model.subnet == subnet,
                    model.ip_address == ip).first()
            if props is None:
                result = ip
                break

        return result


class SnabbMechanismDriver(api.MechanismDriver):

    """Mechanism Driver for Snabb NFV.

    This driver implements bind_port to assign provider VLAN networks
    to Snabb NFV. Snabb NFV is a separate networking
    implementation that forwards packets to virtual machines using its
    own vswitch (Snabb Switch) on compute nodes.
    """

    def initialize(self):
        self.vif_type = portbindings.VIF_TYPE_VHOSTUSER
        # Dictionary of {host_id: {port_id: {zone: (subnet, vlan)}}}
        #
        # Use cases:
        #   Given a host_id, find all physical ports.
        #   Given a host_id and port_id, find all valid zone networks.
        #   Given a host_id and port_id and zone, find the subnet and vlan.
        self.networks = self._load_zones()
        # Dictionary of {(host_id, port_name): gbps_currently_allocated}
        self.allocated_bandwidth = None

        self.props = SnabbMechanismDriverProps()

    def _load_zones(self):
        zonefile = cfg.CONF.ml2_snabb.zone_definition_file
        networks = {}
        if zonefile != '':
            zonelines = jsonutils.load(open(zonefile))
            for entry in zonelines:
                host, port, zone, vlan, subnet = entry["host"], entry[
                    "port"], entry["zone"], entry["vlan"], entry["subnet"]
                used = []
                for u in entry["used"]:
                    used.append(IPAddress(u))
                host = host.strip()
                port = port.strip()
                zone = int(zone)
                vlan = int(vlan)
                subnet = netaddr.IPNetwork(subnet)
                networks.setdefault(host, {})
                networks[host].setdefault(port, {})
                networks[host][port][zone] = (subnet, vlan, used)
                LOG.debug("Loaded zone host:%s port:%s "
                          "zone:%s subnet:%s vlan:%s",
                          host, port, zone, subnet, vlan)

        return networks

    def _filter_ports(self, avail_ports, zone, ip_version):
        """Filter the availabale ports, matching zone and ip version."""
        # zone_ports -   filtered ports that contain
        #                the requested zone and requested ip version subnet
        # ipv_ports  -   filtered ports that contain
        #                the requested zone and reuested ip version,
        #                but not if there are is othe IP subnet
        ipv_ports, zone_ports = {}, {}

        for port_id, zones in avail_ports.items():
            for name, value in zones.items():
                if name == zone and value[0].version == ip_version:
                    zone_ports[port_id] = zones
                    break

        for port_id, zones in zone_ports.items():
            add_port = True
            for name, value in zones.items():
                if value[0].version != ip_version:
                    add_port = False
                    break
            if add_port:
                ipv_ports[port_id] = zones

        return ipv_ports, zone_ports

    def _choose_port(self, host_id, zone, ip_version, gbps):
        """Choose the most suitable port for a new bandwidth allocation."""
        LOG.debug("Choosing port for %s gbps on host %s",
                  gbps, host_id)
        # Port that best fits, and how many gbps it has available.
        avail_ports = self.networks[host_id]
        ports, ports_for_overload = self._filter_ports(
            avail_ports, zone, ip_version)
        port = self._select_port_with_bandwidth(gbps, ports, host_id)
        if port is None:
            LOG.info("No port has bandwidth available. "
                     "Choosing least-overloaded.")
            port = self._select_port_least_overloaded(
                ports_for_overload,
                host_id)
        LOG.info("Selected port %s.", port)
        return port

    def _select_port_with_bandwidth(self, gbps, ports, host_id):
        """Return a port with sufficient bandwidth, or None."""
        best_fit, best_fit_avail = None, None
        for port_id, _ in ports.items():
            allocated = self._get_allocated_bandwidth(host_id, port_id)
            avail = PORT_GBPS - allocated
            # Check for a best (tightest) fit
            if avail >= gbps and (best_fit is None or avail < best_fit_avail):
                best_fit, best_fit_avail = port_id, avail
        return best_fit

    def _select_port_least_overloaded(self, ports, host_id):
        """Return the last-overloaded port."""
        best_fit, best_fit_allocated = None, None
        for port_id, _ in ports.items():
            allocated = self._get_allocated_bandwidth(host_id, port_id)
            # Check for a best (least loaded) fit
            if best_fit is None or allocated < best_fit_allocated:
                best_fit, best_fit_allocated = port_id, allocated
        return best_fit

    def _calculate_ip(self, tenant_id, subnet, orig_zone_ip, used):

        zone_ip = orig_zone_ip or self.props.get_free_ip(tenant_id, subnet)

        if zone_ip is None:
            LOG.error("No free IPs in subnet %s", subnet)

        # check if selected IP is in the used IPs
        if zone_ip in used:
            # remember all used IPs
            for u in used:
                self.props.remember_ip(tenant_id, subnet, u)
            # now get the new free IP
            zone_ip = self.props.get_free_ip(tenant_id, subnet)

        self.props.remember_ip(tenant_id, subnet, zone_ip)

        return zone_ip

    def bind_port(self, context):
        """Bind a Neutron port to a suitable physical port.

        The port binding process includes these steps:
        1. Ensure that we know how bandwidth is currently assigned to ports.
        2. Choose a suitable physical port based on bandwidth supply/demand.
        3. Choose subnet and VLAN-ID based on physical port and zone value.
        4. Store all relevant decisions in binding:vif_details.
        5. Bind the port with VIF_VHOSTUSER to suit the Snabb Switch agent.
        """
        LOG.debug("Attempting to bind port %(port)s on network %(network)s "
                  "with profile %(profile)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id'],
                   'profile': context.original[portbindings.PROFILE]})
        self._update_allocated_bandwidth(context)
        # REVISIT(lukego) Why is binding:profile set in
        # context.original but {} in context.current?
        orig = context.original
        gbps = self._requested_gbps(orig)
        orig_zone_ip = orig[portbindings.VIF_DETAILS].get('zone_ip')

        if orig_zone_ip is not None:
            if context.current['binding:host_id'] != context.original[
                    'binding:host_id']:
                LOG.debug("Port %(port)s with ip %(ip)s "
                          "migrated from %(host_id)s "
                          "to %(orig_host_id)s",
                          {'port': context.current['id'],
                           'ip': orig_zone_ip,
                           'host_id': context.network.current['id'],
                           'orig_host_id':
                           context.original[portbindings.PROFILE]})
                # the port has an allocated IP but is migrated
                self.props.remove_ip(context.current['tenant_id'],
                                     orig_zone_ip)
                orig_zone_ip = None

        for segment in context.network.network_segments:
            if self.check_segment(segment):
                db_port_id = context.current['id']
                host_id = context.current['binding:host_id']
                zone = segment[api.SEGMENTATION_ID]
                base_ip = self._assigned_ip(context.current)
                if base_ip is None:
                    msg = "fixed_ips address required to bind zone port."
                    raise exc.InvalidInput(error_message=msg)
                base_ip = netaddr.IPAddress(base_ip)
                port_id = self._choose_port(
                    host_id,
                    zone,
                    base_ip.version,
                    gbps)
                # Calculate the correct IP address
                try:
                    subnet, vlan, used = self.networks[host_id][port_id][zone]
                except KeyError:
                    msg = ("zone %s not found for host:%s port:%s" %
                           (zone, host_id, port_id))
                    raise exc.InvalidInput(error_message=msg)

                zone_ip = self._calculate_ip(
                    context.current['tenant_id'],
                    subnet,
                    orig_zone_ip,
                    used)

                profile = context.current[portbindings.PROFILE]
                if profile is None:
                    profile = context.original[portbindings.PROFILE]
                # Store all decisions in the port vif_details.
                vif_details = {portbindings.CAP_PORT_FILTER: True,
                               portbindings.PROFILE: profile,
                               'zone_host': host_id,
                               'zone_ip': zone_ip,
                               'zone_vlan': vlan,
                               'zone_port': port_id,
                               'zone_gbps': gbps}
                self._allocate_bandwidth(host_id, port_id, db_port_id, gbps)
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    vif_details,
                                    status=n_const.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    def _requested_gbps(self, port):
        """Return the number of gbps to be reserved for port."""
        gbps = (port[portbindings.PROFILE].get('zone_gbps') or
                port[portbindings.VIF_DETAILS].get('zone_gbps') or
                DEFAULT_GBPS_ALLOCATION)
        return float(gbps)

    def _assigned_ip(self, port):
        """Return the IP address assigned to Port."""
        for ip in port['fixed_ips']:
            if ip['ip_address']:
                return ip['ip_address']

    def _get_allocated_bandwidth(self, host_id, port_id):
        """Return the amount of bandwidth allocated on a physical port."""
        allocations = self.allocated_bandwidth.get((host_id, port_id), {})
        return sum(allocations.values())

    def _allocate_bandwidth(self, host_id, port_id, neutron_port_id, gbps):
        """Record a physical bandwidth allocation."""
        self.allocated_bandwidth.setdefault((host_id, port_id), {})
        self.allocated_bandwidth[(host_id, port_id)][neutron_port_id] = gbps

    def _update_allocated_bandwidth(self, context):
        """Ensure that self.allocated_bandwidth is up-to-date."""
        # TODO(lukego) Find a reliable way to cache this information.
        self._scan_bandwidth_allocations(context)

    def _scan_bandwidth_allocations(self, context):
        """Learn bandwidth allocations by scanning all port bindings."""
        self.allocated_bandwidth = {}
        LOG.debug("context = %s", context)
        dbcontext = context._plugin_context
        ports = context._plugin.get_ports(dbcontext)
        for port in ports:
            self._scan_port_bandwidth_allocation(port)

    def _scan_port_bandwidth_allocation(self, port):
        """Learn the physical bandwdith allocated to a Neutron port."""
        details = port[portbindings.VIF_DETAILS]
        hostname = details.get('zone_host')
        portname = details.get('zone_port')
        gbps = details.get('zone_gbps')
        if hostname and portname and gbps:
            LOG.debug("Port %(port_id)s: %(gbps)s Gbps bandwidth reserved on "
                      "host %(host)s port %(port)s",
                      {'port_id': port['id'],
                       'gbps': gbps,
                       'host': hostname,
                       'port': portname})
            self._allocate_bandwidth(hostname, portname, port['id'], gbps)
        else:
            LOG.debug("Port %s: no bandwidth reservation", portname)

    def check_segment(self, segment):
        """Verify a segment is valid for the SnabbSwitch MechanismDriver.

        Verify the requested segment is supported by Snabb and return True or
        False to indicate this to callers.
        """
        return segment[api.NETWORK_TYPE] == 'zone'

    def _is_float(self, a, name):
        try:
            if a.get(name):
                float(a.get(name))
            return True
        except ValueError:
            return False

    def _is_ip(self, a, name):
        try:
            if a.get(name):
                IPAddress(a.get(name))
            return True
        except Exception:
            return False

    def _validate_port_binding(self, port):
        profile = port[portbindings.PROFILE]

        if not self._is_float(profile, 'tx_police_gbps'):
            return 'tx_police_gbps'
        if not self._is_float(profile, 'rx_police_gbps'):
            return 'rx_police_gbps'
        if not self._is_ip(profile, 'l2tpv3_remote_ip'):
            return 'l2tpv3_remote_ip'
        if not self._is_ip(profile, 'l2tpv3_next_hop'):
            return 'l2tpv3_next_hop'
        v = profile.get('l2tpv3_local_cookie')
        if v and len(v) > 16:
            return 'l2tpv3_local_cookie'
        v = profile.get('l2tpv3_remote_cookie')
        if v and len(v) > 16:
            return 'l2tpv3_remote_cookie'
        v = profile.get('l2tpv3_session')
        if v and int(v) > 0xffffffff:
            return 'l2tpv3_session'

        vif_details = port[portbindings.VIF_DETAILS]
        if not self._is_float(vif_details, 'zone_gbps'):
            return 'zone_gbps'
        if not self._is_ip(vif_details, 'zone_ip'):
            return 'zone_ip'
        v = profile.get('zone_vlan')
        if v and int(v) > 4095:
            return 'zone_vlan'

    def create_port_precommit(self, context):
        """.
        """
        LOG.debug("Attempting to create port %(port)s on network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        fault = self._validate_port_binding(context.current)
        if fault:
            LOG.error("Invalid parameter %", fault)
            raise ml2_exc.MechanismDriverError()

    def update_port_precommit(self, context):
        """.
        """
        LOG.debug("Attempting to update port %(port)s on network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        fault = self._validate_port_binding(context.current)
        if fault:
            LOG.error("Invalid parameter %", fault)
            raise ml2_exc.MechanismDriverError()

    def delete_port_postcommit(self, context):
        vif_type = context.current.get(portbindings.VIF_TYPE)
        if vif_type == portbindings.VIF_TYPE_VHOSTUSER:
            LOG.debug(
                "Deleting port %(port)s on network %(network)s",
                {'port': context.current['id'],
                 'network': context.network.current['id']})
            port_context = context.current
            tenant_id = port_context['tenant_id']
            vif_details = port_context[portbindings.VIF_DETAILS]
            vm_ip = vif_details['zone_ip']

            self.props.remove_ip(tenant_id, vm_ip)
