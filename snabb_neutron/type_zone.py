# Copyright (c) 2013 OpenStack Foundation
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

from neutron.common import exceptions as exc
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)


class ZoneTypeDriver(api.TypeDriver):

    def __init__(self):
        pass

    def get_type(self):
        return 'zone'

    def initialize(self):
        LOG.info(_("ZoneTypeDriver initialization complete."))

    def validate_provider_segment(self, segment):
        segmentation_id = segment.get(api.SEGMENTATION_ID)
        if segmentation_id is None:
            msg = _("segmentation_id required for Zone provider network")
            raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, session, segment):
        # TODO(lukego): Ensure each Zone value is used on only one network.
        pass

    def allocate_tenant_segment(self, session):
        raise exc.NoNetworkAvailable

    def release_segment(self, session, segment):
        pass
