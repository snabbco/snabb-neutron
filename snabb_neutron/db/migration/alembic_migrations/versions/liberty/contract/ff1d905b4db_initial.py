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
# @author: Domen Kožar


"""Initial Liberty contract revision.

Revision ID: fa1d905b4db
Revises: Libert
Create Date: 2016-01-26 15:40:35

"""

from alembic import op
import sqlalchemy as sa
from neutron.db.migration import cli, schema_has_table


# revision identifiers, used by Alembic.
revision = 'fa1d905b4db'
down_revision = ''
branch_labels = (cli.CONTRACT_BRANCH,)


def upgrade():
    if not schema_has_table('snabb_mechanism_props'):
        op.create_table(
            'snabb_mechanism_props',
            sa.Column('tenant_id', sa.String(length=255), nullable=True),
            sa.Column('subnet', sa.String(length=64), nullable=False),
            sa.Column('ip_address', sa.String(length=64), nullable=False),
            sa.PrimaryKeyConstraint('ip_address'),
            mysql_engine='InnoDB',
        )
        op.create_index(
          op.f('ix_snabb_mechanism_props_tenant_id'),
          'snabb_mechanism_props',
          ['tenant_id'],
          unique=False,
        )
