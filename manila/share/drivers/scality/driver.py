# Copyright (c) 2015 Scality
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

from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log

from manila.common import constants as const
from manila import exception
from manila.i18n import _
from manila.i18n import _LE
from manila.i18n import _LI
from manila.share import driver
from manila import utils

LOG = log.getLogger(__name__)

share_opts = [
    cfg.StrOpt('nfs_export_ip', help='IP reachable from the tenant networks '
               'on which the NFS shares are exposed'),
    cfg.StrOpt('nfs_management_host',
               help='IP/hostname of the machine hosting the scality-sfused '
               'NFS connector (on which scality-manila-utils must be '
               'installed)'),
    cfg.IntOpt('nfs_management_port',
               default=22,
               help='Port that sshd is listening on, on the '
               'nfs_management_host machine'),


    cfg.StrOpt('smb_export_ip', help='IP reachable from the tenant networks '
               'on which the SMB shares are exposed'),
    cfg.StrOpt('smb_management_host',
               help='IP/hostname of the machine hosting the scality-sfused '
               'SMB connector (on which scality-manila-utils must be '
               'installed)'),
    cfg.IntOpt('smb_management_port',
               default=22,
               help='Port that sshd is listening on, on the '
               'smb_management_host machine'),
    cfg.StrOpt('smb_export_root', help='Full path on the smb_management_host '
               'machine of a SOFS directory where the SMB share directories '
               'will be created'),


    cfg.StrOpt('management_user',
               help='User for management tasks'),
    cfg.StrOpt('ssh_key_path',
               help='Path to the SSH key of the management user'),
]

CONF = cfg.CONF
CONF.register_opts(share_opts)


class ScalityShareDriver(driver.ShareDriver):
    """Scality Ring driver for Manila.

    Supports NFS through the Sfused NFS connector.
    Supports SMB through the Sfused SMB connector.
    """

    VERSION = '1.0'

    def __init__(self, *args, **kwargs):
        super(ScalityShareDriver, self).__init__(False, *args, **kwargs)
        self.configuration.append_config_values(share_opts)

        self._helpers = {}

    def do_setup(self, context):
        super(ScalityShareDriver, self).do_setup(context)

        LOG.debug('Validating Scality Driver configuration')

        msg = _("Configuration error: missing value for %(item)s. "
                "Check the manila.conf file")

        # Check generic configuration
        for config_item in ('management_user', 'ssh_key_path'):
            # Accept neither None nor ""
            if getattr(self.configuration, config_item) in (None, ''):
                raise exception.InvalidParameterValue(
                    err=msg % {'item': config_item})

        # Check protocol specific configuration
        group_of_config_items = (
            ('NFS', ('nfs_export_ip', 'nfs_management_host')),
            ('SMB', ('smb_export_ip', 'smb_management_host',
                     'smb_export_root'))
        )

        for protocol, config_keys in group_of_config_items:
            config_values = [getattr(self.configuration, k)
                             for k in config_keys]

            if not any(config_values):
                # All the values are empty -> we don't want to configure
                # this protocol
                continue

            if not all(config_values):
                # Some values are missing
                items = ' or '.join(config_keys)
                raise exception.InvalidParameterValue(
                    err=msg % {'item': items})

            proto = protocol.lower()
            ip = getattr(self.configuration, proto + '_management_host')
            port = getattr(self.configuration, proto + '_management_port')
            ssh_pool = utils.SSHPool(
                ip=ip, port=port, conn_timeout=None,
                login=self.configuration.management_user,
                privatekey=self.configuration.ssh_key_path,
                max_size=1)

            export_ip = getattr(self.configuration, proto + '_export_ip')

            if protocol == 'NFS':
                self._helpers['NFS'] = NFSHelper(ssh_pool, export_ip)
            elif protocol == 'SMB':
                export_root = self.configuration.smb_export_root
                # Manila refers to this protocol as CIFS.
                # It's better known as SMB at Scality
                self._helpers['CIFS'] = CIFSHelper(ssh_pool, export_ip,
                                                   export_root)
            else:
                err = ("Unknown protocol %(proto)s while initializing "
                       "%(driver)s") % {"proto": protocol,
                                        "driver": self.__class__.__name__}
                raise exception.ManilaException(err)

    def _get_helper(self, share):
        """Get the correct helper instance based on the share protocol."""
        helper = self._helpers.get(share['share_proto'])
        if helper:
            return helper
        else:
            reason = _("Protocol '%s' is wrong, unsupported or "
                       "disabled") % share['share_proto']
            raise exception.InvalidShare(reason=reason)

    def check_for_setup_error(self):
        """Returns an error if prerequisites aren't met.

        This is called by `manila.share.manager.ShareManager` right after the
        call to `do_setup`
        """
        for proto, helper in list(self._helpers.items()):
            if not helper.setup_is_valid():
                del self._helpers[proto]

        if not self._helpers:
            msg = _("ScalityShareDriver is not properly initialized")
            raise exception.ManilaException(msg)

    def allow_access(self, context, share, access, share_server=None):
        # NOTE(vponomaryov): use direct verification for case some additional
        # level is added.
        access_level = access['access_level']
        if access_level not in (const.ACCESS_LEVEL_RW, const.ACCESS_LEVEL_RO):
            raise exception.InvalidShareAccessLevel(level=access_level)

        self._get_helper(share).allow_access(share, access)

    def deny_access(self, context, share, access, share_server=None):
        self._get_helper(share).deny_access(share, access)

    def delete_share(self, context, share, share_server=None):
        self._get_helper(share).delete_share(share)

    def create_share(self, context, share, share_server=None):
        return self._get_helper(share).create_share(share)

    def ensure_share(self, context, share, share_server=None):
        return self._get_helper(share).ensure_share(share)

    def _update_share_stats(self):
        backend_name = self.configuration.safe_get(
            'share_backend_name') or 'Scality Ring Driver'

        # If both protocols are enabled, protocol must be NFS_CIFS not CIFS_NFS
        protocol = '_'.join(sorted(self._helpers.keys(), reverse=True))

        if not protocol:
            msg = _("ScalityShareDriver is not properly initialized")
            raise exception.ManilaException(msg)

        stats = {
            'share_backend_name': backend_name,
            'vendor_name': 'Scality',
            'storage_protocol': protocol,
            'driver_version': self.VERSION,
        }

        super(ScalityShareDriver, self)._update_share_stats(stats)


class NASHelperBase(object):
    """Base class for protocol specific share management tasks."""

    # Cli exit codes
    EXPORT_NOT_FOUND = 10
    ACCESS_EXISTS = 11
    ACCESS_NOT_FOUND = 12
    HAS_GRANTS = 13
    EXPORT_EXISTS = 14

    def __init__(self, ssh_pool, export_ip):
        self.ssh_pool = ssh_pool
        self.export_ip = export_ip
        self.optional_args = ""

    def _management_call(self, command):
        """Send a command over ssh to the ring management host.

        :param command: command to execute
        :param command: string
        :returns: tuple of (stdout, stderr) with command output
        """
        cmd = 'sudo scality-manila-utils %s %s %s' % (
              self.PROTOCOL.lower(), self.optional_args, command)
        LOG.debug("Management execute: %s", cmd)

        with self.ssh_pool.item() as connection:
            result = processutils.ssh_execute(connection, cmd)
        return result

    @staticmethod
    def _enforce_ip_acl(access):
        """Check that the access is IP based."""
        if access['access_type'] != 'ip':
            reason = 'Only IP access type allowed'
            raise exception.InvalidShareAccess(reason)

    def setup_is_valid(self):
        """Check that the management host is up and ready."""
        LOG.info(_LI('Checking management server prerequisites'))

        try:
            self._management_call('check')
        except processutils.ProcessExecutionError as e:
            err = _LE("Requirements are not met on the management server."
                      "Check the manila.conf file and the "
                      "configuration of the management server. Protocol "
                      "%(proto)s is now disabled.")
            LOG.error(err, {'proto': self.PROTOCOL})
            LOG.error(e)
            return False

        LOG.info(_LI("Scality driver is properly configured for protocol "
                     "%(proto)s"), {'proto': self.PROTOCOL})
        return True

    def _get_allow_access_cmd(self, share, access):
        raise NotImplementedError()

    def allow_access(self, share, access):
        self._enforce_ip_acl(access)

        command = self._get_allow_access_cmd(share, access)
        try:
            self._management_call(command)

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.ACCESS_EXISTS:
                raise exception.ShareAccessExists(
                    access_type=access['access_type'],
                    access=access['access_to']
                )

            elif e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%(name)s' (%(id)s) not found") % {
                    'name': share['name'], 'id': share['id']}
                raise exception.InvalidShare(reason=msg)

            else:
                raise

    def deny_access(self, share, access):
        self._enforce_ip_acl(access)

        command = 'revoke %s %s' % (share['id'], access['access_to'])
        try:
            self._management_call(command)

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.ACCESS_NOT_FOUND:
                # Access rule can be in error state so not properly set
                # in the backend. So don't raise.
                msg = _LI("Fail to revoke access of %(access_to)s on share"
                          "%(name)s (%(id)s): the grant didn't exist in the "
                          "backend") % {'id': share['id'],
                                        'access_to': access['access_to'],
                                        'name': share['name']}
                LOG.info(msg)
            elif e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%(name)s' (%(id)s) not found") % {
                    'name': share['name'], 'id': share['id']}
                raise exception.InvalidShare(reason=msg)

            else:
                raise

    def delete_share(self, share):
        command = 'wipe %s' % share['id']

        try:
            self._management_call(command)

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.HAS_GRANTS:
                msg = _("Unable to remove share with granted access")
                raise exception.ShareBackendException(msg=msg)

            elif e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%(name)s' (%(id)s) not found") % {
                    'name': share['name'], 'id': share['id']}
                raise exception.InvalidShare(reason=msg)

            else:
                raise

    def create_share(self, share):
        command = 'create %s' % share['id']

        try:
            self._management_call(command)
        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.EXPORT_EXISTS:
                msg = _("Share '%(name)s' (%(id)s) already defined.") % {
                    'name': share['name'], 'id': share['id']}
                raise exception.ShareBackendException(msg=msg)
            else:
                raise

        return self._location_from_id(share['id'])

    def ensure_share(self, share):
        # Export locations are derived from the `export_ip` configuration
        # parameter, and may thus change between service restarts. It is
        # therefor always returned here if the share exists.
        try:
            self._management_call('get %s' % share['id'])

        except processutils.ProcessExecutionError as e:
            if e.exit_code == self.EXPORT_NOT_FOUND:
                msg = _("'%(name)s' (%(id)s) not found") % {
                    'name': share['name'], 'id': share['id']}
                raise exception.InvalidShare(reason=msg)

            else:
                raise

        return self._location_from_id(share['id'])

    def _location_from_id(self, share_id):
        """Format an export location from a share_id.

        :param share_id: share id to format
        :type share_id: string
        :returns: string
        """
        raise NotImplementedError()


class CIFSHelper(NASHelperBase):

    PROTOCOL = "SMB"

    def __init__(self, ssh_pool, export_ip, export_root):
        super(CIFSHelper, self).__init__(ssh_pool, export_ip)
        self.optional_args = "--root-export %s" % export_root

    @staticmethod
    def _get_allow_access_cmd(share, access):
        if access['access_level'] != const.ACCESS_LEVEL_RW:
            raise exception.InvalidShareAccessLevel(
                level=access['access_level'])

        # The scality-manila-utils implicitely set the access level to RW
        # for SMB. It doesn't expect the `access['access_level']` argument
        return 'grant %s %s' % (share['id'], access['access_to'])

    def deny_access(self, share, access):
        if access['access_level'] != const.ACCESS_LEVEL_RW:
            return

        super(CIFSHelper, self).deny_access(share, access)

    def _location_from_id(self, share_id):
        return '\\\\%s\\%s' % (self.export_ip, share_id)


class NFSHelper(NASHelperBase):

    PROTOCOL = "NFS"

    @staticmethod
    def _get_allow_access_cmd(share, access):
        return 'grant %s %s %s' % (share['id'], access['access_to'],
                                   access['access_level'])

    def _location_from_id(self, share_id):
        return "%s:/%s" % (self.export_ip, share_id)
