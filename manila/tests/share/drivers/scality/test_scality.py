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
import uuid

import mock
from oslo_concurrency import processutils
from oslo_config import cfg

from manila import context
from manila import exception
from manila.share import configuration
from manila.share.drivers.scality import driver
from manila import test
from manila.tests import fake_share
from manila import utils

CONF = cfg.CONF


class ScalityShareDriverTestCase(test.TestCase):
    """Test of the main interface of the scality share driver."""

    def setUp(self):
        super(ScalityShareDriverTestCase, self).setUp()

        self.context = context.get_admin_context()

        CONF.set_default('driver_handles_share_servers', False)
        self.cfg = configuration.Configuration(None)

    def _populate_generic_config(self):
        self.cfg.ssh_key_path = 'id_rsa'
        self.cfg.management_user = 'scality'

    def _populate_nfs_config(self):
        self.cfg.nfs_export_ip = '127.0.0.1'
        self.cfg.nfs_management_host = '10.0.0.4'

    def _populate_smb_config(self):
        self.cfg.smb_export_ip = '127.0.0.2'
        self.cfg.smb_management_host = '10.0.0.3'
        self.cfg.smb_export_root = '/ring/fs.814441413224832176'

    def _populate_config(self):
        self._populate_generic_config()
        self._populate_smb_config()
        self._populate_nfs_config()

    def test_init(self):
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertEqual({}, drv._helpers)

    def test_do_setup_when_config_misses_management_user(self):
        self.cfg.ssh_key_path = 'valid value'
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertRaisesRegex(exception.InvalidParameterValue,
                               '.*management_user.*', drv.do_setup,
                               self.context)

    def test_do_setup_when_config_misses_ssh_key_path(self):
        self.cfg.management_user = 'valid value'
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertRaisesRegex(exception.InvalidParameterValue,
                               '.*ssh_key_path.*', drv.do_setup,
                               self.context)

    def test_do_setup_when_config_misses_some_nfs_values(self):
        self._populate_generic_config()
        self.cfg.nfs_export_ip = '127.0.0.1'
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertRaisesRegex(exception.InvalidParameterValue,
                               '.*nfs_management_host.*', drv.do_setup,
                               self.context)

    def test_do_setup_when_config_misses_some_smb_values(self):
        self._populate_generic_config()
        self.cfg.smb_export_ip = '127.0.0.1'
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertRaisesRegex(exception.InvalidParameterValue,
                               '.*smb_management_host.*', drv.do_setup,
                               self.context)

    @mock.patch('manila.utils.SSHPool')
    def test_do_setup(self, mock_sshpool):
        self._populate_config()

        drv = driver.ScalityShareDriver(configuration=self.cfg)
        drv.do_setup(self.context)

        commun_args = {'login': drv.configuration.management_user,
                       'port': 22, 'conn_timeout': None, 'max_size': 1,
                       'privatekey': drv.configuration.ssh_key_path}
        expected_ssh_pool_calls = [
            mock.call(ip=drv.configuration.nfs_management_host, **commun_args),
            mock.call(ip=drv.configuration.smb_management_host, **commun_args)
        ]
        mock_sshpool.assert_has_calls(expected_ssh_pool_calls, any_order=True)
        self.assertIn('NFS', drv._helpers)
        self.assertIn('CIFS', drv._helpers)
        self.assertIsInstance(drv._helpers['NFS'], driver.NFSHelper)
        self.assertIsInstance(drv._helpers['CIFS'], driver.CIFSHelper)
        self.assertEqual(drv.configuration.nfs_export_ip,
                         drv._helpers['NFS'].export_ip)
        self.assertEqual(drv.configuration.smb_export_ip,
                         drv._helpers['CIFS'].export_ip)

        root_export = "--root-export %s" % drv.configuration.smb_export_root
        self.assertEqual(root_export, drv._helpers['CIFS'].optional_args)

    @mock.patch('manila.utils.SSHPool', mock.Mock())
    def test_get_helper(self):
        self._populate_config()

        drv = driver.ScalityShareDriver(configuration=self.cfg)
        drv._helpers = {'k': mock.sentinel.my_helper}
        self.assertIs(mock.sentinel.my_helper,
                      drv._get_helper({'share_proto': 'k'}))

    @mock.patch('manila.utils.SSHPool', mock.Mock())
    def test_get_helper_invalid_proto(self):
        self._populate_config()

        drv = driver.ScalityShareDriver(configuration=self.cfg)
        self.assertRaises(exception.InvalidShare,
                          drv._get_helper, {'share_proto': 'k'})

    @mock.patch('manila.utils.SSHPool', mock.Mock())
    def test_check_for_setup_error(self):
        self._populate_config()

        mock_nfs = mock.create_autospec(driver.NFSHelper, spec_set=True)
        mock_nfs.return_value.setup_is_valid.return_value = True
        mock_cifs = mock.create_autospec(driver.CIFSHelper, spec_set=True)
        mock_cifs.return_value.setup_is_valid.return_value = False
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        with mock.patch.object(driver, 'NFSHelper', mock_nfs),\
                mock.patch.object(driver, 'CIFSHelper', mock_cifs):
            drv.do_setup(self.context)

        self.assertIs(mock_cifs.return_value, drv._helpers['CIFS'])
        drv.check_for_setup_error()

        self.assertNotIn('CIFS', drv._helpers)
        self.assertIs(mock_nfs.return_value, drv._helpers['NFS'])
        mock_nfs.return_value.setup_is_valid.assert_called_once_with()
        mock_cifs.return_value.setup_is_valid.assert_called_once_with()

    def test_check_for_setup_error_no_proto_configured(self):
        self._populate_config()
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        self.assertRaises(exception.ManilaException, drv.check_for_setup_error)

    def test_update_share_stats(self):
        drv = driver.ScalityShareDriver(configuration=self.cfg)

        expected_base_dict = {
            'driver_version': drv.VERSION,
            'share_backend_name': 'Scality Ring Driver',
            'vendor_name': 'Scality'
        }

        # If the NFS protocol is the only one enabled
        drv._helpers = {'NFS': None}
        drv.get_share_stats(refresh=True)

        expected_dict = expected_base_dict.copy()
        expected_dict['storage_protocol'] = 'NFS'
        self.assertDictContainsSubset(expected_dict, drv._stats)

        # If the SMB protocol is the only one enabled
        drv._helpers = {'CIFS': None}
        drv.get_share_stats(refresh=True)

        expected_dict = expected_base_dict.copy()
        expected_dict['storage_protocol'] = 'CIFS'
        self.assertDictContainsSubset(expected_dict, drv._stats)

        # If both protocols are enabled
        drv._helpers = {'CIFS': None, 'NFS': None}
        drv.get_share_stats(refresh=True)

        expected_dict = expected_base_dict.copy()
        expected_dict['storage_protocol'] = 'NFS_CIFS'
        self.assertDictContainsSubset(expected_dict, drv._stats)

    def test_update_share_stats_when_no_protocol(self):
        drv = driver.ScalityShareDriver(configuration=self.cfg)
        self.assertRaises(exception.ManilaException, drv.get_share_stats,
                          refresh=True)

    def test_delete_share_when_share_not_found(self):
        drv = driver.ScalityShareDriver(configuration=self.cfg)
        share = fake_share.fake_share()
        exc = exception.InvalidShare(reason=u"Unicode\u1234")
        with mock.patch.object(drv, '_get_helper') as mock_get_helper:
            mock_get_helper.return_value.delete_share.side_effect = exc
            # assert that the exception has been caught.
            self.assertIsNone(drv.delete_share(self.context, share))
        mock_get_helper.return_value.delete_share.assert_called_once_with(
            share)


class NASHelperTestCase(test.TestCase):

    def setUp(self):
        super(NASHelperTestCase, self).setUp()
        mock_ssh_pool = mock.MagicMock(spec=utils.SSHPool, autospec=True)
        self.helper = driver.NASHelperBase(mock_ssh_pool, None)
        self.helper.PROTOCOL = "FAKE"

        patcher = mock.patch.object(self.helper, '_get_allow_access_cmd')
        self.mock_get_cmd = patcher.start()
        self.addCleanup(patcher.stop)

        log_patcher = mock.patch.object(driver, 'LOG')
        self.mock_log = log_patcher.start()
        self.addCleanup(log_patcher.stop)

    @mock.patch('oslo_concurrency.processutils.ssh_execute')
    def test_management_call(self, mock_ssh_execute):
        self.helper._management_call('cmd')

        self.helper.ssh_pool.item.assert_called_once_with()
        mock_connection = self.helper.ssh_pool.item().__enter__()
        expected_cmd = 'sudo scality-manila-utils fake  cmd'
        mock_ssh_execute.assert_called_once_with(mock_connection, expected_cmd)

    def test_enforce_ip_acl(self):
        self.assertIsNone(self.helper._enforce_ip_acl({'access_type': 'ip'}))
        self.assertRaises(exception.InvalidShareAccess,
                          self.helper._enforce_ip_acl, {'access_type': 'user'})

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_setup(self, management_call):
        self.assertIs(True, self.helper.setup_is_valid())
        management_call.assert_called_once_with('check')

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_setup_when_error(self, management_call):
        management_call.side_effect = processutils.ProcessExecutionError()

        self.assertIs(False, self.helper.setup_is_valid())

        management_call.side_effect = KeyError()
        self.assertRaises(KeyError, self.helper.setup_is_valid)

        self.assertEqual(2, self.mock_log.error.call_count)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_allow_access_success(self, management_call):
        access = fake_share.fake_access(
            access_to='192.168.0.1/24',
            access_level='rw',
        )
        share = fake_share.fake_share()

        self.helper.allow_access(share, access)

        self.mock_get_cmd.assert_called_once_with(share, access)
        management_call.assert_called_once_with(self.mock_get_cmd.return_value)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_allow_access_failure(self, management_call):
        access = fake_share.fake_access(access_type='user')
        share = fake_share.fake_share()

        # Unsupported access type
        self.assertRaises(exception.ManilaException, self.helper.allow_access,
                          share, access)

        # Access is already defined
        access = fake_share.fake_access()
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.ACCESS_EXISTS
        )
        self.assertRaises(exception.ShareAccessExists,
                          self.helper.allow_access, share, access)

        # Share does not exist
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.EXPORT_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShare, self.helper.allow_access,
                          share, access)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.helper.allow_access, share, access)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_deny_access_success(self, management_call):
        access = fake_share.fake_access()
        share = fake_share.fake_share()

        self.helper.deny_access(share, access)
        management_call.assert_called_once_with(
            'revoke %s %s' % (share['id'], access['access_to'])
        )

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_deny_access_failure(self, management_call):
        access = fake_share.fake_access(access_type='user')
        share = fake_share.fake_share()

        # Unsupported access type
        self.assertRaises(exception.ManilaException, self.helper.deny_access,
                          share, access)

        # Access does not exist
        access = fake_share.fake_access()
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.ACCESS_NOT_FOUND
        )
        # The exception should be swallowed
        self.assertIsNone(self.helper.deny_access(share, access))

        # Share does not exist
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.EXPORT_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShare, self.helper.deny_access,
                          share, access)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.helper.deny_access, share, access)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_delete_share_success(self, management_call):
        share = fake_share.fake_share()
        expected_wipe_command = 'wipe %s' % share['id']

        self.helper.delete_share(share)
        management_call.assert_called_once_with(expected_wipe_command)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_delete_share_failure(self, management_call):
        share = fake_share.fake_share()

        # Share does not exist
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.EXPORT_NOT_FOUND
        )
        self.assertRaises(exception.InvalidShare, self.helper.delete_share,
                          share)

        # Share has existing grants
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.HAS_GRANTS
        )
        self.assertRaises(exception.ShareBackendException,
                          self.helper.delete_share, share)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.helper.delete_share, share)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_create_share_success(self, management_call):
        share = fake_share.fake_share()

        with mock.patch.object(self.helper, '_location_from_id') as mock_loc:
            self.assertIs(mock_loc.return_value,
                          self.helper.create_share(share))

        management_call.assert_called_once_with('create %s' % share['id'])
        mock_loc.assert_called_once_with(share['id'])

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_create_share_failure(self, management_call):
        share = fake_share.fake_share()

        # Share already exists
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.EXPORT_EXISTS
        )
        self.assertRaises(exception.ShareBackendException,
                          self.helper.create_share, share)

        # Unhandled error code should have the exception re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.helper.create_share, share)

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_ensure_share_success(self, management_call):
        share = fake_share.fake_share()

        with mock.patch.object(self.helper, '_location_from_id') as mock_loc:
            self.assertIs(mock_loc.return_value,
                          self.helper.ensure_share(share))

        mock_loc.assert_called_once_with(share['id'])
        management_call.assert_called_once_with('get %s' % share['id'])

    @mock.patch.object(driver.NASHelperBase, '_management_call')
    def test_ensure_share_failure(self, management_call):
        share = fake_share.fake_share()
        # Test ensure of an unknown share
        management_call.side_effect = processutils.ProcessExecutionError(
            exit_code=driver.NASHelperBase.EXPORT_NOT_FOUND)
        self.assertRaises(exception.InvalidShare,
                          self.helper.ensure_share, share)

        # Check that unhandled errors are re-raised
        management_call.side_effect = processutils.ProcessExecutionError
        self.assertRaises(processutils.ProcessExecutionError,
                          self.helper.ensure_share, share)


class CIFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(CIFSHelperTestCase, self).setUp()

        self.export_ip = '127.0.0.2'
        self.export_root = '/ring/fs.814441413224832176'
        self.helper = driver.CIFSHelper(None, self.export_ip,
                                        self.export_root)

    def test_init(self):
        self.assertEqual('--root-export %s' % self.export_root,
                         self.helper.optional_args)

    def test_get_allow_access_cmd(self):
        access = fake_share.fake_access()
        share = fake_share.fake_share()

        self.assertEqual('grant %s %s' % (share['id'], access['access_to']),
                         self.helper._get_allow_access_cmd(share, access))

    def test_get_allow_access_cmd_with_ro_access_level(self):
        access = fake_share.fake_access(access_level='ro')
        share = fake_share.fake_share()

        self.assertRaises(exception.InvalidShareAccessLevel,
                          self.helper._get_allow_access_cmd, share, access)

    def test_deny_access(self):
        share = fake_share.fake_share()

        access = fake_share.fake_access(access_level='ro')
        self.assertIsNone(self.helper.deny_access(share, access))

        access = fake_share.fake_access(access_level='rw')
        with mock.patch.object(driver.NASHelperBase, 'deny_access') as m_deny:
            self.helper.deny_access(share, access)
        m_deny.assert_called_once_with(share, access)

    def test_location_from_id(self):
        share_id = uuid.uuid4()
        self.assertEqual('\\\\%s\\%s' % (self.export_ip, share_id),
                         self.helper._location_from_id(share_id))


class NFSHelperTestCase(test.TestCase):

    def setUp(self):
        super(NFSHelperTestCase, self).setUp()

        self.export_ip = '127.0.0.3'
        self.helper = driver.NFSHelper(None, self.export_ip)

    def test_get_allow_access_cmd(self):
        access = fake_share.fake_access()
        share = fake_share.fake_share()

        expected_cmd = 'grant %s %s %s' % (share['id'], access['access_to'],
                                           access['access_level'])
        self.assertEqual(expected_cmd,
                         self.helper._get_allow_access_cmd(share, access))

    def test_location_from_id(self):
        share_id = uuid.uuid4()
        self.assertEqual("%s:/%s" % (self.export_ip, share_id),
                         self.helper._location_from_id(share_id))


def test_simple_methods():

    CONF.set_default('driver_handles_share_servers', False)

    def test_method(method_name):
        access = fake_share.fake_access()
        share = fake_share.fake_share()
        cfg = configuration.Configuration(None)
        drv = driver.ScalityShareDriver(configuration=cfg)

        with mock.patch.object(drv, '_get_helper') as mock_get_helper:
            method = getattr(drv, method_name)
            method(context.get_admin_context(), share, access)

        mock_get_helper.assert_called_once_with(share)

        mock_method = getattr(mock_get_helper(), method_name)
        if method_name.endswith("access"):
            mock_method.assert_called_once_with(share, access)
        else:
            mock_method.assert_called_once_with(share)

    for method_name in ("deny_access", "delete_share", "create_share",
                        "ensure_share", "allow_access"):
        yield test_method, method_name
