# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os, re

from autotest_lib.client.bin import test, utils
from autotest_lib.client.common_lib import error

class hardware_TPM(test.test):
    version = 1
    preserve_srcdir = True
    # Tests that we don't want to run for various reasons.
    exclusions = {'context': r'GetRegisteredKeys.*|LoadKeyByUUID03|'
                             r'UnregisterKey03',
                  'hash': r'TickStampBlob.*',
                  'init': r'.*',
                  'nv': r'DefineSpace04',
                  'tpm': r'GetEventLog.*|CertifySelfTest.*|SetStatus.*',
                  'transport': r'GetPubEndorsementKey.*|NV_WriteValue.*|'
                               r'NV_ReadValue.*|Key_UnloadKey.*|'
                               r'Maintenance.*|VerifyDelegation.*|'
                               r'GetAuditDigest.*|OwnerGetSRKPubKey.*|'
                               r'SetOperatorAuth.*|SetStatus.*',
                  'tspi': r'ChangeAuthAsym.*'}
    # Tests that require TPM owner credentials.
    owner_required = {'context': r'CloseSignTransport.*',
                      'cmk': r'.*',
                      'delegation': r'.*',
                      'key': r'CreateMigrationBlob.*|ConvertMigrationBlob.*',
                      'nv': r'.*',
                      'policy': r'policy_check_lifetime.*',
                      'transport': r'.*',
                      'tpm': r'AuthorizeMigrationTicket.*|'
                             r'CollateIdentityRequest.*|'
                             r'CreateMaintenanceArchive.*|Delegate.*|'
                             r'DirWrite.*|GetAuditDigest.*|'
                             r'GetPubEndorsementKey.*|GetStatus.*|'
                             r'KeyControlOwner.*|KillMaintenanceFeature.*|'
                             r'OwnerGetSRKPubKey.*|TakeOwnership.*',
                      'tspi': r'ChangeAuth05.*|ChangeAuth06.*|'
                              r'SetAttribUint3208.*'}

    def setup(self):
        os.chdir(self.srcdir)
        utils.make('clean')
        utils.make('all')

    def run_once(self, suite, owner_secret, test_filter):
        excluded_tests_re = None
        owner_tests_re = None
        test_filter_re = None
        if suite in self.exclusions:
            excluded_tests_re = re.compile(self.exclusions[suite])
        if suite in self.owner_required:
            owner_tests_re = re.compile(self.owner_required[suite])
        if test_filter:
            test_filter_re = re.compile(test_filter)
        if owner_secret:
            os.environ['TESTSUITE_OWNER_SECRET'] = owner_secret
        exclude_owner = not owner_secret
        suite_path = '%s/src/tests/%s' % (self.bindir, suite)
        tests = sorted(os.listdir(suite_path))
        for test in tests:
            # Skip excluded tests.
            if excluded_tests_re and excluded_tests_re.search(test):
                continue
            # Skip tests requiring an owner secret if we don't have one.
            if exclude_owner and owner_tests_re and owner_tests_re.search(test):
                continue
            # Skip filtered tests.
            if test_filter_re and not test_filter_re.search(test):
                continue
            utils.system('%s/%s -v 1.2 1>&2' % (suite_path, test))

