import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from asn1crypto import cms, x509
import certlock
from signature_fixtures import make_pe, make_signed_fixture


class SignerIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signed, cls.signer, cls.collision = make_signed_fixture()

    def test_actual_signer_selected_not_larger_unrelated_certificate(self):
        self.assertEqual(certlock._extract_signer_cert_from_pkcs7(self.signed), self.signer)

    def test_subject_key_identifier_supported(self):
        content = cms.ContentInfo.load(self.signed)
        signer = content['content']['signer_infos'][0]
        signer['version'] = 'v3'
        signer['sid'] = cms.SignerIdentifier(name='subject_key_identifier',
                                            value=x509.Certificate.load(self.signer).key_identifier)
        self.assertEqual(certlock._extract_signer_cert_from_pkcs7(content.dump()), self.signer)

    def test_missing_signer_certificate_rejected(self):
        content = cms.ContentInfo.load(self.signed)
        signer = content['content']['signer_infos'][0]
        signer['sid'] = cms.SignerIdentifier(name='issuer_and_serial_number', value={
            'issuer': signer['sid'].chosen['issuer'], 'serial_number': 999})
        with self.assertRaises(ValueError):
            certlock._extract_signer_cert_from_pkcs7(content.dump())

    def test_ambiguous_issuer_serial_rejected(self):
        content = cms.ContentInfo.load(self.signed)
        content['content']['certificates'].append(cms.CertificateChoices(
            name='certificate', value=x509.Certificate.load(self.collision)))
        with self.assertRaises(ValueError):
            certlock._extract_signer_cert_from_pkcs7(content.dump())

    def test_multiple_or_missing_signers_rejected(self):
        for multiple in (False, True):
            content = cms.ContentInfo.load(self.signed)
            signers = content['content']['signer_infos']
            if multiple:
                signers.append(copy.deepcopy(signers[0]))
            else:
                content['content']['signer_infos'] = cms.SignerInfos([])
            with self.assertRaises(ValueError):
                certlock._extract_signer_cert_from_pkcs7(content.dump())

    def test_nested_signature_rejected(self):
        content = cms.ContentInfo.load(self.signed)
        content['content']['signer_infos'][0]['unsigned_attrs'] = cms.CMSAttributes([
            cms.CMSAttribute({'type': '1.3.6.1.4.1.311.2.4.1',
                              'values': [cms.ContentInfo.load(self.signed)]})])
        with self.assertRaisesRegex(ValueError, '嵌套'):
            certlock._extract_signer_cert_from_pkcs7(content.dump())

    def test_malformed_and_trailing_data_rejected(self):
        for blob in (b'invalid', self.signed[:-20], self.signed + b'extra'):
            with self.assertRaises(ValueError):
                certlock._extract_signer_cert_from_pkcs7(blob)

    def test_pe_extraction_does_not_claim_signature_validity(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'signed.exe'
            path.write_bytes(make_pe(self.signed))
            info = certlock.extract_cert_from_exe(path)
            self.assertEqual(info['CN'], 'Audit Actual Signer')
            self.assertEqual(info['STATUS'], 'ExtractedNotVerified')

    def test_multiple_pe_signatures_and_truncated_tables_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'unsupported.exe'
            for data in (make_pe(self.signed, duplicate=True), make_pe(self.signed)[:-20]):
                path.write_bytes(data)
                self.assertIn('error', certlock.extract_cert_from_exe(path))


class PolicySafetyTests(unittest.TestCase):
    def test_legacy_migration_hook_never_writes(self):
        with patch.object(certlock, 'reg_open_srp') as reader, patch.object(
            certlock.winreg, 'SetValueEx') as writer, patch.object(certlock, '_import_to_trusted_publishers') as trust:
            self.assertEqual(certlock.repair_legacy_rules(), 0)
            reader.assert_not_called()
            writer.assert_not_called()
            trust.assert_not_called()

    def test_gui_startup_never_repairs_existing_policy(self):
        with patch.object(sys, 'argv', ['certlock']), patch.object(certlock, 'is_admin', return_value=True), \
             patch.object(certlock, 'load_preset_cert_data'), patch.object(certlock, 'repair_legacy_rules') as repair, \
             patch.object(certlock, 'check_policy_conflicts', return_value=[]), \
             patch.object(certlock.tk, 'Tk'), patch.object(certlock, 'CertLockApp'), \
             patch.object(certlock.winreg, 'SetValueEx') as writer:
            certlock.main()
            repair.assert_not_called()
            writer.assert_not_called()

    def test_unreadable_policy_does_not_become_empty_inventory(self):
        with patch.object(certlock.winreg, 'OpenKey', side_effect=PermissionError('denied')):
            with self.assertRaises(certlock.PolicyReadError):
                certlock.reg_list_certs()
            with self.assertRaises(certlock.PolicyReadError):
                certlock.reg_export_all_rules()

    def test_missing_policy_is_explicitly_absent(self):
        with patch.object(certlock.winreg, 'OpenKey', side_effect=FileNotFoundError()):
            self.assertEqual(certlock.reg_list_certs(), [])
            snapshot = certlock.reg_export_all_rules()
            self.assertFalse(snapshot['policy_present'])
            self.assertIsNone(snapshot['default_level'])

    def test_enumeration_failure_does_not_return_partial_inventory(self):
        with patch.object(certlock, 'reg_open_srp', return_value=1), \
             patch.object(certlock.winreg, 'OpenKey', return_value=2), \
             patch.object(certlock.winreg, 'QueryInfoKey', return_value=(2, 0, 0)), \
             patch.object(certlock.winreg, 'EnumKey', side_effect=['first', PermissionError('denied')]), \
             patch.object(certlock.winreg, 'QueryValueEx', side_effect=[('description', 1), (0, 4), (b'cert', 3)]), \
             patch.object(certlock.winreg, 'CloseKey'):
            with self.assertRaises(certlock.PolicyReadError):
                certlock.reg_list_certs()

    def test_root_snapshot_failure_aborts(self):
        with patch.object(certlock, 'reg_open_srp', return_value=1), \
             patch.object(certlock.winreg, 'QueryValueEx', side_effect=PermissionError('denied')), \
             patch.object(certlock.winreg, 'CloseKey') as close:
            with self.assertRaises(certlock.PolicyReadError):
                certlock.reg_export_all_rules()
            close.assert_called_once_with(1)

    def test_binary_backup_is_json_serializable(self):
        with patch.object(certlock, 'reg_open_srp', return_value=None), patch.object(
            certlock, 'reg_list_certs', return_value=[dict(thumbprint='a', description='test',
                                                         disallowed=True, cert_data=b'cert')]):
            snapshot = certlock.reg_export_all_rules()
            self.assertEqual(snapshot['certificates'][0]['cert_data'], 'Y2VydA==')
            json.dumps(snapshot)

    def test_read_failure_prevents_template_write_and_backup_creation(self):
        with patch.object(certlock, 'reg_export_all_rules', side_effect=certlock.PolicyReadError('denied')), \
             patch.object(certlock, 'reg_add_cert') as writer, patch.object(certlock.tempfile, 'NamedTemporaryFile') as backup:
            with self.assertRaises(certlock.PolicyReadError):
                certlock.apply_template_plan({'add': [{'thumbprint': 'a'}], 'skip': []})
            writer.assert_not_called()
            backup.assert_not_called()

    def test_gui_read_failure_is_visible_not_an_empty_list(self):
        app = SimpleNamespace(tree=MagicMock(), policy_label=MagicMock(), _report_callback_exception=MagicMock(),
                              _refresh_list_from_registry=MagicMock(side_effect=certlock.PolicyReadError('denied')))
        certlock.CertLockApp.refresh_list(app)
        app._report_callback_exception.assert_called_once()
        self.assertEqual(app.tree.insert.call_args.kwargs['values'][0], '(读取失败)')

    def test_hash_callback_explains_disabled_feature_without_selecting_file(self):
        app = SimpleNamespace(status_label=MagicMock())
        with patch.object(certlock.messagebox, 'showinfo') as notice, \
             patch.object(certlock.filedialog, 'askopenfilename') as chooser, \
             patch.object(certlock, 'reg_add_hash') as writer:
            certlock.CertLockApp.on_block_hash(app)
            self.assertIn('暂不支持', notice.call_args.args[0])
            chooser.assert_not_called()
            writer.assert_not_called()

    def test_disabled_cli_hash_does_not_request_admin(self):
        with patch.object(sys, 'argv', ['certlock', '--hash', 'not-used.exe']), \
             patch.object(certlock, 'is_admin', return_value=False) as admin:
            with self.assertRaises(SystemExit) as error:
                certlock.main()
            self.assertEqual(error.exception.code, certlock.EXIT_OPERATION_FAILED)
            admin.assert_not_called()


if __name__ == '__main__':
    unittest.main()
