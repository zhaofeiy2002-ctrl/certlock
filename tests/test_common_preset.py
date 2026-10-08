import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import certlock


class CommonPresetTests(unittest.TestCase):
    def setUp(self):
        self.template = certlock.build_common_template()
        self.registry = patch.object(certlock, 'reg_list_certs', return_value=[])
        self.registry.start()
        self.addCleanup(self.registry.stop)
        self.discovery = patch.object(certlock, 'discover_wps_directories', return_value=[])
        self.discovery.start()
        self.addCleanup(self.discovery.stop)

    def test_without_wps_skips_both_kingsoft_certificates(self):
        plan = certlock.plan_community_template(self.template)
        self.assertEqual(len(plan['add']), 4)
        self.assertEqual(len(plan['skip']), 2)
        self.assertTrue(all('kingsoft' not in r['subject'].lower() for r in plan['add']))
        self.assertTrue(all('kingsoft' in r['subject'].lower() for r in plan['skip']))

    def test_uses_actual_der_subject_not_template_label(self):
        data = copy.deepcopy(self.template)
        for rule in data['rules']:
            rule['subject'] = 'Unrelated publisher'
            rule['description'] = 'unrelated'
        plan = certlock.plan_community_template(data)
        self.assertEqual(len(plan['skip']), 2)

    def test_wps_shared_signer_excluded_from_all_publishers(self):
        protected = self.template['rules'][0]['thumbprint']
        with patch.object(certlock, 'scan_wps_signers', return_value={protected}):
            plan = certlock.plan_community_template(self.template, 'WPS')
        self.assertEqual(len(plan['add']), 5)
        self.assertEqual(plan['skip'][0]['thumbprint'], protected)

    def test_auto_discovery_scans_every_detected_wps_directory(self):
        tp1, tp2 = [r['thumbprint'] for r in self.template['rules'][:2]]
        with patch.object(certlock, 'discover_wps_directories', return_value=['version1', 'version2']), patch.object(
            certlock, 'scan_wps_signers', side_effect=[{tp1}, {tp2}]) as scanner:
            plan = certlock.plan_community_template(self.template)
        self.assertTrue(plan['wps_checked'])
        self.assertEqual(scanner.call_count, 2)
        self.assertEqual({r['thumbprint'] for r in plan['skip']}, {tp1, tp2})

    def test_extra_keep_program_does_not_disable_unchecked_wps_fallback(self):
        tp = self.template['rules'][3]['thumbprint']
        with patch.object(certlock, 'extract_cert_from_exe', return_value={'THUMBPRINT': tp}):
            plan = certlock.plan_community_template(self.template, protected_files=['qq.exe'])
        self.assertFalse(plan['wps_checked'])
        self.assertEqual(len(plan['skip']), 3)
        self.assertNotIn(tp, {r['thumbprint'] for r in plan['add']})

    def test_unknown_keep_signature_refuses_to_apply(self):
        with patch.object(certlock, 'extract_cert_from_exe', return_value={'error': 'no_signature'}):
            with self.assertRaisesRegex(ValueError, '保留程序'):
                certlock.plan_community_template(self.template, protected_files=['unknown.exe'])

    def test_existing_wps_block_refuses_import(self):
        tp = self.template['rules'][0]['thumbprint']
        with patch.object(certlock, 'scan_wps_signers', return_value={tp}), patch.object(
            certlock, 'reg_list_certs', return_value=[dict(thumbprint=tp, disallowed=True)]
        ), patch.object(certlock, 'reg_add_cert') as writer:
            with self.assertRaisesRegex(ValueError, '冲突'):
                certlock.plan_community_template(self.template, 'WPS')
            writer.assert_not_called()

    def test_malformed_last_rule_cannot_partially_write(self):
        self.template['rules'][-1]['cert_data'] = 'not-base64'
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'invalid.json'
            p.write_text(json.dumps(self.template), encoding='utf-8')
            with patch.object(certlock, 'reg_add_cert') as writer:
                with self.assertRaises(ValueError):
                    certlock.import_community_template(str(p))
                writer.assert_not_called()

    def test_duplicate_unknown_and_allow_rules_rejected(self):
        for mutate in (
            lambda d: d['rules'].append(d['rules'][0]),
            lambda d: d['rules'][0].update(type='hash'),
            lambda d: d['rules'][0].update(disallowed=False),
            lambda d: d.update(protection='unknown'),
        ):
            data = copy.deepcopy(self.template)
            mutate(data)
            with self.assertRaises(ValueError):
                certlock.plan_community_template(data)

    def test_backup_failure_prevents_writes(self):
        plan = certlock.plan_community_template(self.template)
        with (patch.object(certlock, 'reg_export_all_rules', return_value={'certificates': []}), patch.object(
            certlock.os, 'makedirs', side_effect=PermissionError('read-only')),
            patch.object(certlock, 'reg_add_cert') as writer):
            with self.assertRaises(PermissionError):
                certlock.apply_template_plan(plan)
            writer.assert_not_called()

    def test_backup_binary_cert_and_partial_failure_are_reported(self):
        plan = certlock.plan_community_template(self.template)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'LOCALAPPDATA': tmp}), patch.object(
            certlock, 'reg_export_all_rules', return_value={'certificates': [{'cert_data': b'abc'}]}), patch.object(
            certlock, 'reg_add_cert', side_effect=[True, False, True, True]):
            report = certlock.apply_template_plan(plan)
            saved = json.loads(Path(report['backup']).read_text(encoding='utf-8'))
        self.assertEqual(saved['certificates'][0]['cert_data'], 'YWJj')
        self.assertEqual(len(report['added']), 3)
        self.assertEqual(len(report['failed']), 1)

    def test_wps_scan_read_failure_is_not_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'wps.exe').write_bytes(b'fixture')
            with patch.object(certlock, 'extract_cert_from_exe', return_value={'error': 'parse_error'}):
                with self.assertRaisesRegex(ValueError, '签名'):
                    certlock.scan_wps_signers(tmp)

    def test_cli_dry_run_does_not_elevate_repair_or_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'common.json'
            p.write_text(json.dumps(self.template), encoding='utf-8')
            with (patch.object(sys, 'argv', ['certlock', '--dry-run', '--template-import', str(p)]), patch.object(
                certlock, 'is_admin', return_value=False), patch.object(certlock, 'repair_legacy_rules') as repair,
                patch.object(certlock, 'reg_add_cert') as writer, patch.object(certlock, 'elevate') as elevate):
                certlock.main()
                repair.assert_not_called()
                writer.assert_not_called()
                elevate.assert_not_called()

    def test_expired_certificate_detection_is_not_silenced(self):
        old_cert = next(r for r in self.template['rules'] if r['description'] == '金山安全证书 1')
        expired, date = certlock._check_cert_expiry(old_cert['cert_data'])
        self.assertTrue(expired)
        self.assertEqual(date, '2024-05-30')

    def test_export_template_drops_unknown_fields_and_sanitizes_description(self):
        data = copy.deepcopy(self.template)
        data['exported_by'] = 'C:\\Users\\alice'
        data['exported_at'] = '2026-10-08 10:00:00'
        data['local_path'] = 'C:\\Users\\alice\\Desktop\\secret.txt'
        data['vendor_info']['website'] = 'https://example.com'
        data['vendor_info']['products'] = 'some product'
        data['vendor_info']['secret_note'] = 'C:\\Users\\alice\\secret'
        data['rules'][0]['description'] = '360 block C:\\Users\\alice\\secret.exe'
        data['rules'][0]['extra_field'] = 'should be dropped'

        out = certlock.build_shareable_template(data, [0])

        self.assertNotIn('exported_by', out)
        self.assertNotIn('exported_at', out)
        self.assertNotIn('local_path', out)
        self.assertNotIn('website', out['vendor_info'])
        self.assertNotIn('products', out['vendor_info'])
        self.assertNotIn('secret_note', out['vendor_info'])
        self.assertNotIn('extra_field', out['rules'][0])

        self.assertEqual(out['format_version'], '2.0')
        self.assertEqual(out['source'], 'CertLock')
        self.assertEqual(out['protection'], certlock.WPS_PROTECTION)
        self.assertEqual(out['rules'][0]['thumbprint'], self.template['rules'][0]['thumbprint'])
        self.assertEqual(out['rules'][0]['cert_data'], self.template['rules'][0]['cert_data'])

        self.assertNotIn('C:\\Users', out['rules'][0]['description'])
        self.assertIn('[PATH]', out['rules'][0]['description'])


if __name__ == '__main__':
    unittest.main()
