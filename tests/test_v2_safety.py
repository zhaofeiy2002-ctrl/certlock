import base64
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

import certlock


class V2SafetyTests(unittest.TestCase):
    def test_hash_writes_are_disabled(self):
        self.assertFalse(certlock.reg_add_hash("0" * 64, "test"))

    def test_certificate_thumbprint_must_match_der(self):
        blob = base64.b64encode(b"not a certificate").decode("ascii")
        with patch.object(certlock, "_import_to_trusted_publishers") as importer:
            self.assertFalse(certlock.reg_add_cert("0" * 40, blob, "test"))
        importer.assert_not_called()

    def test_certificate_thumbprint_check_accepts_matching_der(self):
        raw = b"certificate bytes for validation"
        thumbprint = hashlib.sha1(raw).hexdigest().upper()
        blob = base64.b64encode(raw).decode("ascii")
        with patch.object(certlock, "_import_to_trusted_publishers", return_value=False):
            self.assertFalse(certlock.reg_add_cert(thumbprint, blob, "test"))

    def test_template_does_not_export_legacy_hash_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = f"{temp_dir}\\template.json"
            count = certlock.export_community_template(output, [
                {"type": "cert", "thumbprint": "A", "cert_data": "B"},
                {"type": "hash", "hash": "C" * 64},
            ])
            with open(output, encoding="utf-8") as saved:
                template = json.load(saved)
        self.assertEqual(count, 1)
        self.assertEqual(template["rules"][0]["type"], "cert")


if __name__ == "__main__":
    unittest.main()
