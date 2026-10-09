"""Synthetic, in-memory signing fixtures. No certificate store is modified."""
import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID, ObjectIdentifier


def make_signed_fixture():
    now = datetime.datetime.now(datetime.timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def certificate(name, signing_key, serial, extra=False):
        dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(dn).issuer_name(dn)
                   .public_key(signing_key.public_key()).serial_number(serial)
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(signing_key.public_key()), False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True))
        if extra:
            builder = builder.add_extension(x509.UnrecognizedExtension(
                ObjectIdentifier('1.3.6.1.4.1.55555.1'), b'x' * 2048), False)
        return builder.sign(signing_key, hashes.SHA256())

    signer = certificate('Audit Actual Signer', key, 1)
    other = certificate('Audit Unrelated Certificate', other_key, 2, True)
    collision = certificate('Audit Actual Signer', other_key, 1, True)
    signed = (pkcs7.PKCS7SignatureBuilder().set_data(b'CertLock test fixture')
              .add_signer(signer, key, hashes.SHA256()).add_certificate(other)
              .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    return signed, signer.public_bytes(serialization.Encoding.DER), collision.public_bytes(serialization.Encoding.DER)


def make_pe(signature, duplicate=False):
    header = bytearray(512)
    header[:2] = b'MZ'
    struct.pack_into('<I', header, 0x3c, 64)
    header[64:68] = b'PE\0\0'
    struct.pack_into('<H', header, 84, 240)
    struct.pack_into('<H', header, 88, 0x20b)
    struct.pack_into('<I', header, 196, 16)
    record = struct.pack('<IHH', len(signature) + 8, 0x200, 2) + signature
    record += b'\0' * (-len(record) % 8)
    table = record * (2 if duplicate else 1)
    struct.pack_into('<II', header, 232, len(header), len(table))
    return bytes(header) + table
