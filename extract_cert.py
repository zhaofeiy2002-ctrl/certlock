"""
Extract X.509 signer certificate from a signed PE (.exe/.dll) file.
Outputs: Base64-encoded DER certificate, ready for SRP registry.
Pure Python - no PowerShell dependency.
"""
import sys
import struct
import base64

def extract_cert_from_pe(exe_path):
    """Extract the signer certificate from a PE file's PKCS#7 signature.
    Returns (der_bytes, subject_str, thumbprint_hex) or (None, None, None).
    """
    with open(exe_path, 'rb') as f:
        data = f.read()

    # --- Parse PE to find Certificate Table (Security Directory) ---
    if len(data) < 64:
        raise ValueError("File too small to be PE")

    # DOS header: offset 0x3C has e_lfanew (PE signature offset)
    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]

    # PE signature: "PE\0\0"
    pe_sig = data[pe_offset:pe_offset+4]
    if pe_sig != b'PE\x00\x00':
        raise ValueError("Not a valid PE file")

    # COFF header (20 bytes after PE sig)
    coff_offset = pe_offset + 4
    # SizeOfOptionalHeader at offset 16 in COFF header
    size_of_optional = struct.unpack_from('<H', data, coff_offset + 16)[0]

    # Optional header starts right after COFF header
    opt_offset = coff_offset + 20

    # Determine magic (PE32 vs PE32+)
    magic = struct.unpack_from('<H', data, opt_offset)[0]

    # DataDirectory[4] is the Certificate Table entry (IMAGE_DIRECTORY_ENTRY_SECURITY)
    # In PE32 (magic=0x10b): optional header is 96 bytes, data directories start at offset 96
    # In PE32+ (magic=0x20b): optional header is 112 bytes, data directories start at offset 112
    if magic == 0x10b:  # PE32
        dd_start = opt_offset + 96
    elif magic == 0x20b:  # PE32+
        dd_start = opt_offset + 112
    else:
        # ROM image (0x107) or unknown
        raise ValueError(f"Unknown PE magic: 0x{magic:04x}")

    # Certificate Table = DataDirectory[4], each entry is 8 bytes (VirtualAddress, Size)
    cert_dd_offset = dd_start + 4 * 8
    cert_va, cert_size = struct.unpack_from('<II', data, cert_dd_offset)

    if cert_size == 0 or cert_va == 0:
        raise ValueError("No digital signature (Certificate Table is empty)")

    # --- Read WIN_CERTIFICATE structure ---
    # dwLength (4), wRevision (2), wCertificateType (2), bCertificate[cert_size - 8]
    win_cert = data[cert_va:cert_va + cert_size]
    if len(win_cert) < 8:
        raise ValueError("WIN_CERTIFICATE too small")

    dw_length, w_revision, w_type = struct.unpack_from('<IHH', win_cert, 0)
    # w_type 0x0002 = WIN_CERT_TYPE_PKCS_SIGNED_DATA
    if w_type != 0x0002:
        raise ValueError(f"Expected PKCS_SIGNED_DATA (0x0002), got 0x{w_type:04x}")

    pkcs7_der = win_cert[8:dw_length]

    # --- Parse PKCS#7 SignedData to extract signer certificate ---
    # Use a minimal ASN.1 DER parser (no external dependency)
    signer_cert_der = extract_signer_cert_from_pkcs7(pkcs7_der)

    # Compute thumbprint (SHA1 hash of DER cert)
    import hashlib
    sha1 = hashlib.sha1(signer_cert_der).hexdigest().upper()

    # Parse subject
    subject = parse_x509_subject(signer_cert_der)

    return signer_cert_der, subject, sha1


def _read_tlv(der, offset):
    """Read a DER TLV (Tag-Length-Value) from offset. Returns (tag, length, value_offset, next_offset)."""
    tag = der[offset]
    offset += 1
    if offset >= len(der):
        raise ValueError("Unexpected end of DER")
    length = der[offset]
    offset += 1
    if length & 0x80:
        num_len_octets = length & 0x7F
        length = 0
        for _ in range(num_len_octets):
            length = (length << 8) | der[offset]
            offset += 1
    return tag, length, offset, offset + length


def _skip_tlv(der, offset):
    """Skip a complete TLV, return next offset."""
    _, _, _, next_off = _read_tlv(der, offset)
    return next_off


def _is_context_tag(der, offset, ctx_num):
    """Check if byte at offset is a context-specific tag [ctx_num]."""
    if offset >= len(der):
        return False
    return der[offset] == (0xA0 | ctx_num)


def _skip_element(der, offset):
    """Skip one ASN.1 element (TLV), return next offset."""
    _, _, _, next_off = _read_tlv(der, offset)
    return next_off


def extract_signer_cert_from_pkcs7(pkcs7_der):
    """Extract the signer certificate (end-entity, not intermediate CA)
    from a PKCS#7 SignedData DER blob.

    PKCS#7 SignedData structure:
      ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
      SignedData ::= SEQUENCE {
        version INTEGER,
        digestAlgorithms SET,
        contentInfo SEQUENCE,                   -- encapsulatedContentInfo
        certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
        crls [1] IMPLICIT SET OF CRL OPTIONAL,
        signerInfos SET OF SignerInfo
      }
    """
    der = pkcs7_der
    if len(der) < 10:
        raise ValueError("PKCS#7 too short")

    pos = 0
    # ContentInfo SEQUENCE
    tag, ci_len, ci_val, ci_end = _read_tlv(der, pos)
    if tag != 0x30:
        raise ValueError(f"Expected ContentInfo SEQUENCE, got 0x{tag:02X}")

    # Walk ContentInfo children: OID then [0] SignedData
    pos = ci_val
    while pos < ci_end and not _is_context_tag(der, pos, 0):
        pos = _skip_element(der, pos)
    if pos >= ci_end:
        raise ValueError("[0] SignedData not found in ContentInfo")

    # Enter [0] SignedData
    _, sd_len, sd_val, sd_end = _read_tlv(der, pos)

    # SignedData SEQUENCE
    pos = sd_val
    tag, seq_len, seq_val, seq_end = _read_tlv(der, pos)
    if tag != 0x30:
        raise ValueError(f"Expected SignedData SEQUENCE, got 0x{tag:02X}")

    # Collect all certificates by walking SignedData elements
    certs = []
    pos = seq_val
    while pos < seq_end:
        tag_byte = der[pos]
        if tag_byte == 0xA0:
            # [0] certificates — collect all cert SEQUENCEs inside
            _, certs_len, certs_val, certs_end = _read_tlv(der, pos)
            p = certs_val
            while p < certs_end:
                ct, clen, cv, cnx = _read_tlv(der, p)
                if ct == 0x30:
                    certs.append(der[p:cnx])
                p = cnx
            pos = certs_end
        else:
            # Skip all other elements (version INTEGER, digest SET,
            # contentInfo SEQUENCE, [1] crls, signerInfos SET)
            pos = _skip_element(der, pos)

    if not certs:
        raise ValueError("No certificates found in SignedData")

    # Pick the signer certificate (not intermediate CA)
    # Use heuristic: the end-entity cert usually does NOT have
    # known CA names in its Subject
    if len(certs) == 1:
        return certs[0]

    ca_patterns = ['DigiCert', 'VeriSign', 'GlobalSign', 'Sectigo', 'thawte',
                   'Certum', 'Entrust', 'Go Daddy', 'Let\'s Encrypt', 'Amazon',
                   'Symantec', 'GeoTrust', 'RapidSSL', 'Comodo', 'Microsoft']

    non_ca = []
    for c in certs:
        try:
            subj = parse_x509_subject(c)
            if not any(kw.lower() in subj.lower() for kw in ca_patterns):
                non_ca.append(c)
        except Exception:
            non_ca.append(c)

    if non_ca:
        # Pick the largest end-entity cert
        return max(non_ca, key=len)

    # All look like CAs — return the last one (usually end-entity)
    return certs[-1]


def parse_x509_subject(der_bytes):
    """Parse the Subject field from an X.509 certificate DER.
    Returns the subject DN string.
    """
    # X.509 Certificate: SEQUENCE { ... TBSCertificate, ... }
    # TBSCertificate: SEQUENCE { ... SEQUENCE { ... Subject ... } ... }
    #
    # Structure: Certificate.SEQuence -> TBSCertificate.SEquence -> [6] Subject (SEQUENCE of RDNs)
    # Subject is the 6th element in TBSCertificate (version [0] is 1st, serialNumber, signature, issuer, validity, subject)

    try:
        # Parse Certificate SEQUENCE
        tag, cert_len, cert_val, cert_end = _read_tlv(der_bytes, 0)
        if tag != 0x30:
            return "Unknown"

        # Parse TBSCertificate SEQUENCE (first element of Certificate)
        tbs_tag, tbs_len, tbs_val, tbs_end = _read_tlv(der_bytes, cert_val)
        if tbs_tag != 0x30:
            return "Unknown"

        offset = tbs_val
        # Element 0: [0] version (optional, explicit tag)
        if offset < tbs_end and der_bytes[offset] == 0xA0:
            offset = _skip_tlv(der_bytes, offset)
        # Element 1: serialNumber (INTEGER)
        offset = _skip_tlv(der_bytes, offset)
        # Element 2: signature (SEQUENCE)
        offset = _skip_tlv(der_bytes, offset)
        # Element 3: issuer (SEQUENCE)
        offset = _skip_tlv(der_bytes, offset)
        # Element 4: validity (SEQUENCE)
        offset = _skip_tlv(der_bytes, offset)
        # Element 5: subject (SEQUENCE)
        subject_val = offset
        subject_end = _skip_tlv(der_bytes, offset)

        # Now parse the Subject DN components
        return _parse_dn(der_bytes, subject_val, subject_end)
    except Exception:
        return "Unknown"


def _parse_dn(der, offset, end):
    """Parse a Distinguished Name SEQUENCE OF SET OF AttributeTypeAndValue."""
    parts = []
    try:
        pos = offset
        if pos < end and der[pos] == 0x30:  # Skip outer SEQUENCE
            tag, seq_len, seq_val, seq_end = _read_tlv(der, pos)
            pos = seq_val
            end = seq_end

        while pos < end:
            # Each RDN is a SET (0x31)
            if der[pos] != 0x31:
                pos += 1
                continue
            _, set_len, set_val, set_next = _read_tlv(der, pos)
            # Inside SET is a SEQUENCE (0x30) containing OID + STRING
            inner_pos = set_val
            while inner_pos < set_next:
                if der[inner_pos] != 0x30:
                    inner_pos += 1
                    continue
                _, sq_len, sq_val, sq_next = _read_tlv(der, inner_pos)
                # First element: OID
                oid_tag, oid_len, oid_val, oid_end = _read_tlv(der, sq_val)
                # Second element: value
                val_tag, val_len, val_val, val_end = _read_tlv(der, oid_end)

                # Decode string value
                try:
                    value = der[val_val:val_end].decode('utf-8', errors='replace')
                except Exception:
                    value = "<binary>"

                # Map common OIDs to short names
                oid_bytes = der[oid_val:oid_end]
                oid_str = _decode_oid(oid_bytes)

                if oid_str not in ('2.5.4.3', '2.5.4.10', '2.5.4.11', '2.5.4.6',
                                    '2.5.4.7', '2.5.4.8', '2.5.4.12', '2.5.4.97',
                                    '1.2.840.113549.1.9.1'):
                    inner_pos = sq_next
                    continue

                oid_map = {
                    '2.5.4.3':  'CN',
                    '2.5.4.6':  'C',
                    '2.5.4.7':  'L',
                    '2.5.4.8':  'S',
                    '2.5.4.10': 'O',
                    '2.5.4.11': 'OU',
                    '2.5.4.12': 'T',
                    '2.5.4.97': 'serialNumber',
                    '1.2.840.113549.1.9.1': 'E',
                }
                name = oid_map.get(oid_str, oid_str)
                parts.append(f"{name}={value}")
                inner_pos = sq_next
            pos = set_next

    except Exception as e:
        return f"ParseError({e})"

    return ', '.join(parts)


def _decode_oid(oid_bytes):
    """Decode BER-encoded OID bytes to dotted string."""
    if not oid_bytes:
        return ''
    oid_parts = []
    # First byte: first two components
    first = oid_bytes[0]
    oid_parts.append(str(first // 40))
    oid_parts.append(str(first % 40))
    # Remaining bytes: base-128 encoded
    value = 0
    for b in oid_bytes[1:]:
        if b & 0x80:
            value = (value << 7) | (b & 0x7F)
        else:
            value = (value << 7) | b
            oid_parts.append(str(value))
            value = 0
    return '.'.join(oid_parts)


# ============================================================
# CLI
# ============================================================
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <signed.exe> [output.txt]")
        sys.exit(1)

    exe_path = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        der_bytes, subject, thumbprint = extract_cert_from_pe(exe_path)
        b64 = base64.b64encode(der_bytes).decode('ascii')

        print(f"Subject:    {subject}")
        print(f"Thumbprint: {thumbprint}")
        print(f"DER length: {len(der_bytes)} bytes")
        print(f"Base64:     {len(b64)} chars")

        if out_file:
            with open(out_file, 'w') as f:
                f.write(b64)
            print(f"Saved to:   {out_file}")
        else:
            print(f"\n--- BASE64 CERT ---")
            print(b64)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
