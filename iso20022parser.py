#!/usr/bin/env python3
"""
MX-only ISO 20022 parser (standard library only) -> sanctions screening CSV

Reads input CSV containing message_id + payload_xml (header name tolerant)
Writes output CSV with one row per message using schema:

message_id, direction, format, msg_type,
debtor_name, creditor_name,
dbtr_agt_bic, cdtr_agt_bic, intrmy_agt_bic_1,
remittance_70, sender_to_receiver_72, remittance_ustrd,
raw_payload_hash, parse_status, parse_errors

Usage (Windows PowerShell / CMD):
python mx_parser_free.py --in-csv .\\test\\parser_text.csv --out .\\test\\mx_parsed.csv --your-bics ABCDUS33,ABCDUS33XXX

Usage (Mac/Linux):
python3 mx_parser_free.py --in-csv ./test/parser_text.csv --out ./test/mx_parsed.csv --your-bics ABCDUS33,ABCDUS33XXX
"""

import argparse
import csv
import hashlib
import re
from xml.etree import ElementTree as ET
from typing import Dict, List, Tuple, Optional

# Allow very large XML fields inside CSV
csv.field_size_limit(50_000_000)

CSV_COLUMNS = [
    "message_id", "direction", "format", "msg_type",
    "debtor_name", "creditor_name",
    "dbtr_agt_bic", "cdtr_agt_bic", "intrmy_agt_bic_1",
    "remittance_70", "sender_to_receiver_72", "remittance_ustrd",
    "raw_payload_hash", "parse_status", "parse_errors",
]

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def safe_join(parts: List[str], sep: str = " | ") -> str:
    clean = [normalize_space(x) for x in parts if x and normalize_space(x)]
    return sep.join(clean)

def is_mx(payload: str) -> bool:
    p = (payload or "").lstrip()
    if not p.startswith("<"):
        return False
    # Typical ISO 20022 tells
    return ("urn:iso:std:iso:20022" in p) or ("<Document" in p) or ("<Doc:" in p)

def get_namespace_uri(root: ET.Element) -> str:
    if root.tag.startswith("{"):
        return root.tag.split("}")[0].strip("{")
    return ""

def detect_msg_type_from_ns(ns_uri: str) -> str:
    # Usually ends with pacs.008.001.08, pacs.009.001.08, etc.
    if not ns_uri:
        return ""
    tail = ns_uri.split(":")[-1]
    return tail[:50]

def et_find_first_text(node: ET.Element, xpaths: List[str], ns: Dict[str, str]) -> str:
    for xp in xpaths:
        el = node.find(xp, ns)
        if el is not None and el.text:
            return normalize_space(el.text)
    return ""

def et_find_all_text(node: ET.Element, xp: str, ns: Dict[str, str]) -> List[str]:
    out = []
    for el in node.findall(xp, ns):
        if el is not None and el.text:
            out.append(normalize_space(el.text))
    return out

def infer_direction_from_bics(dbtr_agt_bic: str, cdtr_agt_bic: str, your_bics: List[str]) -> str:
    if not your_bics:
        return "UNKNOWN"
    your = {b.upper() for b in your_bics if b}
    d = (dbtr_agt_bic or "").upper()
    c = (cdtr_agt_bic or "").upper()
    if d and d in your:
        return "OUTGOING"
    if c and c in your:
        return "INCOMING"
    return "UNKNOWN"

def parse_mx_et(xml_text: str) -> Tuple[Dict[str, str], List[str]]:
    """
    Best-effort extraction for any MX ISO 20022 message.
    """
    errors: List[str] = []
    out = {
        "format": "MX",
        "msg_type": "",
        "debtor_name": "",
        "creditor_name": "",
        "dbtr_agt_bic": "",
        "cdtr_agt_bic": "",
        "intrmy_agt_bic_1": "",
        "remittance_70": "",
        "sender_to_receiver_72": "",
        "remittance_ustrd": "",
    }

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        return out, [f"xml_parse_error:{type(e).__name__}"]

    ns_uri = get_namespace_uri(root)
    ns = {"ns": ns_uri} if ns_uri else {}
    out["msg_type"] = detect_msg_type_from_ns(ns_uri) or root.tag[:50]

    # Prefer first CdtTrfTxInf when present (most pacs messages)
    cdt_trf = root.find(".//ns:CdtTrfTxInf", ns) if ns else root.find(".//CdtTrfTxInf")
    base = cdt_trf if cdt_trf is not None else root

    if ns:
        out["debtor_name"] = et_find_first_text(base, [".//ns:Dbtr/ns:Nm"], ns)
        out["creditor_name"] = et_find_first_text(base, [".//ns:Cdtr/ns:Nm"], ns)
        out["dbtr_agt_bic"] = et_find_first_text(base, [".//ns:DbtrAgt//ns:BICFI"], ns)
        out["cdtr_agt_bic"] = et_find_first_text(base, [".//ns:CdtrAgt//ns:BICFI"], ns)
        out["intrmy_agt_bic_1"] = et_find_first_text(
            base,
            [".//ns:IntrmyAgt1//ns:BICFI", ".//ns:IntrmyAgt//ns:BICFI"],
            ns
        )
        ustrd = et_find_all_text(base, ".//ns:RmtInf/ns:Ustrd", ns)
    else:
        out["debtor_name"] = et_find_first_text(base, [".//Dbtr/Nm"], {})
        out["creditor_name"] = et_find_first_text(base, [".//Cdtr/Nm"], {})
        out["dbtr_agt_bic"] = et_find_first_text(base, [".//DbtrAgt//BICFI"], {})
        out["cdtr_agt_bic"] = et_find_first_text(base, [".//CdtrAgt//BICFI"], {})
        out["intrmy_agt_bic_1"] = et_find_first_text(
            base,
            [".//IntrmyAgt1//BICFI", ".//IntrmyAgt//BICFI"],
            {}
        )
        ustrd = et_find_all_text(base, ".//RmtInf/Ustrd", {})

    out["remittance_ustrd"] = safe_join(ustrd)

    # DQ flags (don’t fail parsing unless XML is invalid)
    if not out["debtor_name"]:
        errors.append("missing_dbtr_nm")
    if not out["creditor_name"]:
        errors.append("missing_cdtr_nm")
    if not out["remittance_ustrd"]:
        errors.append("missing_rmtinf_ustrd")

    return out, errors

def canonical_header(h: str) -> str:
    # strip BOM, trim, lower, replace spaces with underscore
    return (h or "").replace("\ufeff", "").strip().lower().replace(" ", "_")

def resolve_columns(fieldnames: List[str]) -> Tuple[str, str]:
    """
    Resolve message_id and payload_xml even if headers have spaces/BOM/casing differences.
    Returns the actual header strings used in DictReader row dict.
    """
    if not fieldnames:
        raise ValueError("Input CSV has no headers.")

    canon_to_real = {canonical_header(h): h for h in fieldnames}

    # Accept a few common variants
    id_candidates = ["message_id", "msg_id", "id", "messageid"]
    payload_candidates = ["payload_xml", "payload", "xml", "raw_payload", "payloadxml"]

    real_id = next((canon_to_real.get(c) for c in id_candidates if c in canon_to_real), None)
    real_payload = next((canon_to_real.get(c) for c in payload_candidates if c in canon_to_real), None)

    if not real_id or not real_payload:
        raise ValueError(
            f"Input CSV must include columns like message_id and payload_xml. "
            f"Found headers: {fieldnames}"
        )
    return real_id, real_payload

def parse_one(message_id: str, payload_xml: str, your_bics: List[str]) -> Dict[str, str]:
    row = {c: "" for c in CSV_COLUMNS}
    row["message_id"] = message_id
    row["format"] = "MX"
    row["raw_payload_hash"] = sha256_text(payload_xml or "")
    row["remittance_70"] = ""
    row["sender_to_receiver_72"] = ""

    if not (payload_xml or "").strip():
        row["parse_status"] = "FAIL"
        row["parse_errors"] = "blank_payload"
        row["direction"] = "UNKNOWN"
        return row

    if not is_mx(payload_xml):
        # Still output a row so you can quantify non-MX in the file
        row["parse_status"] = "FAIL"
        row["parse_errors"] = "not_mx_payload"
        row["direction"] = "UNKNOWN"
        return row

    parsed, errors = parse_mx_et(payload_xml)

    row.update(parsed)
    row["direction"] = infer_direction_from_bics(parsed.get("dbtr_agt_bic",""), parsed.get("cdtr_agt_bic",""), your_bics)

    if any(e.startswith("xml_parse_error") for e in errors):
        row["parse_status"] = "FAIL"
    else:
        row["parse_status"] = "OK" if not errors else "PARTIAL"

    row["parse_errors"] = ";".join(errors)
    return row

def main():
    ap = argparse.ArgumentParser(description="MX-only parser (free, standard library) to sanctions CSV schema.")
    ap.add_argument("--in-csv", required=True, help="Input CSV path (contains message_id + payload_xml).")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    ap.add_argument("--your-bics", default="", help="Comma-separated list of your bank BICs for direction inference.")
    args = ap.parse_args()

    your_bics = [x.strip() for x in args.your_bics.split(",") if x.strip()]

    with open(args.in_csv, "r", encoding="utf-8-sig", errors="ignore", newline="") as f_in:
        r = csv.DictReader(f_in)
        real_id_col, real_payload_col = resolve_columns(r.fieldnames)

        with open(args.out, "w", encoding="utf-8", newline="") as f_out:
            w = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
            w.writeheader()

            count = 0
            for i, in_row in enumerate(r, start=1):
                mid = (in_row.get(real_id_col) or f"row_{i}").strip()
                payload = in_row.get(real_payload_col) or ""
                out_row = parse_one(mid, payload, your_bics)
                w.writerow(out_row)
                count += 1

    print(f"Wrote {count} rows to {args.out}")

if __name__ == "__main__":
    main()

