#!/usr/bin/env python3
"""
MX-only ISO 20022 parser -> sanctions screening CSV (one row per message)

Outputs columns:
message_id, direction, format (MX), msg_type,
debtor_name, creditor_name,
dbtr_agt_bic, cdtr_agt_bic, intrmy_agt_bic_1,
remittance_70, sender_to_receiver_72, remittance_ustrd,
raw_payload_hash, parse_status, parse_errors

Usage examples:

1) Parse a folder of XML files:
python mx_to_sanctions_csv.py --in-dir ./mx_xml --out mx_parsed.csv

2) Parse an input CSV (message_id,payload_xml columns):
python mx_to_sanctions_csv.py --in-csv input_payloads.csv --out mx_parsed.csv

Optional:
--your-bics ABCDUS33,ABCDUS33XXX  (for direction inference)
"""

import argparse
import csv
import hashlib
import os
import re
from dataclasses import is_dataclass
from typing import Dict, List, Optional, Tuple

from xml.etree import ElementTree as ET

# xsdata parser (used by pyiso20022 models)
from xsdata.formats.dataclass.parsers import XmlParser


CSV_COLUMNS = [
    "message_id", "direction", "format", "msg_type",
    "debtor_name", "creditor_name",
    "dbtr_agt_bic", "cdtr_agt_bic", "intrmy_agt_bic_1",
    "remittance_70", "sender_to_receiver_72", "remittance_ustrd",
    "raw_payload_hash", "parse_status", "parse_errors",
]


# -----------------------------
# Utilities
# -----------------------------
def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def is_mx(payload: str) -> bool:
    p = (payload or "").lstrip()
    if not p.startswith("<"):
        return False
    return ("urn:iso:std:iso:20022" in p) or ("<Document" in p) or ("<Doc:" in p)

def safe_join(parts: List[str], sep: str = " | ") -> str:
    clean = [normalize_space(x) for x in parts if x and normalize_space(x)]
    return sep.join(clean)

def get_namespace_uri(root: ET.Element) -> str:
    # {namespace}Tag
    if root.tag.startswith("{"):
        return root.tag.split("}")[0].strip("{")
    return ""

def detect_msg_type_from_ns(ns_uri: str) -> str:
    """
    ISO 20022 namespaces often end with something like:
    ...:pacs.008.001.08
    ...:pacs.009.001.08
    """
    if not ns_uri:
        return ""
    tail = ns_uri.split(":")[-1]
    # Keep only typical message identifiers
    return tail[:50]

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


# -----------------------------
# ElementTree fallback extraction (works for any MX)
# -----------------------------
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

def parse_mx_fallback_et(xml_text: str) -> Tuple[Dict[str, str], List[str]]:
    """
    Best-effort extraction using XPath-like queries with namespaces.
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

    # Prefer first CdtTrfTxInf if present (common for pacs.*)
    cdt_trf = root.find(".//ns:CdtTrfTxInf", ns) if ns else root.find(".//CdtTrfTxInf")
    base = cdt_trf if cdt_trf is not None else root

    if ns:
        out["debtor_name"] = et_find_first_text(base, [".//ns:Dbtr/ns:Nm"], ns)
        out["creditor_name"] = et_find_first_text(base, [".//ns:Cdtr/ns:Nm"], ns)
        out["dbtr_agt_bic"] = et_find_first_text(base, [".//ns:DbtrAgt//ns:BICFI"], ns)
        out["cdtr_agt_bic"] = et_find_first_text(base, [".//ns:CdtrAgt//ns:BICFI"], ns)
        out["intrmy_agt_bic_1"] = et_find_first_text(base, [".//ns:IntrmyAgt1//ns:BICFI", ".//ns:IntrmyAgt//ns:BICFI"], ns)
        ustrd = et_find_all_text(base, ".//ns:RmtInf/ns:Ustrd", ns)
    else:
        out["debtor_name"] = et_find_first_text(base, [".//Dbtr/Nm"], {})
        out["creditor_name"] = et_find_first_text(base, [".//Cdtr/Nm"], {})
        out["dbtr_agt_bic"] = et_find_first_text(base, [".//DbtrAgt//BICFI"], {})
        out["cdtr_agt_bic"] = et_find_first_text(base, [".//CdtrAgt//BICFI"], {})
        out["intrmy_agt_bic_1"] = et_find_first_text(base, [".//IntrmyAgt1//BICFI", ".//IntrmyAgt//BICFI"], {})
        ustrd = et_find_all_text(base, ".//RmtInf/Ustrd", {})

    out["remittance_ustrd"] = safe_join(ustrd)

    if not out["debtor_name"]:
        errors.append("missing_dbtr_nm")
    if not out["creditor_name"]:
        errors.append("missing_cdtr_nm")
    if not out["remittance_ustrd"]:
        errors.append("missing_rmtinf_ustrd")

    return out, errors


# -----------------------------
# pyiso20022 + xsdata parsing (pacs.008, pacs.009)
# -----------------------------
def try_import_pacs_model(msg_type: str):
    """
    Returns (DocumentClass, root_attr_path_string) for supported types.
    We only support pacs.008 and pacs.009 here, as requested.
    """
    mt = (msg_type or "").lower()

    # These are common versions in the wild; you can add others if needed.
    # pyiso20022 naming often follows: pyiso20022.pacs.pacs_008_001_08
    # and: pyiso20022.pacs.pacs_009_001_08
    candidates = []
    if "pacs.008" in mt:
        candidates = [
            ("pyiso20022.pacs.pacs_008_001_08", "Document"),
            ("pyiso20022.pacs.pacs_008_001_07", "Document"),
            ("pyiso20022.pacs.pacs_008_001_10", "Document"),
        ]
    elif "pacs.009" in mt:
        candidates = [
            ("pyiso20022.pacs.pacs_009_001_08", "Document"),
            ("pyiso20022.pacs.pacs_009_001_07", "Document"),
            ("pyiso20022.pacs.pacs_009_001_10", "Document"),
        ]
    else:
        return None

    for module_name, cls_name in candidates:
        try:
            mod = __import__(module_name, fromlist=[cls_name])
            return getattr(mod, cls_name)
        except Exception:
            continue
    return None

def get_attr(obj, path: str):
    """
    Safe attribute walk: "A.B.C" returns None if any link missing.
    Supports list indexing with [0] in path segments.
    """
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None

        # list index support e.g. CdtTrfTxInf[0]
        m = re.fullmatch(r"([A-Za-z0-9_]+)\[(\d+)\]", part)
        if m:
            name, idx_s = m.group(1), m.group(2)
            cur = getattr(cur, name, None)
            if cur is None or not isinstance(cur, list):
                return None
            idx = int(idx_s)
            if idx >= len(cur):
                return None
            cur = cur[idx]
            continue

        cur = getattr(cur, part, None)
    return cur

def parse_mx_with_pyiso(xml_text: str) -> Tuple[Optional[Dict[str, str]], List[str]]:
    """
    Attempts model-based parsing for pacs.008 and pacs.009 using pyiso20022 + xsdata.
    If unsupported or fails, returns (None, errors) so caller can fall back to ET.
    """
    errors: List[str] = []

    # First, detect message type from namespace using ET quickly (no extraction)
    try:
        root = ET.fromstring(xml_text)
        ns_uri = get_namespace_uri(root)
        msg_type = detect_msg_type_from_ns(ns_uri)
    except Exception:
        return None, ["xml_parse_error_for_type_detection"]

    if not msg_type:
        return None, ["missing_msg_type"]

    DocumentClass = try_import_pacs_model(msg_type)
    if DocumentClass is None:
        return None, [f"unsupported_msg_type:{msg_type}"]

    parser = XmlParser()
    try:
        doc = parser.from_string(xml_text, DocumentClass)
    except Exception as e:
        return None, [f"pyiso_parse_error:{type(e).__name__}"]

    # For pacs.008, path: doc.FIToFICstmrCdtTrf.CdtTrfTxInf[0]
    # For pacs.009, often: doc.FIToFICstmrCdtTrf OR doc.FIToFIPmtStsRpt etc. but we’ll focus on pacs.009 credit transfer structures.
    # We will attempt common transaction containers.
    tx = (
        get_attr(doc, "FIToFICstmrCdtTrf.CdtTrfTxInf[0]") or
        get_attr(doc, "FICdtTrf.CdtTrfTxInf[0]") or
        get_attr(doc, "FIToFICdtTrf.CdtTrfTxInf[0]") or
        get_attr(doc, "FIToFIPmtStsRpt.OrgnlPmtInfAndSts[0].TxInfAndSts[0]")  # fallback style, may not have parties
    )

    if tx is None:
        return None, ["missing_cdt_trf_tx_inf"]

    # Pull fields with safe paths. These paths are typical for pacs credit transfers.
    debtor_name = get_attr(tx, "Dbtr.Nm") or ""
    creditor_name = get_attr(tx, "Cdtr.Nm") or ""

    dbtr_agt_bic = get_attr(tx, "DbtrAgt.FinInstnId.BICFI") or ""
    cdtr_agt_bic = get_attr(tx, "CdtrAgt.FinInstnId.BICFI") or ""

    # Some messages use IntrmyAgt1; others IntrmyAgt
    intrmy_agt_bic_1 = (
        get_attr(tx, "IntrmyAgt1.FinInstnId.BICFI") or
        get_attr(tx, "IntrmyAgt.FinInstnId.BICFI") or
        ""
    )

    # Remittance unstructured can be list of strings
    ustrd_val = get_attr(tx, "RmtInf.Ustrd")
    if isinstance(ustrd_val, list):
        remittance_ustrd = safe_join([str(x) for x in ustrd_val])
    elif isinstance(ustrd_val, str):
        remittance_ustrd = normalize_space(ustrd_val)
    else:
        remittance_ustrd = ""

    out = {
        "format": "MX",
        "msg_type": msg_type,
        "debtor_name": normalize_space(debtor_name),
        "creditor_name": normalize_space(creditor_name),
        "dbtr_agt_bic": normalize_space(dbtr_agt_bic),
        "cdtr_agt_bic": normalize_space(cdtr_agt_bic),
        "intrmy_agt_bic_1": normalize_space(intrmy_agt_bic_1),
        "remittance_70": "",
        "sender_to_receiver_72": "",
        "remittance_ustrd": remittance_ustrd,
    }

    if not out["debtor_name"]:
        errors.append("missing_dbtr_nm")
    if not out["creditor_name"]:
        errors.append("missing_cdtr_nm")
    if not out["remittance_ustrd"]:
        errors.append("missing_rmtinf_ustrd")

    return out, errors


# -----------------------------
# Unified per-message parse
# -----------------------------
def parse_one_mx(message_id: str, xml_text: str, your_bics: List[str]) -> Dict[str, str]:
    base = {c: "" for c in CSV_COLUMNS}
    base["message_id"] = message_id
    base["format"] = "MX"
    base["raw_payload_hash"] = sha256_text(xml_text)
    base["remittance_70"] = ""
    base["sender_to_receiver_72"] = ""

    if not is_mx(xml_text):
        base["parse_status"] = "FAIL"
        base["parse_errors"] = "not_mx_payload"
        base["direction"] = "UNKNOWN"
        base["msg_type"] = ""
        return base

    # Try model-based first
    parsed, errors = parse_mx_with_pyiso(xml_text)
    if parsed is None:
        # Fall back to ET extraction
        parsed, errors = parse_mx_fallback_et(xml_text)

    # direction
    direction = infer_direction_from_bics(parsed.get("dbtr_agt_bic", ""), parsed.get("cdtr_agt_bic", ""), your_bics)

    # status
    if any(e.startswith("xml_parse_error") for e in errors):
        status = "FAIL"
    else:
        status = "OK" if not errors else "PARTIAL"

    base.update(parsed)
    base["direction"] = direction
    base["parse_status"] = status
    base["parse_errors"] = ";".join(errors)

    return base


# -----------------------------
# Input readers
# -----------------------------
def read_xml_files(in_dir: str) -> List[Tuple[str, str]]:
    messages = []
    for fn in sorted(os.listdir(in_dir)):
        if not fn.lower().endswith(".xml"):
            continue
        path = os.path.join(in_dir, fn)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            xml_text = f.read()
        message_id = os.path.splitext(fn)[0]
        messages.append((message_id, xml_text))
    return messages

def read_input_csv(in_csv: str, id_col: str, payload_col: str) -> List[Tuple[str, str]]:
    messages = []
    with open(in_csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
        r = csv.DictReader(f)
        if id_col not in r.fieldnames or payload_col not in r.fieldnames:
            raise ValueError(f"Input CSV must include columns '{id_col}' and '{payload_col}'. Found: {r.fieldnames}")
        for row in r:
            messages.append((row[id_col], row[payload_col]))
    return messages


# -----------------------------
# Main
# -----------------------------
def main():
    ap = argparse.ArgumentParser(description="MX-only ISO 20022 parser to sanctions CSV schema.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--in-dir", help="Directory of .xml files (one message per file).")
    g.add_argument("--in-csv", help="CSV input with message_id and payload_xml columns.")
    ap.add_argument("--id-col", default="message_id", help="Input CSV column name for message id (default: message_id).")
    ap.add_argument("--payload-col", default="payload_xml", help="Input CSV column name for XML payload (default: payload_xml).")
    ap.add_argument("--your-bics", default="", help="Comma-separated list of your bank BICs for direction inference.")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    args = ap.parse_args()

    your_bics = [x.strip() for x in args.your_bics.split(",") if x.strip()]

    if args.in_dir:
        messages = read_xml_files(args.in_dir)
    else:
        messages = read_input_csv(args.in_csv, args.id_col, args.payload_col)

    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for message_id, xml_text in messages:
            row = parse_one_mx(message_id, xml_text, your_bics)
            w.writerow(row)

    print(f"Wrote {len(messages)} rows to {args.out}")

if __name__ == "__main__":
    main()
