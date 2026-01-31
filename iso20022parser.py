#!/usr/bin/env python3
import argparse, csv, hashlib, re, html
from xml.etree import ElementTree as ET

csv.field_size_limit(50_000_000)

CSV_COLUMNS = [
    "message_id","direction","format","msg_type",
    "debtor_name","creditor_name",
    "dbtr_agt_bic","cdtr_agt_bic","intrmy_agt_bic_1",
    "remittance_70","sender_to_receiver_72","remittance_ustrd",
    "raw_payload_hash","parse_status","parse_errors"
]

def sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8", errors="ignore")).hexdigest()

def normalize_space(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def safe_join(parts, sep=" | "):
    clean = [normalize_space(x) for x in parts if x and normalize_space(x)]
    return sep.join(clean)

def canonical_header(h: str) -> str:
    return (h or "").replace("\ufeff","").strip().lower().replace(" ", "_")

def resolve_columns(fieldnames):
    if not fieldnames:
        raise ValueError("Input CSV has no headers.")
    canon_to_real = {canonical_header(h): h for h in fieldnames}
    id_candidates = ["message_id","msg_id","id","messageid"]
    payload_candidates = ["payload_xml","payload","xml","raw_payload","payloadxml"]
    real_id = next((canon_to_real.get(c) for c in id_candidates if c in canon_to_real), None)
    real_payload = next((canon_to_real.get(c) for c in payload_candidates if c in canon_to_real), None)
    if not real_id or not real_payload:
        raise ValueError(f"Missing required columns. Found headers: {fieldnames}")
    return real_id, real_payload

def strip_ns(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag

def looks_like_mx(payload: str) -> bool:
    p = (payload or "").lstrip()
    if not p.startswith("<"):
        return False
    head = p[:500]
    return ("AppHdr" in head) or ("Document" in head) or ("urn:iso:std:iso:20022" in p)

def normalize_payload_xml(payload: str):
    notes = []
    p = (payload or "").lstrip()
    if "&lt;" in p and "&gt;" in p:
        un = html.unescape(p)
        if un.lstrip().startswith("<"):
            notes.append("html_unescape")
            p = un.lstrip()
    return p, notes

def wrap_if_two_roots(xml_text: str):
    """
    If xml_text has two top-level elements (e.g., <AppHdr>...</AppHdr><pacs:Document>...</pacs:Document>),
    wrap them in a synthetic root so ET can parse it.
    """
    t = xml_text.lstrip()
    # Heuristic: starts with AppHdr and later contains a second '<...:Document'
    if "AppHdr" in t[:200] and re.search(r"</[^>]*AppHdr>\s*<[^>]*Document\b", t, flags=re.DOTALL):
        return "<Root>" + t + "</Root>", ["wrapped_root"]
    return xml_text, []

def find_first_by_localname(root: ET.Element, local: str):
    for el in root.iter():
        if strip_ns(el.tag) == local:
            return el
    return None

def find_all_text_by_localpath(root: ET.Element, locals_path):
    out = []
    parent = {c: p for p in root.iter() for c in p}
    for el in root.iter():
        if strip_ns(el.tag) != locals_path[-1]:
            continue
        cur = el
        ok = True
        for i in range(len(locals_path)-2, -1, -1):
            cur = parent.get(cur)
            if cur is None or strip_ns(cur.tag) != locals_path[i]:
                ok = False
                break
        if ok and el.text:
            out.append(normalize_space(el.text))
    return out

def detect_msg_type(xml_text: str) -> str:
    m = re.search(r"(pacs|camt|pain)\.\d{3}\.\d{3}\.\d{2}", xml_text)
    return m.group(0) if m else ""

def bic_from_agent(scope: ET.Element, agent_local: str) -> str:
    agent = find_first_by_localname(scope, agent_local)
    if agent is None:
        return ""
    fin = find_first_by_localname(agent, "FinInstnId")
    if fin is None:
        return ""
    bic = find_first_by_localname(fin, "BICFI")
    return normalize_space(bic.text) if (bic is not None and bic.text) else ""

def infer_direction(dbtr_agt_bic, cdtr_agt_bic, your_bics):
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

def parse_mx(xml_text: str):
    errors = []
    out = {
        "format":"MX","msg_type":"",
        "debtor_name":"","creditor_name":"",
        "dbtr_agt_bic":"","cdtr_agt_bic":"","intrmy_agt_bic_1":"",
        "remittance_70":"","sender_to_receiver_72":"","remittance_ustrd":""
    }

    xml_text, wrap_notes = wrap_if_two_roots(xml_text)

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        return out, wrap_notes + [f"xml_parse_error:{type(e).__name__}"]

    # Prefer the Document element even if it's <pacs:Document>
    doc = find_first_by_localname(root, "Document")
    base = doc if doc is not None else root

    out["msg_type"] = detect_msg_type(xml_text) or strip_ns(base.tag)

    # Focus on first credit transfer transaction if present
    tx = find_first_by_localname(base, "CdtTrfTxInf")
    scope = tx if tx is not None else base

    dbtr = find_first_by_localname(scope, "Dbtr")
    if dbtr is not None:
        nm = find_first_by_localname(dbtr, "Nm")
        out["debtor_name"] = normalize_space(nm.text) if (nm is not None and nm.text) else ""

    cdtr = find_first_by_localname(scope, "Cdtr")
    if cdtr is not None:
        nm = find_first_by_localname(cdtr, "Nm")
        out["creditor_name"] = normalize_space(nm.text) if (nm is not None and nm.text) else ""

    out["dbtr_agt_bic"] = bic_from_agent(scope, "DbtrAgt")
    out["cdtr_agt_bic"] = bic_from_agent(scope, "CdtrAgt")
    out["intrmy_agt_bic_1"] = bic_from_agent(scope, "IntrmyAgt1") or bic_from_agent(scope, "IntrmyAgt")

    ustrd = find_all_text_by_localpath(scope, ["RmtInf","Ustrd"])
    out["remittance_ustrd"] = safe_join(ustrd)

    if not out["debtor_name"]:
        errors.append("missing_dbtr_nm")
    if not out["creditor_name"]:
        errors.append("missing_cdtr_nm")
    if not out["remittance_ustrd"]:
        errors.append("missing_rmtinf_ustrd")

    return out, wrap_notes + errors

def parse_one(message_id: str, payload: str, your_bics):
    row = {c:"" for c in CSV_COLUMNS}
    row["message_id"] = message_id
    row["format"] = "MX"
    row["raw_payload_hash"] = sha256_text(payload)
    row["remittance_70"] = ""
    row["sender_to_receiver_72"] = ""

    if not (payload or "").strip():
        row["parse_status"] = "FAIL"
        row["parse_errors"] = "blank_payload"
        row["direction"] = "UNKNOWN"
        return row

    payload_norm, notes = normalize_payload_xml(payload)

    if not looks_like_mx(payload_norm):
        row["parse_status"] = "FAIL"
        row["parse_errors"] = "not_mx_payload"
        row["direction"] = "UNKNOWN"
        return row

    parsed, errs = parse_mx(payload_norm)
    row.update(parsed)
    row["direction"] = infer_direction(parsed.get("dbtr_agt_bic",""), parsed.get("cdtr_agt_bic",""), your_bics)

    if any(e.startswith("xml_parse_error") for e in errs):
        row["parse_status"] = "FAIL"
    else:
        row["parse_status"] = "OK" if not errs else "PARTIAL"

    row["parse_errors"] = ";".join(notes + errs)
    return row

def main():
    ap = argparse.ArgumentParser(description="MX-only parser (AppHdr + pacs:Document sibling safe) -> sanctions CSV.")
    ap.add_argument("--in-csv", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--your-bics", default="")
    args = ap.parse_args()

    your_bics = [x.strip() for x in args.your_bics.split(",") if x.strip()]

    with open(args.in_csv, "r", encoding="utf-8-sig", errors="ignore", newline="") as f_in:
        r = csv.DictReader(f_in)
        id_col, payload_col = resolve_columns(r.fieldnames)

        with open(args.out, "w", encoding="utf-8", newline="") as f_out:
            w = csv.DictWriter(f_out, fieldnames=CSV_COLUMNS)
            w.writeheader()

            count = 0
            for i, in_row in enumerate(r, start=1):
                mid = (in_row.get(id_col) or f"row_{i}").strip()
                payload = in_row.get(payload_col) or ""
                w.writerow(parse_one(mid, payload, your_bics))
                count += 1

    print(f"Wrote {count} rows to {args.out}")

if __name__ == "__main__":
    main()

