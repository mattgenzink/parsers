#!/usr/bin/env python3
import argparse, csv, hashlib, re, html
from xml.etree import ElementTree as ET

csv.field_size_limit(50_000_000)

# ---- OUTPUT SCHEMA (extended) ----
CSV_COLUMNS = [
    "message_id","direction","format","msg_type",

    "debtor_name","creditor_name",
    "debtor_bic","creditor_bic",

    "dbtr_agt_bic","dbtr_agt_name",
    "cdtr_agt_bic","cdtr_agt_name",
    "intrmy_agt_bic_1",

    "debtor_address","creditor_address",
    "acct_owner_res_country",

    "intrbk_sttlm_ccy",

    "remittance_70","sender_to_receiver_72","remittance_ustrd",

    "raw_payload_hash","parse_status","parse_errors"
]

# ---- helpers ----
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
    head = p[:800]
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
    t = xml_text.lstrip()
    if "AppHdr" in t[:400] and re.search(r"</[^>]*AppHdr>\s*<[^>]*Document\b", t, flags=re.DOTALL):
        return "<Root>" + t + "</Root>", ["wrapped_root"]
    return xml_text, []

def find_first_by_localname(root: ET.Element, local: str):
    for el in root.iter():
        if strip_ns(el.tag) == local:
            return el
    return None

def find_all_by_localname(root: ET.Element, local: str):
    return [el for el in root.iter() if strip_ns(el.tag) == local]

def text_of_first_child(parent: ET.Element, child_local: str) -> str:
    if parent is None:
        return ""
    for el in parent:
        if strip_ns(el.tag) == child_local and el.text:
            return normalize_space(el.text)
    # if not direct child, search one level down
    el = find_first_by_localname(parent, child_local)
    return normalize_space(el.text) if (el is not None and el.text) else ""

def detect_msg_type(xml_text: str) -> str:
    m = re.search(r"(pacs|camt|pain)\.\d{3}\.\d{3}\.\d{2}", xml_text)
    return m.group(0) if m else ""

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

# ---- specific extractors ----
def extract_postal_address(party_el: ET.Element) -> str:
    """
    Pull AdrLine or structured address parts under PstlAdr.
    """
    if party_el is None:
        return ""
    pstl = find_first_by_localname(party_el, "PstlAdr")
    if pstl is None:
        return ""

    # Prefer AdrLine repeats
    adr_lines = [normalize_space(x.text) for x in find_all_by_localname(pstl, "AdrLine") if x.text]
    if adr_lines:
        return safe_join(adr_lines, sep=", ")

    # Else build from known components
    parts = []
    for key in ["StrtNm","BldgNb","PstCd","TwnNm","CtrySubDvsn","Ctry"]:
        val = text_of_first_child(pstl, key)
        if val:
            parts.append(val)
    return safe_join(parts, sep=", ")

def extract_party_country_of_residence(party_el: ET.Element) -> str:
    """
    Country of residence is usually 'CtryOfRes' under Dbtr/Cdtr (party element)
    or sometimes within Id structures. We take the first one we find under the party.
    """
    if party_el is None:
        return ""
    ctry = find_first_by_localname(party_el, "CtryOfRes")
    if ctry is not None and ctry.text:
        return normalize_space(ctry.text)
    return ""

def extract_party_bic(party_el: ET.Element) -> str:
    """
    Party BIC may appear under party Id: Pty/Id/OrgId/AnyBIC or Id/OrgId/AnyBIC.
    We search under the party element for AnyBIC.
    """
    if party_el is None:
        return ""
    anybic = find_first_by_localname(party_el, "AnyBIC")
    if anybic is not None and anybic.text:
        return normalize_space(anybic.text)
    return ""

def extract_agent_bic_and_name(scope: ET.Element, agent_local: str):
    """
    Extract BICFI and FinInstnId/Nm for agent elements like DbtrAgt, CdtrAgt.
    """
    agent = find_first_by_localname(scope, agent_local)
    if agent is None:
        return "", ""
    fin = find_first_by_localname(agent, "FinInstnId")
    if fin is None:
        return "", ""
    bic = ""
    bic_el = find_first_by_localname(fin, "BICFI")
    if bic_el is not None and bic_el.text:
        bic = normalize_space(bic_el.text)

    nm = ""
    nm_el = find_first_by_localname(fin, "Nm")
    if nm_el is not None and nm_el.text:
        nm = normalize_space(nm_el.text)

    return bic, nm

def extract_intrbk_sttlm_ccy(scope: ET.Element) -> str:
    """
    Interbank settlement currency often appears on IntrBkSttlmAmt Ccy attribute.
    Example: <IntrBkSttlmAmt Ccy="USD">123.45</IntrBkSttlmAmt>
    """
    amt = find_first_by_localname(scope, "IntrBkSttlmAmt")
    if amt is not None:
        # Attribute may be 'Ccy' (case sensitive)
        ccy = amt.attrib.get("Ccy") or amt.attrib.get("CCY") or amt.attrib.get("ccy")
        if ccy:
            return normalize_space(ccy)
    return ""

def extract_remittance(scope: ET.Element) -> str:
    """
    Remittance:
    - Prefer unstructured: RmtInf/Ustrd (repeat)
    - Fall back to structured: RmtInf/Strd/RfrdDocInf/Nb or AddtlRmtInf etc.
    We’ll concatenate whatever we can find without overengineering.
    """
    ustrd = []
    for rmt in find_all_by_localname(scope, "RmtInf"):
        ustrd.extend([normalize_space(x.text) for x in find_all_by_localname(rmt, "Ustrd") if x.text])

    if ustrd:
        return safe_join(ustrd)

    # Structured fallbacks (pick common narrative-like nodes)
    parts = []
    for key in ["AddtlRmtInf","Nb","Tp","CdOrPrtry","Issr"]:
        for el in find_all_by_localname(scope, key):
            if el.text:
                parts.append(normalize_space(el.text))
    return safe_join(parts)  # may be blank

# ---- main parse ----
def parse_mx(xml_text: str):
    errors = []
    out = {c:"" for c in CSV_COLUMNS}
    out["format"] = "MX"
    out["remittance_70"] = ""
    out["sender_to_receiver_72"] = ""

    xml_text, wrap_notes = wrap_if_two_roots(xml_text)

    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        out["parse_errors"] = ";".join(wrap_notes + [f"xml_parse_error:{type(e).__name__}"])
        out["parse_status"] = "FAIL"
        return out, wrap_notes + [f"xml_parse_error:{type(e).__name__}"]

    doc = find_first_by_localname(root, "Document")
    base = doc if doc is not None else root

    out["msg_type"] = detect_msg_type(xml_text) or strip_ns(base.tag)

    tx = find_first_by_localname(base, "CdtTrfTxInf")
    scope = tx if tx is not None else base

    # Parties
    dbtr = find_first_by_localname(scope, "Dbtr")
    cdtr = find_first_by_localname(scope, "Cdtr")

    out["debtor_name"] = text_of_first_child(dbtr, "Nm")
    out["creditor_name"] = text_of_first_child(cdtr, "Nm")

    out["debtor_address"] = extract_postal_address(dbtr)
    out["creditor_address"] = extract_postal_address(cdtr)

    out["debtor_bic"] = extract_party_bic(dbtr)
    out["creditor_bic"] = extract_party_bic(cdtr)

    # Agent BIC + Name
    out["dbtr_agt_bic"], out["dbtr_agt_name"] = extract_agent_bic_and_name(scope, "DbtrAgt")
    out["cdtr_agt_bic"], out["cdtr_agt_name"] = extract_agent_bic_and_name(scope, "CdtrAgt")

    # Intermediary
    intr1, _ = extract_agent_bic_and_name(scope, "IntrmyAgt1")
    intr, _ = extract_agent_bic_and_name(scope, "IntrmyAgt")
    out["intrmy_agt_bic_1"] = intr1 or intr

    # Interbank settlement currency
    out["intrbk_sttlm_ccy"] = extract_intrbk_sttlm_ccy(scope)

    # Account owner country of residence
    # If you mean debtor country of residence, capture debtor first, else creditor
    out["acct_owner_res_country"] = extract_party_country_of_residence(dbtr) or extract_party_country_of_residence(cdtr)

    # Remittance
    out["remittance_ustrd"] = extract_remittance(scope)

    # DQ flags
    if not out["debtor_name"]:
        errors.append("missing_dbtr_nm")
    if not out["creditor_name"]:
        errors.append("missing_cdtr_nm")
    if not out["remittance_ustrd"]:
        errors.append("missing_rmtinf")

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
    row["direction"] = infer_direction(row.get("dbtr_agt_bic",""), row.get("cdtr_agt_bic",""), your_bics)

    if any(e.startswith("xml_parse_error") for e in errs):
        row["parse_status"] = "FAIL"
    else:
        # treat missing remittance as PARTIAL, not FAIL
        hard_missing = [e for e in errs if e.startswith("missing_")]
        row["parse_status"] = "OK" if not hard_missing else "PARTIAL"

    row["parse_errors"] = ";".join(notes + errs)
    return row

def main():
    ap = argparse.ArgumentParser(description="MX-only parser (AppHdr + pacs:Document safe) with extra fields.")
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
