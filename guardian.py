#!/usr/bin/env python3
import sys
import re
import json
import ssl
import subprocess
import argparse
import urllib.request

def query_txt_records(domain):
    records = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=TXT"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "TAVARDT-Guardian"})
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for a in data.get("Answer", []):
                val = a.get("data", "").strip('"')
                if val:
                    records.append(val)
    except Exception:
        pass

    if records:
        return records

    try:
        proc = subprocess.run(["nslookup", "-type=TXT", domain], capture_output=True, timeout=5)
        raw = proc.stdout.decode("latin1", errors="ignore")
        for line in raw.splitlines():
            line_str = line.strip()
            if "text =" in line_str:
                val = line_str.split("text =", 1)[1].strip().strip('"')
                records.append(val)
            elif line_str.startswith('"') and line_str.endswith('"'):
                records.append(line_str.strip('"'))
    except Exception:
        pass

    return records

def parse_dmarc(records):
    for r in records:
        if "v=DMARC1" in r:
            tags = {}
            for part in r.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    tags[k.strip().lower()] = v.strip()
            return {"raw": r, "tags": tags}
    return None

def parse_spf(records):
    for r in records:
        if r.startswith("v=spf1") or "v=spf1 " in r:
            parts = r.split()
            qual = "none"
            for p in parts:
                if p in ["-all", "~all", "?all", "+all"]:
                    qual = p
            return {"raw": r, "parts": parts, "qualifier": qual}
    return None

def check_dkim(domain, selector):
    query = f"{selector}._domainkey.{domain}"
    records = query_txt_records(query)
    for r in records:
        if "v=DKIM1" in r or "p=" in r:
            return {"found": True, "raw": r, "query": query}
    return {"found": False, "raw": None, "query": query}

def evaluate(dmarc, spf, dkim):
    score = 0
    recs = []

    if not dmarc:
        recs.append("Enregistrement DMARC introuvable. Le domaine est vulnérable aux attaques d usurpation.")
    else:
        tags = dmarc.get("tags", {})
        p = tags.get("p", "").lower()
        if p == "reject":
            score += 45
        elif p == "quarantine":
            score += 35
            recs.append("Politique DMARC sur p=quarantine. Recommandation de passer à p=reject pour un blocage complet.")
        elif p == "none":
            score += 15
            recs.append("Politique DMARC configurée sur p=none (mode surveillance). Passez à p=quarantine ou p=reject.")
        else:
            recs.append("Politique DMARC configurée sur p=none (mode surveillance). Passez à p=quarantine ou p=reject.")

        if "rua" in tags:
            score += 10
        else:
            recs.append("Balise rua absente dans DMARC. Aucun rapport agrégé ne sera transmis.")

    if not spf:
        recs.append("Enregistrement SPF introuvable. Tout serveur peut émettre des messages au nom du domaine.")
    else:
        qual = spf.get("qualifier", "")
        if qual == "-all":
            score += 30
        elif qual == "~all":
            score += 20
            recs.append("Qualificateur SPF configuré sur ~all (softfail). Transitionnez vers -all (hardfail).")
        elif qual == "?all":
            score += 10
            recs.append("Qualificateur SPF configuré sur ?all (neutre). Modifiez vers -all ou ~all.")
        elif qual == "+all":
            score += 0
            recs.append("Qualificateur SPF configuré sur +all. Autorise explicitement tout serveur sur Internet.")
        else:
            score += 10

    if dkim and dkim.get("found"):
        score += 15
    else:
        recs.append("Enregistrement DKIM introuvable pour le sélecteur spécifié.")

    score = min(score, 100)
    if score >= 85:
        status = "Conforme (Politiques Strictes Actives)"
    elif score >= 50:
        status = "Attention (Politiques Permissives ou Incomplètes)"
    else:
        status = "Critique (Vulnérable à l Usurpation et au Spoofing)"

    return score, status, recs

def main():
    parser = argparse.ArgumentParser(description="TAVARDT France: Auditeur de Sécurité Messagerie (DMARC, SPF, DKIM)")
    parser.add_argument("domain", help="Target domain to inspect")
    parser.add_argument("--selector", default="default", help="DKIM selector to verify")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    domain = args.domain.strip()
    dmarc = parse_dmarc(query_txt_records(f"_dmarc.{domain}"))
    spf = parse_spf(query_txt_records(domain))
    dkim = check_dkim(domain, args.selector)
    score, status, recs = evaluate(dmarc, spf, dkim)

    if args.json:
        payload = {
            "domain": domain,
            "security_score": score,
            "status": status,
            "dmarc": dmarc,
            "spf": spf,
            "dkim": dkim,
            "recommendations": recs
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    border = "=" * 76
    print(border)
    print(f" TAVARDT FRANCE: AUDITEUR DE SÉCURITÉ MESSAGERIE (DMARC, SPF, DKIM)")
    print(border)
    print(f" Domain: {domain}")
    print(f" Score de Sécurité: {score}/100")
    print(f" Diagnostic Général: {status}")
    print("-" * 76)
    print(f" Enregistrement DMARC: {dmarc['raw'] if dmarc else 'N/A'}")
    print(f" Enregistrement SPF: {spf['raw'] if spf else 'N/A'}")
    print(f" Enregistrement DKIM ({args.selector}): {dkim['raw'] if dkim.get('found') else 'N/A'}")
    print("-" * 76)
    print(f" Recommandations Techniques:")
    if recs:
        for r in recs:
            print(f"   * {r}")
    else:
        print(f"   * Configuration robuste. Aucune vulnérabilité critique identifiée.")
    print(border)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python guardian.py <domain> [--selector <name>] [--json]")
        sys.exit(1)
    main()
