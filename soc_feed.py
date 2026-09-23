#!/usr/bin/env python3
"""
SOC FEED ELITE — Alimentateur automatique de ~/soc-brain
Sources : MITRE ATT&CK, CISA KEV, NVD CVE, RSS Blogs, Sigma Rules, Abuse.ch

Usage :
  python3 soc_feed.py                         → mise à jour intelligente (skip si frais)
  python3 soc_feed.py --force                 → forcer le re-téléchargement de tout
  python3 soc_feed.py --source mitre          → une source précise
  python3 soc_feed.py --source rss --force    → forcer une source précise
  python3 soc_feed.py --status                → voir l'âge de chaque source
"""

import os
import re
import time
import argparse
import requests
import feedparser
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ===================== CONFIG =====================
SOC_BRAIN_PATH = Path(os.path.expanduser("~/soc-brain"))
LOG_FILE       = SOC_BRAIN_PATH / "_feed_log.txt"
TIMEOUT        = 20

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

PATHS = {
    "mitre":    SOC_BRAIN_PATH / "mitre_attack",
    "cisa":     SOC_BRAIN_PATH / "cisa_kev",
    "nvd":      SOC_BRAIN_PATH / "nvd_cve",
    "rss":      SOC_BRAIN_PATH / "threat_blogs",
    "sigma":    SOC_BRAIN_PATH / "sigma_rules",
    "abuse":    SOC_BRAIN_PATH / "abuse_ch",
    "playbook": SOC_BRAIN_PATH / "playbooks",
}

FRESHNESS_FILES = {
    "mitre":     PATHS["mitre"]    / "_index_mitre.txt",
    "cisa":      PATHS["cisa"]     / "_all_cisa_kev.txt",
    "nvd":       PATHS["nvd"]      / "_nvd_last_run.txt",
    "rss":       PATHS["rss"]      / "_rss_last_run.txt",
    "sigma":     PATHS["sigma"]    / "sigma_rules_soc.txt",
    "abuse":     PATHS["abuse"]    / "_abuse_last_run.txt",
    "playbooks": PATHS["playbook"] / "ransomware_response.txt",
}

MAX_AGE_DAYS = {
    "mitre":     30,
    "cisa":       7,
    "nvd":        7,
    "rss":        1,
    "sigma":     14,
    "abuse":      1,
    "playbooks": 999,
}

# RSS — avec User-Agent header pour éviter les blocages
RSS_FEEDS = {
    "thedfirreport":      "https://thedfirreport.com/feed/",
    "malwarebytes":       "https://www.malwarebytes.com/blog/feed/",
    "unit42_palo":        "https://unit42.paloaltonetworks.com/feed/",
    "crowdstrike":        "https://www.crowdstrike.com/blog/feed/",
    "bleepingcomputer":   "https://www.bleepingcomputer.com/feed/",
    "sans_isc":           "https://isc.sans.edu/rssfeed_full.xml",
    "schneier":           "https://www.schneier.com/feed/atom/",
    "elastic_security":   "https://www.elastic.co/security-labs/rss/feed.xml",
    "microsoft_security": "https://www.microsoft.com/en-us/security/blog/feed/",
    "recorded_future":    "https://www.recordedfuture.com/feed",
    "sekoia":             "https://blog.sekoia.io/feed/",
    "talos_intel":        "https://blog.talosintelligence.com/rss/",
}
# ==================================================


# ===================== UTILITAIRES =====================

def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def make_dirs():
    for p in PATHS.values():
        p.mkdir(parents=True, exist_ok=True)
    SOC_BRAIN_PATH.mkdir(parents=True, exist_ok=True)


def file_age_days(filepath) -> float:
    p = Path(filepath)
    if not p.exists():
        return 9999.0
    return (time.time() - p.stat().st_mtime) / 86400


def is_fresh(source_key: str) -> bool:
    ffile  = FRESHNESS_FILES.get(source_key)
    maxage = MAX_AGE_DAYS.get(source_key, 7)
    if ffile is None:
        return False
    return file_age_days(ffile) < maxage


def format_age(days: float) -> str:
    if days >= 9999:
        return "jamais téléchargé"
    if days < 1:
        return f"{days * 24:.0f}h"
    return f"{days:.1f} jour(s)"


def http_get_with_retry(url, retries=3, wait=5, **kwargs):
    """GET avec retry automatique en cas d'erreur réseau."""
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, **kwargs)
            r.raise_for_status()
            return r
        except requests.exceptions.ConnectionError as e:
            log(f"  ⚠️  Tentative {attempt}/{retries} échouée (connexion) : {e}")
            if attempt < retries:
                time.sleep(wait)
        except requests.exceptions.HTTPError as e:
            log(f"  ⚠️  HTTP error {e}")
            return None
        except Exception as e:
            log(f"  ⚠️  Erreur inattendue : {e}")
            if attempt < retries:
                time.sleep(wait)
    return None


# ===================== STATUS =====================

def show_status():
    print("\n" + "="*58)
    print("  SOC FEED — ÉTAT DES SOURCES")
    print("="*58)
    print(f"  {'SOURCE':<12} {'ÂGE':<20} {'MAX':<8} {'STATUT'}")
    print("-"*58)

    for source, ffile in FRESHNESS_FILES.items():
        age     = file_age_days(ffile)
        maxage  = MAX_AGE_DAYS.get(source, 7)
        age_str = format_age(age)
        max_str = f"{maxage}j"

        if age >= 9999:
            status = "❌ ABSENT"
        elif age < maxage:
            status = "✅ FRAIS"
        elif age < maxage * 1.5:
            status = "⚠️  BIENTÔT PÉRIMÉ"
        else:
            status = "🔴 PÉRIMÉ"

        print(f"  {source:<12} {age_str:<20} {max_str:<8} {status}")

    print("="*58 + "\n")


# ===================== MITRE ATT&CK =====================

def fetch_mitre(force=False):
    if not force and is_fresh("mitre"):
        log(f"⏭️  MITRE ATT&CK — frais ({format_age(file_age_days(FRESHNESS_FILES['mitre']))}), skip.")
        return

    log("🔴 MITRE ATT&CK — téléchargement en cours...")
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    r = http_get_with_retry(url, retries=3, wait=10)
    if not r:
        log("❌ MITRE — impossible de télécharger après 3 tentatives")
        return

    try:
        data = r.json()
    except Exception as e:
        log(f"❌ MITRE JSON parse error : {e}")
        return

    techniques = [
        obj for obj in data.get("objects", [])
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False)
    ]

    index_lines = []
    count = 0

    for tech in techniques:
        name         = tech.get("name", "unknown")
        tech_id      = ""
        description  = tech.get("description", "")
        platforms    = ", ".join(tech.get("x_mitre_platforms", []))
        detection    = tech.get("x_mitre_detection", "")
        data_sources = ", ".join(tech.get("x_mitre_data_sources", []))

        for ref in tech.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break

        tactic = ", ".join([p.get("phase_name", "") for p in tech.get("kill_chain_phases", [])])

        safe_name = name.replace("/", "_").replace(" ", "_").replace(":", "")
        filename  = PATHS["mitre"] / f"{tech_id}_{safe_name}.txt"

        content = f"""MITRE ATT&CK TECHNIQUE
======================
ID          : {tech_id}
Nom         : {name}
Tactique(s) : {tactic}
Plateformes : {platforms}
Sources de données : {data_sources}

DESCRIPTION
-----------
{description}

DÉTECTION
---------
{detection}

SOURCE : MITRE ATT&CK Enterprise — https://attack.mitre.org/techniques/{tech_id}/
DATE_IMPORT : {datetime.now().strftime("%Y-%m-%d")}
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)

        index_lines.append(f"{tech_id} | {tactic} | {name}")
        count += 1

    with open(PATHS["mitre"] / "_index_mitre.txt", "w", encoding="utf-8") as f:
        f.write("INDEX MITRE ATT&CK ENTERPRISE\n")
        f.write(f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write("\n".join(sorted(index_lines)))

    log(f"✅ MITRE ATT&CK — {count} techniques écrites")


# ===================== CISA KEV =====================

def fetch_cisa(force=False):
    if not force and is_fresh("cisa"):
        log(f"⏭️  CISA KEV — frais ({format_age(file_age_days(FRESHNESS_FILES['cisa']))}), skip.")
        return

    log("🟠 CISA KEV — téléchargement en cours...")
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    r = http_get_with_retry(url, retries=3, wait=5)
    if not r:
        log("❌ CISA — impossible de télécharger")
        return

    try:
        data = r.json()
    except Exception as e:
        log(f"❌ CISA JSON parse error : {e}")
        return

    vulns = data.get("vulnerabilities", [])
    lines = [
        "CISA KNOWN EXPLOITED VULNERABILITIES",
        f"Catalogue version : {data.get('catalogVersion', 'N/A')}",
        f"Date de mise à jour : {data.get('dateReleased', 'N/A')}",
        f"Total : {len(vulns)} vulnérabilités activement exploitées",
        f"Import : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "\n" + "=" * 60 + "\n"
    ]

    by_vendor = {}
    for v in vulns:
        vendor = v.get("vendorProject", "Unknown")
        by_vendor.setdefault(vendor, []).append(v)

    for vendor, items in sorted(by_vendor.items()):
        vendor_file = PATHS["cisa"] / f"cisa_{vendor.replace(' ','_').replace('/','_')}.txt"
        vendor_lines = [f"CISA KEV — {vendor}\n{'='*50}\n"]
        for v in sorted(items, key=lambda x: x.get("dateAdded", ""), reverse=True):
            block = f"""CVE         : {v.get('cveID','')}
Produit     : {v.get('product','')}
Ajouté le   : {v.get('dateAdded','')}
Date limite : {v.get('dueDate','')}
Description : {v.get('shortDescription','')}
Action      : {v.get('requiredAction','')}
Notes       : {v.get('notes','')}
---
"""
            vendor_lines.append(block)
            lines.append(block)

        with open(vendor_file, "w", encoding="utf-8") as f:
            f.write("\n".join(vendor_lines))

    with open(PATHS["cisa"] / "_all_cisa_kev.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log(f"✅ CISA KEV — {len(vulns)} vulnérabilités enregistrées")


# ===================== NVD CVE =====================

def fetch_nvd(force=False):
    if not force and is_fresh("nvd"):
        log(f"⏭️  NVD CVE — frais ({format_age(file_age_days(FRESHNESS_FILES['nvd']))}), skip.")
        return

    log("🟡 NVD CVE — téléchargement (90 derniers jours, CVSS CRITICAL)...")

    # Fix deprecation warning : utiliser timezone-aware datetime
    end_date   = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=90)

    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={start_date.strftime('%Y-%m-%dT00:00:00.000')}"
        f"&pubEndDate={end_date.strftime('%Y-%m-%dT23:59:59.000')}"
        f"&cvssV3Severity=CRITICAL"
    )

    # NVD est souvent instable — on attend 6s entre tentatives
    r = http_get_with_retry(url, retries=4, wait=6)
    if not r:
        log("❌ NVD — impossible de télécharger après 4 tentatives")
        log("   → NVD est parfois hors ligne. Réessaie plus tard avec : python3 ~/soc_feed.py --source nvd")
        return

    try:
        data = r.json()
    except Exception as e:
        log(f"❌ NVD JSON parse error : {e}")
        return

    items = data.get("vulnerabilities", [])
    lines = [
        "NVD CVE CRITIQUES (CVSS >= 9.0) — 90 derniers jours",
        f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Total : {len(items)}",
        "\n" + "=" * 60 + "\n"
    ]

    for item in items:
        cve     = item.get("cve", {})
        cve_id  = cve.get("id", "")
        desc_en = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            "No description"
        )
        published = cve.get("published", "")
        metrics   = cve.get("metrics", {})
        score = vector = "N/A"

        for key in ["cvssMetricV31", "cvssMetricV30"]:
            m = metrics.get(key, [])
            if m:
                score  = m[0].get("cvssData", {}).get("baseScore", "N/A")
                vector = m[0].get("cvssData", {}).get("vectorString", "N/A")
                break

        lines.append(f"""CVE         : {cve_id}
Publié le   : {published[:10]}
CVSS Score  : {score}
Vecteur     : {vector}
Description : {desc_en[:500]}
NVD Link    : https://nvd.nist.gov/vuln/detail/{cve_id}
---
""")

    with open(PATHS["nvd"] / f"nvd_critical_{end_date.strftime('%Y%m')}.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    with open(PATHS["nvd"] / "_nvd_last_run.txt", "w", encoding="utf-8") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"CVE récupérés : {len(items)}\n")

    log(f"✅ NVD — {len(items)} CVE critiques enregistrés")


# ===================== RSS BLOGS =====================

def fetch_rss_feed(name: str, url: str) -> list:
    """
    Télécharge un flux RSS en utilisant requests d'abord,
    puis feedparser pour parser — contourne les blocages User-Agent.
    """
    try:
        # Pré-télécharger avec requests (headers réalistes)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code != 200:
            return []

        # Parser le contenu téléchargé
        feed = feedparser.parse(r.content)
        entries = feed.get("entries", [])
        return entries[:20]

    except Exception as e:
        log(f"  ❌ {name} — erreur fetch : {e}")
        return []


def fetch_rss(force=False):
    if not force and is_fresh("rss"):
        log(f"⏭️  RSS Blogs — frais ({format_age(file_age_days(FRESHNESS_FILES['rss']))}), skip.")
        return

    log("🟢 RSS Blogs — téléchargement en cours...")
    total   = 0
    success = 0

    for name, url in RSS_FEEDS.items():
        entries = fetch_rss_feed(name, url)

        if not entries:
            log(f"  ⚠️  {name} — aucun article (feed vide ou inaccessible)")
            time.sleep(1)
            continue

        lines = [
            f"BLOG SÉCURITÉ : {name.upper()}",
            f"Source : {url}",
            f"Mis à jour : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 60 + "\n"
        ]

        for entry in entries:
            title   = entry.get("title", "No title")
            link    = entry.get("link", "")
            date    = entry.get("published", entry.get("updated", ""))
            summary = entry.get("summary", "")

            if not summary:
                content_list = entry.get("content", [])
                summary = content_list[0].get("value", "") if content_list else ""

            # Nettoyer le HTML
            summary = re.sub(r"<[^>]+>", " ", summary)
            summary = re.sub(r"&[a-z]+;", " ", summary)
            summary = re.sub(r"\s+", " ", summary).strip()[:1000]

            lines.append(f"""TITRE   : {title}
DATE    : {date}
LIEN    : {link}
RÉSUMÉ  : {summary}
---
""")

        with open(PATHS["rss"] / f"{name}.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        count  = len(entries)
        total += count
        success += 1
        log(f"  ✅ {name} — {count} articles")
        time.sleep(1.5)  # pause entre chaque feed

    # Fichier témoin (créé même si 0 articles pour éviter de re-tenter en boucle)
    with open(PATHS["rss"] / "_rss_last_run.txt", "w", encoding="utf-8") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Feeds réussis : {success}/{len(RSS_FEEDS)}\n")
        f.write(f"Articles récupérés : {total}\n")

    log(f"✅ RSS — {total} articles depuis {success}/{len(RSS_FEEDS)} feeds")


# ===================== SIGMA RULES =====================

# ===================== SIGMA RULES — FONCTION CORRIGÉE =====================
# REMPLACE fetch_sigma() dans soc_feed.py (lignes 482-548)
# BUG CORRIGÉ : filtre "hayabusa/" retiré — il bloquait 100% des règles SigmaHQ

def fetch_sigma(force=False):
    if not force and is_fresh("sigma"):
        log(f"⏭️  Sigma Rules — frais ({format_age(file_age_days(FRESHNESS_FILES['sigma']))}), skip.")
        return

    log("🔵 Sigma Rules — téléchargement en cours...")

    r = http_get_with_retry(
        "https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1",
        retries=3, wait=5
    )
    if not r:
        log("❌ Sigma — impossible de récupérer l'index GitHub")
        return

    try:
        tree = r.json().get("tree", [])
    except Exception as e:
        log(f"❌ Sigma JSON parse error : {e}")
        return

    # Priorité : windows et linux — les plus utiles pour un SOC
    priority_cats = ["windows", "linux"]
    other_cats    = ["network", "web", "cloud"]

    # CORRECTION : suppression du filtre "hayabusa/" qui bloquait tout
    # SigmaHQ/sigma n'a pas de dossier hayabusa/ — ce filtre donnait 0 résultats
    priority_rules = [
        item for item in tree
        if item["path"].endswith(".yml")
        and any(f"/{cat}/" in item["path"] for cat in priority_cats)
    ][:400]

    other_rules = [
        item for item in tree
        if item["path"].endswith(".yml")
        and any(f"/{cat}/" in item["path"] for cat in other_cats)
        and item not in priority_rules
    ][:100]

    rule_files = priority_rules + other_rules  # max 500 règles
    log(f"  📋 {len(rule_files)} règles sélectionnées (windows/linux + network/web/cloud)...")

    lines = [
        "SIGMA DETECTION RULES — SigmaHQ",
        "Source : https://github.com/SigmaHQ/sigma",
        f"Généré le : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Règles sélectionnées : {len(rule_files)}",
        "=" * 60 + "\n"
    ]

    count = 0
    for item in rule_files:
        r2 = http_get_with_retry(
            f"https://raw.githubusercontent.com/SigmaHQ/sigma/master/{item['path']}",
            retries=2, wait=3
        )
        if r2 and r2.status_code == 200:
            lines.append(f"--- FICHIER : {item['path']} ---\n{r2.text}\n")
            count += 1
        time.sleep(0.5)  # légèrement réduit pour accélérer

    with open(PATHS["sigma"] / "sigma_rules_soc.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log(f"✅ Sigma — {count} règles enregistrées dans sigma_rules_soc.txt")

# ===================== ABUSE.CH (sources sans auth) =====================

def fetch_abuse(force=False):
    if not force and is_fresh("abuse"):
        log(f"⏭️  Abuse.ch — frais ({format_age(file_age_days(FRESHNESS_FILES['abuse']))}), skip.")
        return

    log("🟣 Abuse.ch & Threat Intel — téléchargement en cours...")

    # Sources 100% gratuites sans authentification
    feeds = {
        # Feodo Tracker — IPs de botnet C2 (Emotet, Qakbot, etc.)
        "feodotracker_c2": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.csv",
            "desc": "IPs C2 botnet (Emotet, Qakbot, Dridex)"
        },
        # URLhaus — URLs malveillantes (ne nécessite pas d'auth pour le CSV)
        "urlhaus_csv": {
            "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
            "desc": "URLs malveillantes récentes (format CSV)"
        },
        # ThreatFox — IOC (IPs, URLs, hashes) sans auth
        "threatfox_ioc": {
            "url": "https://threatfox.abuse.ch/export/csv/recent/",
            "desc": "IOC récents ThreatFox (IPs, URLs, hashes)"
        },
        # SSL Blacklist — certificats malveillants
        "sslbl_aggressive": {
            "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv",
            "desc": "IPs avec certificats SSL malveillants"
        },
        # CINS Army — IPs malveillantes connues (source externe complémentaire)
        "emerging_threats_compromised": {
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "desc": "IPs compromises Emerging Threats"
        },
    }

    success = 0
    for name, config in feeds.items():
        r = http_get_with_retry(config["url"], retries=3, wait=3)
        if not r:
            log(f"  ❌ {name} — impossible de télécharger")
            continue

        out_path = PATHS["abuse"] / f"{name}_{datetime.now().strftime('%Y%m')}.txt"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"THREAT INTEL — {name.upper()}\n")
            f.write(f"Description : {config['desc']}\n")
            f.write(f"Source      : {config['url']}\n")
            f.write(f"Récupéré le : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            f.write("=" * 60 + "\n\n")
            f.write(r.text[:100000])  # max 100KB par fichier

        size_kb = len(r.text) // 1024
        log(f"  ✅ {name} — {size_kb}KB")
        success += 1
        time.sleep(1)

    with open(PATHS["abuse"] / "_abuse_last_run.txt", "w", encoding="utf-8") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Feeds réussis : {success}/{len(feeds)}\n")

    log(f"✅ Abuse.ch & Threat Intel — {success}/{len(feeds)} feeds récupérés")


# ===================== PLAYBOOKS SOC =====================

def create_playbooks(force=False):
    if not force and is_fresh("playbooks"):
        log("⏭️  Playbooks — déjà présents, skip.")
        return

    log("📋 Playbooks SOC — génération...")

    playbooks = {
        "ransomware_response.txt": """PLAYBOOK : RÉPONSE À UN RANSOMWARE
===================================
PHASE 1 — CONTAINMENT (0-30 min)
- Isoler immédiatement les machines affectées du réseau
- Désactiver les comptes compromis dans AD
- Bloquer la communication C2 identifiée au niveau firewall
- Snapshot des machines affectées avant toute action

PHASE 2 — IDENTIFICATION (30-120 min)
- Identifier le vecteur initial (phishing ? RDP exposé ? VPN ?)
- Vérifier les logs : auth.log, Windows Event 4624/4625/4776
- Chercher les IOC dans SIEM : nouveaux processus, services, registry keys
- Identifier le ransomware (soumettre sample à VirusTotal, ID Ransomware)
- Rechercher dans CISA KEV si la CVE exploitée est connue

COMMANDES DE TRIAGE LINUX
- ps aux | grep -E "(crypt|enc|ransom)"
- find / -name "*.locked" -o -name "README_DECRYPT*" 2>/dev/null
- last -n 50 | head
- journalctl -xe --since "2 hours ago" | grep -i "ssh|auth|fail"
- netstat -tulnp

COMMANDES DE TRIAGE WINDOWS
- Get-Process | Where-Object {$_.CPU -gt 50}
- Get-ScheduledTask | Where-Object {$_.State -eq "Running"}
- net user /domain
- wevtutil qe Security /q:"*[System[EventID=4625]]" /c:50 /f:text

PHASE 3 — ÉRADICATION
- Supprimer le malware identifié
- Réinitialiser TOUS les mots de passe compromis
- Patcher la vulnérabilité exploitée
- Revérifier les règles firewall et VPN

PHASE 4 — RECOVERY
- Restaurer depuis backup sain (vérifier intégrité)
- Monitorer intensément 72h post-recovery
- Documenter timeline complète

IOC TYPES À CHERCHER
- Processus vssadmin.exe (suppression shadow copies)
- wbadmin delete backup
- bcdedit /set {default} recoveryenabled No
- PowerShell encoded commands
- LSASS access (credential dumping)
""",
        "phishing_response.txt": """PLAYBOOK : RÉPONSE À UN PHISHING
==================================
DÉCLENCHEURS
- Utilisateur signale un email suspect
- Alerte SIEM sur URL malveillante cliquée
- Alerte EDR sur processus enfant d'Outlook/Teams

TRIAGE INITIAL (0-15 min)
- Récupérer l'email original (headers complets)
- Analyser les headers : Return-Path, Received, X-Originating-IP
- Vérifier SPF/DKIM/DMARC : dig TXT domaine.com
- Soumettre URL/pièce jointe à VirusTotal, URLScan.io, Any.run

ANALYSE DE L'EMAIL
- Extraire tous les URLs et les vérifier
- Identifier si credential harvesting ou malware delivery
- Vérifier si l'expéditeur est usurpé (spoofing)

SI LIEN CLIQUÉ
- Isoler la machine de l'utilisateur
- Vérifier proxy logs pour URL visitée
- Chercher dans EDR : nouveaux processus post-click
- Vérifier si credentials soumis (alerte sur MFA/connexions inhabituelles)
- Reset immédiat des credentials potentiellement compromis

COMMANDES D'INVESTIGATION
- grep "URL_MALVEILLANTE" /var/log/proxy/access.log
- Windows: Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} | Select -First 20
- Analyser Prefetch : PECmd.exe -d "C:\\Windows\\Prefetch"

CONTAINMENT SI COMPROMIS
- Bloquer domaine malveillant au niveau DNS et proxy
- Révoquer les sessions actives de l'utilisateur
- Forcer MFA re-enrollment si token compromis
""",
        "lateral_movement_detection.txt": """PLAYBOOK : DÉTECTION LATERAL MOVEMENT
=======================================
INDICATEURS CLÉS
- Connexions RDP/SMB inhabituelles entre postes
- Pass-the-Hash (Event ID 4624 type 3 + NTLM)
- PsExec ou outils d'admin à distance
- Kerberoasting (Event ID 4769 avec RC4)
- WMI remote execution

WINDOWS EVENT IDS CRITIQUES
4624  - Logon réussi (type 3 = réseau, type 10 = remote)
4625  - Logon échoué
4648  - Logon avec credentials explicites
4672  - Privilèges spéciaux assignés
4688  - Création de processus (avec command line si activé)
4697  - Service installé
4776  - NTLM auth
4768  - Kerberos TGT request
4769  - Kerberos service ticket request
5140  - Accès partage réseau

REQUÊTES SIEM (KQL/SPL style)
# Pass-the-Hash
EventID:4624 AND LogonType:3 AND AuthPackage:NTLM AND NOT SourceIP:127.0.0.1

# Kerberoasting
EventID:4769 AND TicketEncryptionType:0x17

# PsExec
process_name:psexesvc.exe OR CommandLine:*psexec*

LINUX — DÉTECTION PIVOTING
- /var/log/auth.log : SSH de machine à machine
- ss -tulnp : ports en écoute inhabituels
- ps auxf : arbres de processus suspects
- cat /proc/net/tcp : connexions actives (hex vers décimal)

SIGMA RULE ASSOCIÉE : process_creation_psexec_lateral_movement
""",
        "incident_response_checklist.txt": """CHECKLIST INCIDENT RESPONSE UNIVERSELLE
========================================
□ RÉCEPTION DE L'ALERTE
  □ Horodater la réception (UTC)
  □ Identifier la source (SIEM ? EDR ? Utilisateur ?)
  □ Évaluer la criticité initiale (P1/P2/P3/P4)
  □ Notifier le responsable SOC si P1/P2

□ TRIAGE INITIAL
  □ Confirmer que c'est un vrai incident (pas faux positif)
  □ Identifier les systèmes/utilisateurs affectés
  □ Déterminer si l'incident est en cours ou passé
  □ Sauvegarder les preuves initiales (logs, screenshots)

□ CONTAINMENT
  □ Isoler les systèmes compromis si nécessaire
  □ Bloquer les IOC au niveau réseau/endpoint
  □ Désactiver les comptes compromis
  □ Documenter chaque action avec timestamp

□ INVESTIGATION
  □ Collecter les logs (Windows Events, syslog, proxy, DNS)
  □ Analyser la timeline des événements
  □ Identifier le vecteur initial d'infection
  □ Rechercher la persistance (cron, services, autorun, tâches planifiées)
  □ Vérifier les connexions sortantes (C2 ?)
  □ Identifier les données potentiellement exfiltrées

□ ÉRADICATION
  □ Supprimer le malware/backdoor
  □ Éliminer la persistance
  □ Réinitialiser les credentials
  □ Patcher les vulnérabilités exploitées

□ RECOVERY
  □ Restaurer depuis backup sain
  □ Vérifier intégrité des systèmes restaurés
  □ Monitoring renforcé 72h

□ POST-INCIDENT
  □ Rédiger le rapport d'incident
  □ Lessons learned
  □ Mettre à jour les règles de détection
  □ Partager les IOC avec l'équipe
"""
    }

    for filename, content in playbooks.items():
        with open(PATHS["playbook"] / filename, "w", encoding="utf-8") as f:
            f.write(content)

    log(f"✅ Playbooks — {len(playbooks)} playbooks générés")


# ===================== MAIN =====================

def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC Feed Elite — Alimentateur automatique intelligent"
    )
    parser.add_argument(
        "--source",
        type=str,
        choices=["mitre", "cisa", "nvd", "rss", "sigma", "abuse", "playbooks", "atomic", "hayabusa", "anssi", "til", "all"],
        default="all",
        help="Source à mettre à jour (défaut : all)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Forcer le re-téléchargement même si les données sont encore fraîches"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Afficher l'état de fraîcheur de chaque source et quitter"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    make_dirs()

    if args.status:
        show_status()
        return

    log(f"\n{'='*55}")
    log(f"SOC FEED ELITE — démarrage (source={args.source}, force={args.force})")
    log(f"{'='*55}")

    if args.force:
        log("⚠️  Mode FORCE activé — re-téléchargement complet")

    dispatch = {
        "mitre":     fetch_mitre,
        "cisa":      fetch_cisa,
        "nvd":       fetch_nvd,
        "rss":       fetch_rss,
        "sigma":     fetch_sigma,
        "abuse":     fetch_abuse,
        "playbooks": create_playbooks,
        "atomic":    fetch_atomic_red_team,
        "hayabusa":  fetch_hayabusa,
        "anssi":     fetch_anssi,
        "til":       fetch_til,
    }

    if args.source == "all":
        for name, func in dispatch.items():
            try:
                func(force=args.force)
            except Exception as e:
                log(f"❌ Erreur dans {name} : {e}")
    else:
        func = dispatch.get(args.source)
        if func:
            try:
                func(force=args.force)
            except Exception as e:
                log(f"❌ Erreur : {e}")

    log(f"\n✅ SOC FEED ELITE — terminé.")
    log(f"   Si nouvelles données : python3 ~/soc_ask_v2.py --rebuild\n")
    show_status()




# ===================== ATOMIC RED TEAM =====================

def fetch_atomic_red_team(force=False):
    path = PATHS.get("atomic", SOC_BRAIN_PATH / "atomic_red_team")
    path.mkdir(parents=True, exist_ok=True)
    freshness_file = path / "_atomic_last_run.txt"

    if not force and file_age_days(freshness_file) < 14:
        log(f"⏭️  Atomic Red Team — frais, skip.")
        return

    log("🔴 Atomic Red Team — téléchargement en cours...")

    r = http_get_with_retry(
        "https://api.github.com/repos/redcanaryco/atomic-red-team/git/trees/master?recursive=1",
        retries=3, wait=5
    )
    if not r:
        log("❌ Atomic Red Team — impossible de récupérer l'index")
        return

    tree = r.json().get("tree", [])
    yaml_files = [
        item for item in tree
        if item["path"].endswith(".yaml")
        and "atomics/T" in item["path"]
    ][:200]

    log(f"  📋 {len(yaml_files)} techniques sélectionnées...")
    count = 0

    for item in yaml_files:
        r2 = http_get_with_retry(
            f"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/{item['path']}",
            retries=2, wait=3
        )
        if r2:
            fname = item["path"].replace("/", "_")
            with open(path / f"{fname}.txt", "w", encoding="utf-8") as f:
                f.write(f"ATOMIC RED TEAM — {item['path']}\n")
                f.write(f"Source : https://github.com/redcanaryco/atomic-red-team\n")
                f.write("=" * 60 + "\n\n")
                f.write(r2.text)
            count += 1
        time.sleep(0.5)

    with open(freshness_file, "w") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Fichiers récupérés : {count}\n")

    log(f"✅ Atomic Red Team — {count} techniques enregistrées")


# ===================== HAYABUSA RULES =====================

def fetch_hayabusa(force=False):
    path = PATHS.get("hayabusa", SOC_BRAIN_PATH / "hayabusa_rules")
    path.mkdir(parents=True, exist_ok=True)
    freshness_file = path / "_hayabusa_last_run.txt"

    if not force and file_age_days(freshness_file) < 14:
        log(f"⏭️  Hayabusa Rules — frais, skip.")
        return

    log("🔵 Hayabusa Rules — téléchargement en cours...")

    r = http_get_with_retry(
        "https://api.github.com/repos/Yamato-Security/hayabusa-rules/git/trees/main?recursive=1",
        retries=3, wait=5
    )
    if not r:
        log("❌ Hayabusa — impossible de récupérer l'index")
        return

    tree = r.json().get("tree", [])
    rule_files = [
        item for item in tree
        if item["path"].endswith(".yml")
        and "hayabusa/" in item["path"]
    ][:300]

    log(f"  📋 {len(rule_files)} règles sélectionnées...")
    count = 0

    for item in rule_files:
        r2 = http_get_with_retry(
            f"https://raw.githubusercontent.com/Yamato-Security/hayabusa-rules/main/{item['path']}",
            retries=2, wait=3
        )
        if r2:
            fname = item["path"].replace("/", "_")
            with open(path / f"{fname}.txt", "w", encoding="utf-8") as f:
                f.write(f"HAYABUSA RULE — {item['path']}\n")
                f.write(f"Source : https://github.com/Yamato-Security/hayabusa-rules\n")
                f.write("=" * 60 + "\n\n")
                f.write(r2.text)
            count += 1
        time.sleep(0.5)

    with open(freshness_file, "w") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Fichiers récupérés : {count}\n")

    log(f"✅ Hayabusa — {count} règles enregistrées")


# ===================== ANSSI =====================

def fetch_anssi(force=False):
    path = PATHS.get("anssi", SOC_BRAIN_PATH / "anssi")
    path.mkdir(parents=True, exist_ok=True)
    freshness_file = path / "_anssi_last_run.txt"

    if not force and file_age_days(freshness_file) < 7:
        log(f"⏭️  ANSSI — frais, skip.")
        return

    log("🇫🇷 ANSSI — téléchargement flux RSS en cours...")

    feeds = {
        "anssi_actualite": "https://www.cert.ssi.gouv.fr/actualite/feed/",
        "anssi_alerte":    "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "anssi_avis":      "https://www.cert.ssi.gouv.fr/avis/feed/",
    }

    total = 0
    for name, url in feeds.items():
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code != 200:
                log(f"  ⚠️  {name} — HTTP {r.status_code}")
                continue

            feed = feedparser.parse(r.content)
            entries = feed.get("entries", [])

            lines = [
                f"ANSSI — {name.upper()}",
                f"Source : {url}",
                f"Mis à jour : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                "=" * 60 + "\n"
            ]

            for entry in entries[:30]:
                title   = entry.get("title", "")
                link    = entry.get("link", "")
                date    = entry.get("published", "")
                summary = entry.get("summary", "")
                summary = re.sub(r"<[^>]+>", " ", summary)
                summary = re.sub(r"\s+", " ", summary).strip()[:1000]

                lines.append(f"""TITRE   : {title}
DATE    : {date}
LIEN    : {link}
RÉSUMÉ  : {summary}
---
""")

            with open(path / f"{name}.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

            total += len(entries)
            log(f"  ✅ {name} — {len(entries)} entrées")
            time.sleep(1)

        except Exception as e:
            log(f"  ❌ {name} — erreur : {e}")

    with open(freshness_file, "w") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Entrées récupérées : {total}\n")

    log(f"✅ ANSSI — {total} entrées enregistrées")


# ===================== THREAT INTELLIGENCE COLLECTIVE =====================

def fetch_til(force=False):
    path = PATHS.get("til", SOC_BRAIN_PATH / "threat_intel_collective")
    path.mkdir(parents=True, exist_ok=True)
    freshness_file = path / "_til_last_run.txt"

    if not force and file_age_days(freshness_file) < 7:
        log(f"⏭️  TIL — frais, skip.")
        return

    log("🟠 Threat Intelligence Collective — téléchargement...")

    r = http_get_with_retry(
        "https://api.github.com/repos/threat-intelligence-collective/til/git/trees/main?recursive=1",
        retries=3, wait=5
    )
    if not r:
        log("❌ TIL — impossible de récupérer l'index")
        return

    tree = r.json().get("tree", [])
    md_files = [
        item for item in tree
        if item["path"].endswith(".md")
    ][:200]

    log(f"  📋 {len(md_files)} fichiers sélectionnés...")
    count = 0

    for item in md_files:
        r2 = http_get_with_retry(
            f"https://raw.githubusercontent.com/threat-intelligence-collective/til/main/{item['path']}",
            retries=2, wait=3
        )
        if r2:
            fname = item["path"].replace("/", "_")
            with open(path / f"{fname}.txt", "w", encoding="utf-8") as f:
                f.write(f"THREAT INTEL COLLECTIVE — {item['path']}\n")
                f.write(f"Source : https://github.com/threat-intelligence-collective/til\n")
                f.write("=" * 60 + "\n\n")
                f.write(r2.text)
            count += 1
        time.sleep(0.5)

    with open(freshness_file, "w") as f:
        f.write(f"Dernière exécution : {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Fichiers récupérés : {count}\n")

    log(f"✅ TIL — {count} fichiers enregistrés")

if __name__ == "__main__":
    main()
