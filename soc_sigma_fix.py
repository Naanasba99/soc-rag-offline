#!/usr/bin/env python3
"""
soc_sigma_fix.py — Réindexation des règles Sigma en fichiers individuels
────────────────────────────────────────────────────────────────────────
Problème : les règles Sigma sont dans un fichier compilé sigma_rules_soc.txt
           → 1 chunk pour 3000 règles = retrieval très dilué

Solution  : extraire chaque règle YAML en fichier individuel
            → 3000 chunks individuels = retrieval précis par règle

Usage :
  python3.13 soc_sigma_fix.py --check    # voir l'état actuel
  python3.13 soc_sigma_fix.py --extract  # extraire les règles en fichiers
  python3.13 soc_sigma_fix.py --rebuild  # re-indexer dans ChromaDB
"""

import os
import re
import argparse
import yaml
from pathlib import Path

SIGMA_BRAIN_DIR    = Path.home() / "soc-brain" / "sigma_rules"
SIGMA_EXTRACTED_DIR = Path.home() / "soc-brain" / "sigma_extracted"


def check_state():
    """Vérifie l'état actuel de l'indexation Sigma"""
    print("\n📊 État indexation Sigma\n")

    # Fichier compilé
    compiled = SIGMA_BRAIN_DIR / "sigma_rules_soc.txt"
    if compiled.exists():
        size = compiled.stat().st_size / 1024 / 1024
        print(f"  📄 Fichier compilé : sigma_rules_soc.txt ({size:.1f} MB)")
        # Compter les règles
        content = compiled.read_text(errors="ignore")
        count = content.count("title:")
        print(f"  📌 Règles estimées dans le fichier : {count}")
    else:
        print("  ❌ sigma_rules_soc.txt non trouvé")

    # Fichiers YAML individuels
    if SIGMA_EXTRACTED_DIR.exists():
        yamls = list(SIGMA_EXTRACTED_DIR.glob("*.yml"))
        print(f"  📁 Fichiers YAML extraits : {len(yamls)}")
    else:
        print("  📁 Dossier sigma_extracted : non créé")

    # Fichiers YAML dans sigma_rules/
    yamls_in_brain = list(SIGMA_BRAIN_DIR.glob("**/*.yml"))
    print(f"  📁 YAML dans sigma_rules/ : {len(yamls_in_brain)}")

    print()


def extract_rules_from_compiled(compiled_file: Path, output_dir: Path):
    """Extrait les règles YAML du fichier compilé en fichiers individuels"""
    output_dir.mkdir(parents=True, exist_ok=True)
    content = compiled_file.read_text(errors="ignore")

    # Séparer les règles (séparateur --- ou début de nouvelle règle title:)
    # Méthode 1 : séparateur ---
    rules = re.split(r'\n---\n', content)

    extracted = 0
    errors = 0

    for i, rule_text in enumerate(rules):
        rule_text = rule_text.strip()
        if not rule_text or "title:" not in rule_text:
            continue

        # Extraire le titre pour nommer le fichier
        title_match = re.search(r'^title:\s*(.+)$', rule_text, re.MULTILINE)
        if not title_match:
            continue

        title = title_match.group(1).strip()
        # Nettoyer le titre pour en faire un nom de fichier
        safe_title = re.sub(r'[^\w\s-]', '', title).strip()
        safe_title = re.sub(r'\s+', '_', safe_title)[:80]

        # Extraire l'ID si disponible
        id_match = re.search(r'^id:\s*([a-f0-9-]{36})', rule_text, re.MULTILINE)
        rule_id = id_match.group(1)[:8] if id_match else f"{i:04d}"

        filename = f"{rule_id}_{safe_title}.yml"
        output_path = output_dir / filename

        # Ajouter métadonnées utiles pour le RAG
        enriched = f"# SOURCE: sigma_rules\n# THEME: sigma\n{rule_text}\n"

        try:
            output_path.write_text(enriched, encoding="utf-8")
            extracted += 1
        except Exception as e:
            errors += 1
            if errors < 5:
                print(f"  ⚠️  Erreur écriture {filename}: {e}")

    return extracted, errors


def extract_yaml_from_git(sigma_git_dir: Path, output_dir: Path):
    """Copie les YAML depuis sigma_rules_git/ en les enrichissant"""
    output_dir.mkdir(parents=True, exist_ok=True)

    yaml_files = list(sigma_git_dir.glob("**/*.yml"))
    extracted = 0

    for yaml_file in yaml_files:
        # Lire le YAML
        content = yaml_file.read_text(errors="ignore")
        if "title:" not in content:
            continue

        # Nommer selon la structure (tactics/technique)
        parts = yaml_file.relative_to(sigma_git_dir).parts
        prefix = "_".join(parts[:-1])[:40] if len(parts) > 1 else ""
        name   = yaml_file.stem[:60]
        filename = f"{prefix}_{name}.yml" if prefix else f"{name}.yml"
        filename = re.sub(r'[^\w._-]', '_', filename)

        output_path = output_dir / filename

        # Enrichir avec métadonnées
        enriched = f"# SOURCE: {yaml_file.name}\n# THEME: sigma\n{content}\n"

        try:
            output_path.write_text(enriched, encoding="utf-8")
            extracted += 1
        except Exception:
            pass

    return extracted


def main():
    parser = argparse.ArgumentParser(description="SOC Sigma Fix — Réindexation individuelle")
    parser.add_argument("--check",   action="store_true", help="Vérifier l'état")
    parser.add_argument("--extract", action="store_true", help="Extraire les règles")
    parser.add_argument("--rebuild", action="store_true", help="Lancer le rebuild RAG après extraction")
    args = parser.parse_args()

    if args.check or not any([args.extract, args.rebuild]):
        check_state()
        return

    if args.extract:
        print("\n🔧 Extraction des règles Sigma en fichiers individuels\n")

        # Méthode 1 : depuis fichier compilé
        compiled = SIGMA_BRAIN_DIR / "sigma_rules_soc.txt"
        if compiled.exists():
            print(f"  📄 Extraction depuis {compiled.name}...")
            extracted, errors = extract_rules_from_compiled(compiled, SIGMA_EXTRACTED_DIR)
            print(f"  ✅ {extracted} règles extraites, {errors} erreurs")

        # Méthode 2 : depuis sigma_rules_git/ si disponible
        git_dir = Path.home() / "soc-brain" / "sigma_rules_git"
        if git_dir.exists():
            print(f"\n  📁 Copie depuis sigma_rules_git/...")
            count = extract_yaml_from_git(git_dir, SIGMA_EXTRACTED_DIR)
            print(f"  ✅ {count} fichiers YAML copiés")

        print(f"\n  📁 Dossier extrait : {SIGMA_EXTRACTED_DIR}")
        print(f"\n  🔔 IMPORTANT : Tu dois maintenant ajouter sigma_extracted")
        print(f"     dans FOLDER_THEME_MAP de soc_ask_v2.py :")
        print(f'     "sigma_extracted": "sigma",')
        print(f"\n  Puis relancer le rebuild :")
        print(f"  python3.13 soc_ask_v2.py --rebuild")

    if args.rebuild:
        print("\n  🔄 Lancement du rebuild...")
        os.system("python3.13 /Users/sangour3i/CYBER/soc-stack/soc_ask_v2.py --rebuild")


if __name__ == "__main__":
    main()
