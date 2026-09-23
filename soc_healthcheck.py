#!/usr/bin/env python3
"""
soc_healthcheck.py — Validation de santé du SOC RAG
======================================================

But : détecter 90% des problèmes courants AVANT d'utiliser le RAG
(Ollama down, base corrompue, régression de retrieval après un changement).

À lancer :
  - avant un --rebuild (pour vérifier qu'Ollama répond, et faire un backup)
  - après un --rebuild (pour confirmer que les chunks/fichiers attendus sont là)
  - après toute modification de code (chunking, reranker, prompts...)

Usage :
  python3 soc_healthcheck.py                  # check complet
  python3 soc_healthcheck.py --pre-rebuild     # check rapide avant rebuild (Ollama + backup)
  python3 soc_healthcheck.py --no-backup       # check complet sans backup
  python3 soc_healthcheck.py --questions-only  # uniquement les 5 questions de référence
"""

import os
import sys
import json
import shutil
import argparse
import urllib.request
from datetime import datetime

# ===================== CONFIG =====================
DB_PATH       = os.path.expanduser("~/CYBER/soc-stack/soc-chroma-db-v2")
BACKUP_DIR    = os.path.expanduser("~/CYBER/soc-stack/backups")
SOC_ASK_SCRIPT = os.path.expanduser("~/CYBER/soc-stack/soc_ask_v2.py")
OLLAMA_URL    = "http://localhost:11434/api/tags"

# Valeurs attendues — à mettre à jour après un rebuild volontaire et validé
EXPECTED_CHUNKS = 25410  # mis à jour après rebuild avec chunk_size=1200 (était 52233 à 600)
EXPECTED_FILES  = 6207
CHUNK_TOLERANCE = 0.05  # 5% d'écart toléré avant alerte (ajout normal de docs)

# Questions de référence : (question, mode, theme, [sources attendues (substring match)])
REFERENCE_QUESTIONS = [
    {
        "question": "Explique T1059",
        "mode": "synthesis",
        "theme": "mitre",
        "expected_sources": ["T1059_Command_and_Scripting_Interpreter"],
    },
    {
        "question": "Explique T1218",
        "mode": "synthesis",
        "theme": "mitre",
        "expected_sources": ["T1218"],
    },
    {
        # Cas de régression réel : ce RAG a halluciné sur cette question
        # (retrieval hors-sujet sur du tcpdump/SSH + LLM qui a inventé des
        # IDs de règles Sigma). Root cause diagnostiquée et corrigée :
        # 1) le reranker forçait 3 chunks même sous son propre seuil de
        #    confiance (fixé — voir `confident` dans soc_reranker.rerank) ;
        # 2) le tokenizer BM25 traitait les underscores comme des
        #    caractères de mot, rendant "pass_the_hash" invisible à une
        #    requête "pass"+"hash" (fixé — voir soc_reranker.bm25_filter) ;
        # 3) le cross-encoder reranker (English-only) rejetait le contenu
        #    MITRE anglais pertinent face à une question française (mesuré :
        #    -2.34 en FR vs +6.78 en EN pour le même contenu — fixé via
        #    translate_query_en + double scoring dans rerank()).
        # T1550.002 EXISTE bel et bien dans le corpus — la note précédente
        # de ce fichier affirmant le contraire était une erreur de diagnostic
        # (le vrai problème était le retrieval, pas la couverture).
        "question": "Qu'est-ce que Pass-the-Hash ?",
        "mode": "blue",
        "theme": None,
        "expected_sources": ["T1550.002", "Pass_the_Hash"],
    },
    {
        "question": "Explique une règle Sigma",
        "mode": "extract",
        "theme": "sigma",
        "expected_sources": [],  # pas de fichier précis attendu, on vérifie juste que ça répond
    },
    {
        "question": "Que fait Atomic Red Team ?",
        "mode": "synthesis",
        "theme": "atomic",
        "expected_sources": [],
    },
]


# ===================== UTILS AFFICHAGE =====================
def header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def ok(msg):
    print(f"  ✅ {msg}")


def fail(msg):
    print(f"  ❌ {msg}")


def warn(msg):
    print(f"  ⚠️  {msg}")


# ===================== NIVEAU 1 : OLLAMA =====================
def check_ollama() -> bool:
    header("1. OLLAMA")
    try:
        req = urllib.request.Request(OLLAMA_URL, method="GET")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            models = [m.get("name", "?") for m in data.get("models", [])]
            ok(f"Ollama répond — {len(models)} modèle(s) disponible(s)")
            for m in models:
                print(f"       • {m}")
            return True
    except Exception as e:
        fail(f"Ollama ne répond pas sur {OLLAMA_URL}")
        fail(f"   Détail : {e}")
        warn("Lance 'ollama serve' avant de continuer.")
        return False


# ===================== NIVEAU 2 : BACKUP =====================
def backup_db() -> bool:
    header("2. SAUVEGARDE")
    if not os.path.isdir(DB_PATH):
        warn(f"Pas de base existante à sauvegarder ({DB_PATH})")
        return True

    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y-%m-%d_%Hh%M")
    backup_path = os.path.join(BACKUP_DIR, f"soc-chroma-db-v2_{timestamp}")

    try:
        shutil.copytree(DB_PATH, backup_path)
        size_mb = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, files in os.walk(backup_path)
            for f in files
        ) / (1024 * 1024)
        ok(f"Backup créé : {backup_path} ({size_mb:.1f} MB)")
        cleanup_old_backups()
        return True
    except Exception as e:
        fail(f"Échec du backup : {e}")
        return False


def cleanup_old_backups(keep: int = 5):
    """Garde uniquement les N backups les plus récents pour ne pas saturer le disque."""
    if not os.path.isdir(BACKUP_DIR):
        return
    backups = sorted(
        [d for d in os.listdir(BACKUP_DIR) if d.startswith("soc-chroma-db-v2_")],
        reverse=True
    )
    for old in backups[keep:]:
        old_path = os.path.join(BACKUP_DIR, old)
        try:
            shutil.rmtree(old_path)
            print(f"       🗑️  Ancien backup supprimé : {old}")
        except Exception:
            pass


# ===================== NIVEAU 3 : STATS =====================
def check_stats() -> bool:
    header("3. STATISTIQUES DE LA BASE")
    try:
        import chromadb
        client = chromadb.PersistentClient(path=DB_PATH)
        collection = client.get_collection("soc_elite")
        count = collection.count()
    except Exception as e:
        fail(f"Impossible de lire la base : {e}")
        return False

    print(f"  Chunks actuels  : {count}")
    print(f"  Chunks attendus : {EXPECTED_CHUNKS} (± {int(EXPECTED_CHUNKS * CHUNK_TOLERANCE)})")

    low  = EXPECTED_CHUNKS * (1 - CHUNK_TOLERANCE)
    high = EXPECTED_CHUNKS * (1 + CHUNK_TOLERANCE)

    if count == 0:
        fail("Base vide — 0 chunks. Rebuild nécessaire.")
        return False
    elif count < low:
        fail(f"Chute anormale du nombre de chunks ({count} << {EXPECTED_CHUNKS})")
        warn("La base a probablement été partiellement reconstruite ou corrompue.")
        return False
    elif count > high:
        warn(f"Plus de chunks que prévu ({count} > {EXPECTED_CHUNKS}) — probablement de nouveaux documents ajoutés, à confirmer.")
        return True
    else:
        ok(f"Nombre de chunks cohérent ({count})")
        return True


# ===================== NIVEAU 4 : QUESTIONS DE RÉFÉRENCE =====================
def run_reference_questions() -> bool:
    header("4. QUESTIONS DE RÉFÉRENCE (pipeline complet)")

    if not os.path.isfile(SOC_ASK_SCRIPT):
        fail(f"Script introuvable : {SOC_ASK_SCRIPT}")
        return False

    # Import direct plutôt que subprocess : réutilise le reranker
    # cross-encoder déjà chargé en mémoire entre les 5 questions (le
    # rechargement par subprocess coûtait plusieurs secondes par question),
    # et donne accès à answer_question() qui expose la détection de
    # citations fabriquées — impossible à vérifier depuis la seule sortie
    # texte d'un subprocess sans reparser la liste des sources à la main.
    sys.path.insert(0, os.path.dirname(SOC_ASK_SCRIPT))
    import soc_ask_v2 as rag

    all_passed = True
    results = []

    for i, test in enumerate(REFERENCE_QUESTIONS, 1):
        question = test["question"]
        mode     = test["mode"]
        theme    = test.get("theme")
        expected = test.get("expected_sources", [])

        print(f"\n  Test {i}/{len(REFERENCE_QUESTIONS)} : \"{question}\"")

        try:
            r = rag.answer_question(question, mode, theme=theme, topk=8)
        except Exception as e:
            fail(f"   Erreur d'exécution : {e}")
            results.append((question, False, str(e)))
            all_passed = False
            continue

        if "❌ Erreur LLM" in r["response"]:
            fail(f"   Erreur LLM détectée dans la réponse")
            results.append((question, False, "erreur LLM"))
            all_passed = False
            continue

        if r["fabricated_citations"]:
            fail(f"   HALLUCINATION — citation(s) fabriquée(s) : {', '.join(r['fabricated_citations'])}")
            results.append((question, False, f"citations fabriquées: {r['fabricated_citations']}"))
            all_passed = False
            continue

        if not expected:
            # Pas de source précise attendue : on vérifie juste qu'une réponse a été générée
            if not r["abstained"] and len(r["response"].strip()) > 100:
                ok(f"   Réponse générée (pas de source spécifique vérifiée)")
                results.append((question, True, None))
            else:
                fail(f"   Aucune réponse exploitable générée (abstained={r['abstained']})")
                results.append((question, False, "réponse vide ou abstention"))
                all_passed = False
            continue

        missing = [src for src in expected if not any(src.lower() in s.lower() for s in r["sources"])]
        # "missing" complet (aucune des sources attendues trouvée) : si
        # `expected` contient plusieurs alias pour la même source (ex:
        # "T1550.002" et "Pass_the_Hash"), un seul suffit à passer le test.
        if len(missing) < len(expected):
            ok(f"   PASS — source(s) attendue(s) trouvée(s) parmi : {', '.join(expected)}")
            results.append((question, True, None))
        elif r["abstained"]:
            fail(f"   FAIL — abstention (aucun document jugé assez pertinent) ; "
                 f"sources attendues introuvables : {', '.join(expected)}")
            results.append((question, False, f"abstention, attendu {expected}"))
            all_passed = False
        else:
            fail(f"   FAIL — source(s) manquante(s) : {', '.join(missing)}")
            results.append((question, False, f"manque {missing}"))
            all_passed = False

    print()
    header("RÉSUMÉ DES TESTS")
    for question, passed, detail in results:
        status = "PASS" if passed else "FAIL"
        icon   = "✅" if passed else "❌"
        line   = f"  {icon} [{status}] {question}"
        if detail:
            line += f"  ({detail})"
        print(line)

    return all_passed


# ===================== RAPPORT FINAL =====================
def print_dashboard(ollama_ok, backup_ok, stats_ok, questions_ok):
    header("RAG HEALTH — TABLEAU DE BORD")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"  Date            : {timestamp}")
    print(f"  Ollama          : {'OK' if ollama_ok else 'ERREUR'}")
    print(f"  Backup          : {'OK' if backup_ok else 'ERREUR'}")
    print(f"  ChromaDB stats  : {'OK' if stats_ok else 'ERREUR'}")
    print(f"  Tests référence : {'PASS' if questions_ok else 'FAIL'}")
    print()

    if ollama_ok and backup_ok and stats_ok and questions_ok:
        print("  🟢 RAG EN BON ÉTAT — tu peux continuer sereinement.")
    else:
        print("  🔴 PROBLÈME DÉTECTÉ — corrige avant de continuer (voir détails ci-dessus).")
    print()


# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="Health check du SOC RAG")
    parser.add_argument("--pre-rebuild", action="store_true",
                         help="Check rapide avant rebuild : Ollama + backup uniquement")
    parser.add_argument("--no-backup", action="store_true",
                         help="Ne pas faire de backup pendant le check complet")
    parser.add_argument("--questions-only", action="store_true",
                         help="Lancer uniquement les questions de référence")
    args = parser.parse_args()

    if args.pre_rebuild:
        header("PRE-REBUILD CHECK")
        ollama_ok = check_ollama()
        if not ollama_ok:
            fail("Ollama doit répondre avant de lancer un rebuild. Arrêt.")
            sys.exit(1)
        backup_ok = backup_db()
        if not backup_ok:
            warn("Backup échoué — tu peux continuer mais sans filet de sécurité.")
        print("\n  ✅ Prêt pour le rebuild.\n")
        sys.exit(0)

    if args.questions_only:
        questions_ok = run_reference_questions()
        sys.exit(0 if questions_ok else 1)

    # Check complet
    ollama_ok    = check_ollama()
    backup_ok    = True if args.no_backup else backup_db()
    stats_ok     = check_stats()
    questions_ok = run_reference_questions() if ollama_ok and stats_ok else False

    if not (ollama_ok and stats_ok):
        warn("Tests de référence ignorés (Ollama ou base non fonctionnels).")

    print_dashboard(ollama_ok, backup_ok, stats_ok, questions_ok)

    sys.exit(0 if (ollama_ok and stats_ok and questions_ok) else 1)


if __name__ == "__main__":
    main()
