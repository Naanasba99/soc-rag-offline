#!/usr/bin/env python3
"""
eval_rag.py — Évaluation objective du RAG (retrieval + fidélité anti-hallucination)

Contexte : le système a produit des réponses hallucinées en usage réel (ex:
inventer des IDs de règles Sigma sur une question mal couverte par le
retrieval). Ce script mesure objectivement, sur un jeu de questions couvrant
les principaux thèmes de la base, si un changement (modèle LLM, prompt,
retrieval) améliore ou dégrade la fiabilité — plutôt que de juger "à l'oreille".

Pour chaque question :
  - abstained          : le garde-fou de confiance a-t-il refusé d'appeler le LLM ?
                          (attendu=True seulement pour les questions volontairement
                          hors-sujet ; sinon c'est un retrieval-miss à investiguer)
  - expected_sources_ok : au moins un des fichiers sources attendus a-t-il été
                          effectivement récupéré ? (mesure la qualité du retrieval,
                          indépendamment de ce que fait le LLM ensuite)
  - fabricated_citations : citations du LLM absentes des sources réellement
                          récupérées (mesure directe de l'hallucination)

Usage :
  python3 eval_rag.py                        # compare mistral vs qwen2.5:7b
  python3 eval_rag.py --models mistral        # un seul modèle
  python3 eval_rag.py --models qwen2.5:7b
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

import soc_ask_v2 as rag

QUESTIONS = [
    {
        "id": "Q1_mitre_known_good",
        "question": "Explique T1059 Command and Scripting Interpreter",
        "mode": "blue",
        "expected_sources": ["T1059_Command_and_Scripting_Interpreter"],
    },
    {
        "id": "Q2_pass_the_hash_regression",
        "question": "Qu'est-ce que Pass-the-Hash ?",
        "mode": "blue",
        "expected_sources": ["Pass_the_Hash", "pass_the_hash"],
    },
    {
        "id": "Q3_sigma_kerberoasting",
        "question": "Règle Sigma pour détecter du Kerberoasting",
        "mode": "extract",
        "expected_sources": ["kerberoast"],
    },
    {
        "id": "Q4_dfir_ransomware",
        "question": "Comment détecter un ransomware en cours de chiffrement ?",
        "mode": "hunt",
        "expected_sources": ["ransomware", "RANSOM"],
    },
    {
        "id": "Q5_atomic_red_team",
        "question": "Que fait Atomic Red Team ?",
        "mode": "red",
        "expected_sources": ["atomic"],
    },
    {
        "id": "Q6_threat_hunt_cobaltstrike",
        "question": "Comment chasser Cobalt Strike dans les logs Windows ?",
        "mode": "hunt",
        "expected_sources": ["COBALTSTRIKE", "cobaltstrike", "cobalt_strike"],
    },
    {
        "id": "Q7_dfir_beaconing",
        "question": "Qu'est-ce que le beaconing en DFIR ?",
        "mode": "blue",
        "expected_sources": ["BEACONING"],
    },
    {
        "id": "Q8_mitre_exact_id",
        "question": "Explique la technique T1218",
        "mode": "blue",
        "expected_sources": ["T1218"],
    },
    {
        "id": "Q9_golden_ticket",
        "question": "Explique l'attaque Golden Ticket Kerberos",
        "mode": "red",
        "expected_sources": ["golden_ticket", "Golden_Ticket", "T1558"],
    },
    {
        "id": "Q10_ssh_hardening",
        "question": "Comment durcir la configuration SSH sur un serveur Linux ?",
        "mode": "checklist",
        "expected_sources": ["ssh", "SSH"],
    },
    {
        "id": "Q11_out_of_scope_abstain",
        # Hors-sujet total : la base ne contient rien là-dessus. Le système
        # doit s'abstenir, pas inventer une réponse.
        "question": "Quelle est la meilleure recette de tarte tatin ?",
        "mode": "synthesis",
        "expected_sources": [],
        "expect_abstain": True,
    },
    {
        "id": "Q12_cisa_kev_generic",
        "question": "Qu'est-ce que le catalogue CISA KEV et à quoi sert-il ?",
        "mode": "blue",
        "expected_sources": ["cisa"],
    },
]


def run_eval(model: str, verbose: bool = False) -> dict:
    os.environ["SOC_LLM_MODEL"] = model
    results = []
    t0 = time.time()

    for q in QUESTIONS:
        qt0 = time.time()
        try:
            r = rag.answer_question(
                q["question"], q["mode"],
                theme=None, topk=8, source=None, no_filter=False
            )
        except Exception as e:
            results.append({
                "id": q["id"], "question": q["question"], "error": str(e),
                "expected_sources_ok": False, "fabricated_citations": [], "abstained": None,
            })
            continue
        elapsed = round(time.time() - qt0, 1)

        expected = q.get("expected_sources", [])
        expected_ok = (not expected) or any(
            any(exp.lower() in src.lower() for src in r["sources"]) for exp in expected
        )
        expect_abstain = q.get("expect_abstain", False)
        abstain_correct = (r["abstained"] == expect_abstain) if expect_abstain else (not r["abstained"] or True)
        # abstain_correct n'est un vrai signal d'échec que pour les questions
        # marquées expect_abstain=True (hors-sujet) : si le système répond
        # quand même sur une question hors-sujet, c'est un échec net.
        # Pour les questions normales, un abstain n'est pas "faux" en soi —
        # c'est un retrieval-miss à regarder, signalé séparément.

        entry = {
            "id": q["id"],
            "question": q["question"],
            "abstained": r["abstained"],
            "expect_abstain": expect_abstain,
            "abstain_correct": abstain_correct,
            "expected_sources_ok": expected_ok,
            "fabricated_citations": r["fabricated_citations"],
            "n_sources": len(r["sources"]),
            "elapsed_s": elapsed,
        }
        if verbose:
            entry["response"] = r["response"][:500]
            entry["sources"] = r["sources"]
        results.append(entry)

        status = "✅" if (expected_ok and not r["fabricated_citations"] and abstain_correct) else "❌"
        print(f"  {status} [{q['id']}] abstain={r['abstained']} "
              f"expected_src_ok={expected_ok} fabricated={len(r['fabricated_citations'])} "
              f"({elapsed}s)")

    total_elapsed = round(time.time() - t0, 1)
    n = len(results)
    n_expected_ok = sum(1 for r in results if r.get("expected_sources_ok"))
    n_fabricated = sum(1 for r in results if r.get("fabricated_citations"))
    n_abstain_wrong = sum(1 for r in results if not r.get("abstain_correct", True))

    return {
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "n_questions": n,
        "expected_sources_ok": n_expected_ok,
        "questions_with_fabricated_citations": n_fabricated,
        "abstain_errors_on_out_of_scope": n_abstain_wrong,
        "total_elapsed_s": total_elapsed,
        "details": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="+", default=["mistral", "qwen2.5:7b"])
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--out", default=None, help="Fichier JSON de sortie (défaut: eval_results_<ts>.json)")
    args = parser.parse_args()

    all_results = {}
    for model in args.models:
        print(f"\n{'='*70}\n  ÉVALUATION — modèle: {model}\n{'='*70}")
        all_results[model] = run_eval(model, verbose=args.verbose)

    print(f"\n{'='*70}\n  RÉSUMÉ COMPARATIF\n{'='*70}")
    print(f"  {'Modèle':<15} {'Sources OK':<12} {'Citations fab.':<16} {'Abstain err.':<14} {'Temps total':<12}")
    for model, res in all_results.items():
        print(f"  {model:<15} {res['expected_sources_ok']}/{res['n_questions']:<10} "
              f"{res['questions_with_fabricated_citations']:<16} "
              f"{res['abstain_errors_on_out_of_scope']:<14} {res['total_elapsed_s']}s")

    out_path = args.out or f"eval_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n  📄 Résultats détaillés : {out_path}")


if __name__ == "__main__":
    main()
