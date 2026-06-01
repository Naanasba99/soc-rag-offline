# SOC RAG ELITE V3 — Guide d'installation et d'intégration
## Passage du niveau 3 au niveau 4 (Agentic RAG Premium)

---

## ÉTAPE 0 — Installation des dépendances

```bash
pip3.13 install sentence-transformers rank-bm25 --break-system-packages
```

Premier lancement : télécharge automatiquement le modèle reranker (~80MB).

---

## ÉTAPE 1 — Copie les fichiers dans ton dossier SOC

```bash
cp soc_reranker.py /Users/sangour3i/CYBER/soc-stack/
cp soc_sigma_fix.py /Users/sangour3i/CYBER/soc-stack/
```

---

## ÉTAPE 2 — Vérifie les dépendances

```bash
cd /Users/sangour3i/CYBER/soc-stack/
python3.13 soc_reranker.py
```

Résultat attendu :
```
✅ sentence-transformers
✅ rank-bm25
✅ Toutes les dépendances OK

🧪 Test du query router
✅ 'CVE critiques FortiClient ces 90 derniers jours' → Agent CVE
✅ 'règle Sigma pour détecter Kerberoasting'        → Agent DETECTION
✅ 'comment investiguer une persistance T1053'      → Agent DFIR
✅ 'chasser Cobalt Strike dans les logs Windows'   → Agent THREAT_HUNT
```

---

## ÉTAPE 3 — Patch soc_ask_v2.py (3 modifications)

### Modification A — Imports (après la ligne `import chromadb`)

```python
# Ajouter après "import chromadb" :
try:
    from soc_reranker import rerank, bm25_filter, reciprocal_rank_fusion, route_query, hyde_query
    RERANKING_ENABLED     = True
    HYBRID_SEARCH_ENABLED = True
    HYDE_ENABLED          = False  # True si questions conceptuelles fréquentes
    print("  ✅ SOC Reranker v3 chargé")
except ImportError:
    RERANKING_ENABLED     = False
    HYBRID_SEARCH_ENABLED = False
    HYDE_ENABLED          = False
    print("  ⚠️  soc_reranker.py non trouvé — mode v2 standard")
```

### Modification B — Remplace la fonction retrieval()

Cherche `def retrieval(` dans soc_ask_v2.py et remplace toute la fonction
par le contenu de PATCH_RETRIEVAL.py (la fonction entre les lignes de ══)

### Modification C — Ajoute sigma_extracted dans FOLDER_THEME_MAP

```python
# Dans FOLDER_THEME_MAP, ajouter :
"sigma_extracted": "sigma",
```

---

## ÉTAPE 4 — Fix Sigma (réindexation individuelle)

```bash
cd /Users/sangour3i/CYBER/soc-stack/

# Vérifier l'état
python3.13 soc_sigma_fix.py --check

# Extraire les règles en fichiers individuels
python3.13 soc_sigma_fix.py --extract

# Rebuild de la base vectorielle (20-30 min pour 400K chunks)
python3.13 soc_ask_v2.py --rebuild
```

---

## ÉTAPE 5 — Test de validation

```bash
# Test 1 — Reranking conceptuel (LotL)
python3.13 soc_ask_v2.py --mode synthesis --topk 20 \
  --question "techniques MITRE utilisees pour executer du code avec binaires Windows legitimes T1218 T1059"

# Test 2 — Agent CVE (BM25 exact match)
python3.13 soc_ask_v2.py --topk 15 \
  --question "CVE critiques FortiClient FortiEMS 2024 2025"

# Test 3 — Agent Detection (Sigma individuel)
python3.13 soc_ask_v2.py --topk 15 \
  --question "regle Sigma scheduled task privilege escalation T1053"

# Test 4 — Query router automatique (sans --theme ni --mode)
python3.13 soc_ask_v2.py \
  --question "comment chasser Cobalt Strike dans les logs Windows Event 4688"
```

---

## Résultats attendus après le patch

| Test | Avant | Après | Amélioration |
|------|-------|-------|--------------|
| LotL conceptuel | 8/10 | 9.5/10 | Reranking |
| CVE FortiClient | 9/10 | 9.5/10 | Agent CVE + BM25 |
| Sigma T1053 | 5/10 | 8.5/10 | Sigma fix + reranking |
| Questions mixtes | 7/10 | 9/10 | Query router |
| Distance moyenne | 0.67 | 0.52 | -22% |

---

## Architecture finale — SOC RAG Elite V3

```
                    QUESTION
                       ↓
              ┌─ QUERY ROUTER ─┐
              │  (auto-detect)  │
    ┌─────────┼──────────────┐  │
    │         │              │  │
  CVE      DFIR         DETECT  HUNT
  Agent    Agent        Agent   Agent
  cisa+nvd mitre+atomic sigma+  mitre+
           +playbook    hayab   blogs
    └─────────┴──────────────┘
                  ↓
         HYBRID SEARCH
         Vecteurs (nomic) 
              +
         BM25 (keywords)
              +
           RRF Fusion
                  ↓
           TOP 32 chunks
                  ↓
      CROSS-ENCODER RERANKER
      (ms-marco-MiniLM-L-6)
                  ↓
           TOP 8 chunks
                  ↓
      LLM (Mistral/Qwen2.5)
      avec mode spécialisé
                  ↓
       RÉPONSE + SOURCES
       + SCORES RERANKING
```

---

## Commandes de maintenance

```bash
# Vérifier l'état des sources
python3.13 soc_feed.py --status

# Re-checker les dépendances reranker
python3.13 soc_reranker.py

# Sigma status
python3.13 soc_sigma_fix.py --check
```

---

## Notes importantes

1. **Premier lancement** : le reranker télécharge ~80MB. Prévoir connexion.
2. **Vitesse** : +1-2 secondes par requête (reranking est rapide sur M4).
3. **HyDE** : désactivé par défaut. Activer pour questions conceptuelles complexes.
   Inconvénient : +5-10 secondes (génère d'abord une réponse hypothétique).
4. **Rebuild** : obligatoire après fix Sigma. Dure 20-30 min.
5. **Fallback** : si reranker non disponible, système revient au mode v2 automatiquement.

---

*SOC RAG Elite V3 — Reranking + Hybrid Search + Agents*
*Architecture : Niveau 4 Agentic RAG*
