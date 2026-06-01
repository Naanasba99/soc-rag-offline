# 🧠 SOC RAG ELITE V3 — Assistant IA Offline pour Analystes Cyber

> *"La dépendance au cloud est une vulnérabilité. L'autonomie est une compétence."*

![Version](https://img.shields.io/badge/version-3.0-green)
![Python](https://img.shields.io/badge/python-3.13-blue)
![RAG Level](https://img.shields.io/badge/RAG-Niveau%204-brightgreen)
![Chunks](https://img.shields.io/badge/chunks-52%2C233-orange)
![Local](https://img.shields.io/badge/100%25-local-success)

---

## 🔍 C'est quoi ?

Un système RAG (Retrieval-Augmented Generation) **100% local et offline** conçu pour les analystes SOC, DFIR et Threat Hunters.

Tu poses une question en langage naturel → le système détecte ton intention → cherche dans 52 000+ chunks spécialisés → reclasse par pertinence réelle → un LLM local génère une réponse sourcée.

**Zéro cloud. Zéro abonnement. Zéro fuite de données.**

---

## ⚡ Pourquoi c'est différent

| Approche classique | Ce système |
|---|---|
| Google + 10 onglets | Une question → une réponse sourcée |
| ChatGPT (cloud, logs) | LLM local, données privées |
| Abonnement 50 000$/an | Gratuit, open-source |
| Inutilisable hors ligne | Fonctionne sans internet |
| Connaissance générique | Base spécialisée SOC/DFIR/CTI |
| Top 8 chunks aléatoires | Reranking cross-encoder précis |

---

## 🏗️ Architecture — RAG Niveau 4

```
                    QUESTION
                       ↓
              ┌─ QUERY ROUTER ─┐
              │  Détection auto │
    ┌─────────┼─────────────────┤
    │         │                 │
  CVE       DFIR          DETECTION  HUNT
  Agent     Agent         Agent      Agent
  cisa+nvd  mitre+atomic  sigma+     mitre+
            +playbook     hayabusa   blogs
    └─────────┴─────────────────┘
                  ↓
         HYBRID SEARCH
         Vecteurs (nomic-embed-text)
              +
         BM25 (mots-clés exacts)
              +
           Fusion RRF
                  ↓
           TOP 60-80 chunks
                  ↓
      CROSS-ENCODER RERANKER
      (ms-marco-MiniLM-L-6-v2)
                  ↓
           TOP 8-15 chunks
                  ↓
      LLM local Mistral/Qwen2.5
                  ↓
       RÉPONSE + SOURCES + SCORES
```

---

## 📚 Sources indexées — 52 233 chunks

| Source | Chunks | Mise à jour |
|--------|--------|-------------|
| Sigma Rules (YAML individuels) | 16 692 | 14 jours |
| Atomic Red Team | 10 121 | Variable |
| MITRE ATT&CK (709 techniques) | 7 410 | 30 jours |
| NVD CVE (critiques, 90 jours) | 5 694 | 7 jours |
| CISA KEV (1 602 entrées) | 4 618 | 7 jours |
| Hayabusa (threat hunting Windows) | 2 211 | Variable |
| Abuse.ch (IOC temps réel) | 1 380 | 1 jour |
| DFIR & Références | 449 | Manuel |
| RSS Threat Intel (Talos, Unit42...) | 188 | 1 jour |
| ANSSI (alertes officielles) | 93 | Variable |
| Playbooks personnels | 29 | Manuel |

---

## 🚀 Usage

```bash
# Menu interactif
python3.13 soc_ask_v2.py

# Question directe avec mode
python3.13 soc_ask_v2.py --mode blue   --question "comment détecter un Pass-the-Hash ?"
python3.13 soc_ask_v2.py --mode red    --question "techniques de pivoting Windows"
python3.13 soc_ask_v2.py --mode hunt   --question "chasser Cobalt Strike dans les logs"
python3.13 soc_ask_v2.py --mode extract --question "règles Sigma pour Kerberoasting"

# Filtrage par thème
python3.13 soc_ask_v2.py --theme mitre --question "T1055 Process Injection"
python3.13 soc_ask_v2.py --theme sigma --question "détection PowerShell obfusqué"
python3.13 soc_ask_v2.py --theme cisa  --question "CVE critiques FortiClient 2025"

# Augmenter le pool de chunks
python3.13 soc_ask_v2.py --topk 20 --question "techniques ransomware"

# Statistiques
python3.13 soc_ask_v2.py --stats

# Rebuild de la base
python3.13 soc_ask_v2.py --rebuild
```

### Modes disponibles

| Mode | Cas d'usage |
|------|-------------|
| `blue` | Défense, détection, réponse à incident, hardening |
| `red` | Techniques offensives, pivoting, persistence |
| `hunt` | Threat hunting, recherche IOC dans les logs |
| `extract` | Règles Sigma, Event IDs, TTPs précis |
| `synthesis` | Synthèse multi-sources sur un sujet |
| `checklist` | Checklist d'investigation opérationnelle |

---

## 🛠️ Stack technique

| Composant | Technologie |
|-----------|-------------|
| Embeddings | nomic-embed-text via Ollama |
| Base vectorielle | ChromaDB (local, 4.4 Go) |
| LLM | Mistral 7B / Qwen2.5 7B / DeepSeek-R1 7B |
| Reranker | cross-encoder/ms-marco-MiniLM-L-6-v2 |
| Hybrid Search | BM25 (rank-bm25) + Fusion RRF |
| Query Router | Détection d'agent par patterns |
| Orchestration | LangChain + ChromaDB natif |
| Language | Python 3.13 |

---

## 📈 Performances V2 → V3

| Requête | V2 | V3 | Score reranker |
|---------|----|----|----------------|
| CVE FortiClient 2025 | 9/10 | 9.5/10 | 4.917 |
| Sigma T1053 escalation | 0/10 (0 résultats) | 8.5/10 | 5.038 |
| MITRE LotL T1218 | 3/10 (mauvais TTPs) | 8.5/10 | 0.981 |
| Distance moyenne | 0.68 | 0.55 | -19% |
| Pool de chunks | 8 | 60-80 | +650% |

---

## 📁 Fichiers

| Fichier | Rôle |
|---------|------|
| `soc_ask_v2.py` | Moteur RAG principal (v3 patché) |
| `soc_feed.py` | Fetcher et mise à jour des sources |
| `soc_reranker.py` | Reranker + hybrid search + query router |
| `soc_sigma_fix.py` | Réindexation Sigma YAML individuels |
| `soc.sh` | Menu SOC surveillance temps réel |
| `llm_config.py` | Configuration LLM |
| `requirements.txt` | Dépendances Python |

---

## 🔧 Maintenance

```bash
# Vérifier les sources
python3.13 soc_feed.py --status

# Mettre à jour toutes les sources
python3.13 soc_feed.py

# Rebuild de la base vectorielle
python3.13 soc_ask_v2.py --rebuild

# Vérifier le reranker
python3.13 soc_reranker.py

# Fix Sigma (si nouvelles règles)
python3.13 soc_sigma_fix.py --extract
```

### Checklist hebdomadaire (5 minutes)

```bash
python3.13 soc_feed.py --status    # Sources périmées ?
python3.13 soc_feed.py             # Mettre à jour si besoin
python3.13 soc_ask_v2.py --rebuild # Si nouvelles données
df -h ~                             # Espace disque
```

---

## 🗺️ Roadmap — Niveau 5

- [ ] Intégration Wazuh API (enrichissement d'alertes temps réel)
- [ ] Analyse d'artefacts Velociraptor
- [ ] Export requêtes KQL pour Kibana
- [ ] Évaluation automatique RAGAS
- [ ] Mémoire contextuelle entre sessions

---

## 👤 Auteur

**Naanasba** — Transition Finance → Cybersécurité
Parcours : SOC Analyst → DFIR → Threat Hunter
GitHub : [@Naanasba99](https://github.com/Naanasba99)

---

## 🇫🇷 Pourquoi en français ?

La communauté cyber francophone manque de ressources techniques de qualité.
Ce projet est une contribution à cet écosystème.

---

*Construit pièce par pièce. Compris avant d'être utilisé.*
