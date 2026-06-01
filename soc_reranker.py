#!/usr/bin/env python3
"""
soc_reranker.py — Module Reranking + Hybrid Search pour SOC RAG Elite
Intégration dans soc_ask_v2.py via patch de la fonction retrieval()

Installation :
  pip3.13 install sentence-transformers rank-bm25 --break-system-packages

Usage : importer dans soc_ask_v2.py (voir PATCH_RETRIEVAL.py)
"""

import os
import re
from typing import List, Tuple, Optional

# ── RERANKER ───────────────────────────────────────────────────────────────
_reranker_model = None
RERANKER_MODEL  = "cross-encoder/ms-marco-MiniLM-L-6-v2"  # ~80MB, rapide

def get_reranker():
    """Charge le cross-encoder une seule fois (lazy loading)"""
    global _reranker_model
    if _reranker_model is None:
        try:
            from sentence_transformers import CrossEncoder
            print(f"  🔄 Chargement reranker {RERANKER_MODEL}...")
            _reranker_model = CrossEncoder(RERANKER_MODEL, max_length=512)
            print(f"  ✅ Reranker prêt")
        except ImportError:
            print("  ⚠️  sentence-transformers manquant")
            print("      pip3.13 install sentence-transformers --break-system-packages")
            return None
    return _reranker_model


def rerank(query: str, docs: List[str], metadatas: List[dict],
           distances: List[float], top_n: int = 8) -> Tuple[List, List, List]:
    """
    Re-classe les chunks par pertinence réelle avec un cross-encoder.
    
    Args:
        query     : question originale
        docs      : chunks texte (Top 30 depuis ChromaDB)
        metadatas : métadonnées correspondantes
        distances : scores ChromaDB correspondants
        top_n     : nombre de chunks à retourner après reranking
    
    Returns:
        (docs_rerankés, metadatas_rerankés, scores_rerankés)
    """
    if not docs:
        return docs, metadatas, distances

    reranker = get_reranker()
    if reranker is None:
        # Fallback : retourner les top_n sans reranking
        return docs[:top_n], metadatas[:top_n], distances[:top_n]

    # Paires (question, chunk) pour le cross-encoder
    pairs = [(query, doc[:512]) for doc in docs]  # max 512 tokens

    # Scores de pertinence (-inf à +inf, plus haut = plus pertinent)
    scores = reranker.predict(pairs, show_progress_bar=False)

    # Tri par score décroissant
    ranked = sorted(
        zip(scores, docs, metadatas, distances),
        key=lambda x: x[0],
        reverse=True
    )

    top = ranked[:top_n]
    r_scores   = [round(float(s), 4) for s, _, _, _ in top]
    r_docs     = [d for _, d, _, _ in top]
    r_metas    = [m for _, _, m, _ in top]
    r_dists    = [dist for _, _, _, dist in top]

    return r_docs, r_metas, r_dists, r_scores


# ── HYBRID SEARCH (BM25 + Vecteurs) ───────────────────────────────────────
def bm25_filter(query: str, docs: List[str], top_n: int) -> List[int]:
    """
    Retourne les indices des docs les plus pertinents selon BM25.
    Utile pour CVE-IDs, T-codes MITRE, noms d'outils exacts.
    """
    try:
        from rank_bm25 import BM25Okapi
    except ImportError:
        print("  ⚠️  rank-bm25 manquant : pip3.13 install rank-bm25 --break-system-packages")
        return list(range(min(top_n, len(docs))))

    # Tokenisation simple + mots cybersécurité préservés
    def tokenize(text):
        text = text.lower()
        # Préserver les tokens importants : CVE-xxxx, T1059, SHA256, IPs
        tokens = re.findall(r'cve-\d{4}-\d+|t\d{4}(?:\.\d+)?|\b\w+\b', text)
        return tokens if tokens else text.split()

    tokenized_docs   = [tokenize(doc) for doc in docs]
    tokenized_query  = tokenize(query)

    bm25   = BM25Okapi(tokenized_docs)
    scores = bm25.get_scores(tokenized_query)

    # Retourner les indices triés par score décroissant
    ranked_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    return ranked_indices[:top_n]


def reciprocal_rank_fusion(
    vector_items: List[Tuple],   # [(doc, meta, dist), ...]
    bm25_indices: List[int],     # indices BM25 dans vector_items
    k: int = 60
) -> List[Tuple]:
    """
    Fusion RRF (Reciprocal Rank Fusion) des scores vecteur + BM25.
    Méthode state-of-the-art pour hybrid search.
    
    Score RRF(d) = Σ 1/(k + rank(d))
    """
    scores = {}

    # Scores vecteur (déjà triés par distance)
    for rank, item in enumerate(vector_items):
        key = id(item[0])  # identifiant unique par doc
        scores[key] = scores.get(key, 0) + 1.0 / (k + rank + 1)

    # Scores BM25
    for rank, idx in enumerate(bm25_indices):
        if idx < len(vector_items):
            key = id(vector_items[idx][0])
            scores[key] = scores.get(key, 0) + 1.0 / (k + rank + 1)

    # Tri final par score RRF décroissant
    ranked = sorted(
        vector_items,
        key=lambda item: scores.get(id(item[0]), 0),
        reverse=True
    )
    return ranked


# ── HYDE (Hypothetical Document Embeddings) ────────────────────────────────
def hyde_query(question: str, ollama_url: str = "http://localhost:11434",
               model: str = "mistral") -> str:
    """
    Génère une réponse hypothétique à la question, puis l'utilise
    comme requête d'embedding à la place de la question originale.
    
    Avantage : pour les questions conceptuelles (Living off the Land,
    APT28, etc.), l'embedding d'une réponse hypothétique pointe vers
    les bons chunks bien mieux que l'embedding de la question.
    
    Usage : remplacer embeddings.embed_query(question) par
            embeddings.embed_query(hyde_query(question))
    """
    import urllib.request
    import json

    hyde_prompt = (
        f"Tu es un expert cybersécurité SOC/DFIR. "
        f"Écris un paragraphe technique de 3-4 phrases qui décrit "
        f"précisément : {question}\n"
        f"Réponds UNIQUEMENT avec le paragraphe, sans introduction."
    )

    payload = json.dumps({
        "model": model,
        "prompt": hyde_prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 200}
    }).encode()

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
            hypothetical = data.get("response", "").strip()
            if hypothetical:
                return hypothetical
    except Exception:
        pass

    return question  # Fallback : question originale


# ── QUERY ROUTER ──────────────────────────────────────────────────────────
AGENT_PATTERNS = {
    "CVE": {
        "patterns": [
            r"CVE-\d{4}-\d+",
            r"vulnérabilit",
            r"patch",
            r"CVSS",
            r"FortiClient|FortiEMS|Exchange|Apache|nginx|OpenSSL",
            r"critiques.*90 jours|derniers jours"
        ],
        "themes": ["cisa", "nvd"],
        "topk_boost": 15,
        "mode_default": "blue"
    },
    "DETECTION": {
        "patterns": [
            r"[Ss]igma",
            r"règle.*détection|détection.*règle",
            r"Event ID|EventID",
            r"SIEM|Splunk|Elastic|Wazuh",
            r"[Hh]ayabusa",
            r"détecter|comment.*identifier"
        ],
        "themes": ["sigma", "hayabusa"],
        "topk_boost": 15,
        "mode_default": "extract"
    },
    "DFIR": {
        "patterns": [
            r"DFIR|forensic|forensique",
            r"incident|réponse à incident",
            r"artefact|artefact",
            r"investigation|investiguer",
            r"persistence|persistance",
            r"T1053|T1547|T1055|T1136"
        ],
        "themes": ["mitre", "atomic", "dfir", "playbook"],
        "topk_boost": 20,
        "mode_default": "blue"
    },
    "THREAT_HUNT": {
        "patterns": [
            r"[Tt]hreat [Hh]unt|chasse.*menace",
            r"IOC|indicateur",
            r"APT\d*|Lazarus|Cozy Bear|FIN\d",
            r"Cobalt Strike|Mimikatz|BloodHound",
            r"campagne|attribution"
        ],
        "themes": ["mitre", "blog", "abuse", "anssi"],
        "topk_boost": 20,
        "mode_default": "hunt"
    }
}


def route_query(question: str) -> Optional[dict]:
    """
    Détecte automatiquement l'agent le plus adapté à la question.
    Retourne la config de l'agent ou None (= RAG générique).
    """
    question_lower = question.lower()
    scores = {}

    for agent_name, config in AGENT_PATTERNS.items():
        score = 0
        for pattern in config["patterns"]:
            if re.search(pattern, question, re.IGNORECASE):
                score += 1
        if score > 0:
            scores[agent_name] = score

    if not scores:
        return None

    best_agent = max(scores, key=lambda k: scores[k])
    config = AGENT_PATTERNS[best_agent].copy()
    config["agent_name"] = best_agent
    return config


# ── DIAGNOSTIC ────────────────────────────────────────────────────────────
def check_dependencies():
    """Vérifie que les dépendances sont installées"""
    deps = {
        "sentence_transformers": "sentence-transformers",
        "rank_bm25": "rank-bm25"
    }
    missing = []
    for module, package in deps.items():
        try:
            __import__(module)
            print(f"  ✅ {package}")
        except ImportError:
            print(f"  ❌ {package} manquant")
            missing.append(package)

    if missing:
        print(f"\n  Installe les manquants :")
        print(f"  pip3.13 install {' '.join(missing)} --break-system-packages")
    else:
        print("  ✅ Toutes les dépendances OK")

    return len(missing) == 0


if __name__ == "__main__":
    print("\n🔍 Vérification des dépendances SOC Reranker\n")
    check_dependencies()
    print("\n🧪 Test du query router\n")
    tests = [
        "CVE critiques FortiClient ces 90 derniers jours",
        "règle Sigma pour détecter Kerberoasting",
        "comment investiguer une persistance T1053",
        "chasser Cobalt Strike dans les logs Windows",
        "techniques MITRE Living off the Land"
    ]
    for q in tests:
        agent = route_query(q)
        if agent:
            print(f"  ✅ '{q[:50]}...' → Agent {agent['agent_name']}")
        else:
            print(f"  📌 '{q[:50]}...' → RAG générique")
