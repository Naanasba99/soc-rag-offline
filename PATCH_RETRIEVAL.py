#!/usr/bin/env python3
"""
PATCH_RETRIEVAL.py
──────────────────
Remplace la fonction retrieval() de soc_ask_v2.py par la version
améliorée avec :
  ✅ Reranking cross-encoder (Top 30 → reranker → Top 8)
  ✅ Hybrid search BM25 + vecteurs (RRF fusion)
  ✅ HyDE pour questions conceptuelles
  ✅ Query router vers agents spécialisés
  ✅ topk auto-boosté selon l'agent détecté

COMMENT APPLIQUER CE PATCH :
──────────────────────────────
1. Copie soc_reranker.py dans ~/CYBER/soc-stack/
2. Dans soc_ask_v2.py, ajoute APRÈS les imports existants (ligne ~22) :
   
   from soc_reranker import rerank, bm25_filter, reciprocal_rank_fusion, route_query, hyde_query
   RERANKING_ENABLED = True
   HYBRID_SEARCH_ENABLED = True
   HYDE_ENABLED = False  # Activer si questions conceptuelles fréquentes (plus lent)

3. Remplace TOUTE la fonction retrieval() (lignes 338-411) par le code ci-dessous.
"""

# ══════════════════════════════════════════════════════════════════════════════
# NOUVELLE FONCTION retrieval() — remplace l'ancienne entièrement
# ══════════════════════════════════════════════════════════════════════════════

def retrieval(question: str, mode: str, theme: str = None, topk: int = 8,
              source: str = None, no_filter: bool = False):
    """
    Retrieval v3 — Hybrid Search + Reranking + Query Router
    
    Pipeline :
    1. Query Router → détecte l'agent adapté et ses sources
    2. HyDE (optionnel) → embedding hypothétique pour questions conceptuelles
    3. ChromaDB vector search → Top 30 (plus large pour reranking)
    4. BM25 keyword search → Top 15 sur les mêmes docs
    5. RRF Fusion → combine scores vecteur + BM25
    6. Cross-encoder Reranker → reclasse par pertinence réelle
    7. Top topk → envoyé au LLM
    """
    embeddings = get_embeddings()

    # ── ÉTAPE 1 : QUERY ROUTER ──────────────────────────────────────────────
    agent_config = None
    if not theme and not no_filter:
        agent_config = route_query(question)
        if agent_config:
            agent_name = agent_config["agent_name"]
            print(f"  🤖 Agent détecté : {agent_name}")
            # L'agent peut booster le topk
            topk = max(topk, agent_config.get("topk_boost", topk))

    # ── ÉTAPE 2 : EMBEDDING (standard ou HyDE) ─────────────────────────────
    if HYDE_ENABLED and not theme:
        # HyDE : générer une réponse hypothétique puis l'embedder
        print(f"  🔮 HyDE : génération embedding hypothétique...")
        hyde_text = hyde_query(question, model=LLM_MODEL)
        query_embedding = embeddings.embed_query(hyde_text)
    else:
        query_embedding = embeddings.embed_query(question)

    # ── ÉTAPE 3 : FILTRE THÉMATIQUE ─────────────────────────────────────────
    where_filter = None

    if theme:
        # Thème explicite — priorité absolue
        where_filter = {"theme": {"$eq": theme}}
        fetch_k = topk * 4  # plus large pour reranking
    elif agent_config and not no_filter:
        # Agent router a détecté des thèmes spécialisés
        where_filter = {"theme": {"$in": agent_config["themes"]}}
        fetch_k = topk * 4
    elif not no_filter and mode in MODE_AUTO_THEMES:
        # Auto-filtrage selon le mode
        where_filter = {"theme": {"$in": MODE_AUTO_THEMES[mode]}}
        fetch_k = topk * 4
    else:
        fetch_k = topk * 4  # pas de filtre — tout chercher

    # ── ÉTAPE 4 : CHROMA VECTOR SEARCH ─────────────────────────────────────
    try:
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(fetch_k, max(1, collection.count())),
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )
    except Exception as e:
        print(f"⚠️  Erreur ChromaDB : {e}")
        return [], [], []

    # Filtrer par distance MAX
    raw_items = []
    rejected = 0
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    ):
        if source and meta.get("source", "") != source:
            continue
        if dist > MAX_DISTANCE:
            rejected += 1
            continue
        raw_items.append((doc, meta, dist))

    if rejected > 0:
        print(f"  🚫 {rejected} chunk(s) rejeté(s) (distance > {MAX_DISTANCE})")

    if not raw_items:
        return [], [], []

    raw_docs   = [d for d, _, _ in raw_items]
    raw_metas  = [m for _, m, _ in raw_items]
    raw_dists  = [dist for _, _, dist in raw_items]

    # ── ÉTAPE 5 : HYBRID SEARCH (BM25) ─────────────────────────────────────
    if HYBRID_SEARCH_ENABLED and len(raw_docs) > 5:
        try:
            bm25_top = bm25_filter(question, raw_docs, top_n=min(15, len(raw_docs)))
            fused = reciprocal_rank_fusion(
                list(zip(raw_docs, raw_metas, raw_dists)),
                bm25_top,
                k=60
            )
            raw_docs   = [d for d, _, _ in fused]
            raw_metas  = [m for _, m, _ in fused]
            raw_dists  = [dist for _, _, dist in fused]
        except Exception as e:
            print(f"  ⚠️  Hybrid search ignoré : {e}")

    # ── ÉTAPE 6 : RERANKING CROSS-ENCODER ──────────────────────────────────
    if RERANKING_ENABLED and len(raw_docs) > topk:
        try:
            result = rerank(question, raw_docs, raw_metas, raw_dists, top_n=topk)
            if len(result) == 4:
                final_docs, final_metas, final_dists, rerank_scores = result
                print(f"  🎯 Reranking : {len(raw_docs)} → {len(final_docs)} chunks "
                      f"(scores: {rerank_scores[0]:.3f}→{rerank_scores[-1]:.3f})")
            else:
                final_docs, final_metas, final_dists = result[0], result[1], result[2]
                rerank_scores = []
        except Exception as e:
            print(f"  ⚠️  Reranking ignoré : {e}")
            final_docs, final_metas, final_dists = (
                raw_docs[:topk], raw_metas[:topk], raw_dists[:topk]
            )
    else:
        final_docs  = raw_docs[:topk]
        final_metas = raw_metas[:topk]
        final_dists = raw_dists[:topk]

    # ── ÉTAPE 7 : FORMAT DE SORTIE ──────────────────────────────────────────
    sources = []
    for meta, dist in zip(final_metas, final_dists):
        src   = meta.get("source", "inconnu")
        ttheme = meta.get("theme", "?")
        sources.append(f"{src} [{ttheme}]  (dist: {dist})")

    return final_docs, sources, final_dists


# ══════════════════════════════════════════════════════════════════════════════
# RÉSUMÉ DES CHANGEMENTS
# ══════════════════════════════════════════════════════════════════════════════
"""
AVANT (v2) :
  fetch_k = topk (8)
  ChromaDB → Top 8 → filtre distance → LLM
  Pas de reranking. Concept "LotL" = mauvais chunks.

APRÈS (v3) :
  fetch_k = topk * 4 (32)
  ChromaDB → Top 32 → filtre distance
  BM25 sur les 32 → RRF fusion
  Cross-encoder → Top 8 vraiment pertinents → LLM
  Query router → bon agent selon la question

GAINS ATTENDUS :
  Test LotL      : 8/10 → 9.5/10  (reranking conceptuel)
  Test CVE Forti : 9/10 → 9.5/10  (agent CVE + BM25 exact)
  Test Sigma     : 5/10 → 8/10    (après fix indexing)
  Questions mixed: +30% pertinence moyenne
"""
