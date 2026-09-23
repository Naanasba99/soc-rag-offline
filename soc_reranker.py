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
           distances: List[float], top_n: int = 8,
           min_score: float = -1.0, min_keep: int = 3,
           query_en: Optional[str] = None) -> Tuple[List, List, List, List, bool]:
    """
    Re-classe les chunks par pertinence réelle avec un cross-encoder.

    Args:
        query     : question originale
        docs      : chunks texte (Top 30 depuis ChromaDB)
        metadatas : métadonnées correspondantes
        distances : scores ChromaDB correspondants
        top_n     : nombre de chunks à retourner après reranking
        min_score : score cross-encoder minimal pour garder un chunk.
                    ms-marco-MiniLM-L-6-v2 donne des scores positifs pour
                    les paires pertinentes et négatifs pour le hors-sujet.
                    -1.0 est un seuil prudent ; monte-le (ex: 0.0) si tu
                    vois encore du bruit après ce premier réglage.
        min_keep  : nombre minimal de chunks gardés même si aucun ne
                    dépasse min_score (évite de retourner 0 résultat sur
                    une question légitime mais mal couverte par le corpus).
                    Ces chunks de repli restent dans le retour (utiles pour
                    afficher "voici le plus proche qu'on a trouvé"), mais
                    le flag `confident` ci-dessous signale à l'appelant
                    qu'aucun d'eux n'a réellement passé la barre de
                    pertinence — pour qu'il évite d'en nourrir le LLM comme
                    si c'était un contexte fiable (voir soc_ask_v2.retrieval).
        query_en  : traduction anglaise de `query`, si disponible (voir
                    translate_query_en ci-dessous). ms-marco-MiniLM-L-6-v2
                    est un cross-encoder ENTRAÎNÉ EN ANGLAIS UNIQUEMENT —
                    mesuré empiriquement : la même paire (question, contenu
                    MITRE identique) score -2.34 en français contre +6.78
                    en anglais. Sans ce paramètre, tout le contenu anglais
                    du corpus (MITRE/Sigma/CISA/Atomic — la majorité) est
                    quasi systématiquement rejeté par le reranker dès que
                    la question est posée en français. Quand fourni, on
                    score chaque paire dans les deux langues et on garde le
                    meilleur score, pour ne pénaliser ni le contenu anglais
                    (avec query_en) ni le contenu français (avec query).

    Returns:
        (docs_rerankés, metadatas_rerankés, distances_rerankées,
         scores_rerankés, confident) — confident=True si au moins un chunk
         a réellement dépassé min_score (pas seulement le repli min_keep).
    """
    if not docs:
        return docs, metadatas, distances, [], False

    reranker = get_reranker()
    if reranker is None:
        # Fallback : retourner les top_n sans reranking. Pas de score
        # cross-encoder disponible pour juger la pertinence, donc on ne
        # peut pas se prononcer sur la confiance : True par défaut pour ne
        # pas changer le comportement existant quand le reranker manque.
        return docs[:top_n], metadatas[:top_n], distances[:top_n], [], True

    # Paires (question, chunk) pour le cross-encoder
    pairs = [(query, doc[:512]) for doc in docs]  # max 512 tokens

    # Scores de pertinence (-inf à +inf, plus haut = plus pertinent)
    scores = reranker.predict(pairs, show_progress_bar=False)

    if query_en and query_en.strip().lower() != query.strip().lower():
        pairs_en   = [(query_en, doc[:512]) for doc in docs]
        scores_en  = reranker.predict(pairs_en, show_progress_bar=False)
        scores     = [max(s_fr, s_en) for s_fr, s_en in zip(scores, scores_en)]

    # Tri par score décroissant
    ranked = sorted(
        zip(scores, docs, metadatas, distances),
        key=lambda x: x[0],
        reverse=True
    )

    # Ne garde que les chunks au-dessus du seuil de pertinence (plafonné à
    # top_n). Si trop peu de chunks passent le seuil, on retombe sur les
    # meilleurs disponibles (min_keep) plutôt que de retourner une réponse
    # vide sur une question légitime mais peu couverte par le corpus —
    # mais `confident` reste False dans ce cas, pour que l'appelant sache
    # que ce repli n'est pas un vrai match.
    above_threshold = [item for item in ranked if item[0] >= min_score][:top_n]
    confident = len(above_threshold) > 0
    if len(above_threshold) >= min_keep:
        top = above_threshold
    else:
        top = ranked[:max(min_keep, len(above_threshold))][:top_n]

    rejected = len(ranked) - len(top)
    if rejected > 0:
        print(f"  🚫 {rejected} chunk(s) rejeté(s) par le reranker (score < {min_score})")
    if not confident:
        print(f"  ⚠️  Aucun chunk au-dessus du seuil de confiance ({min_score}) — "
              f"les {len(top)} chunk(s) retenu(s) sont un repli de dernier recours, pas un vrai match.")

    r_scores   = [round(float(s), 4) for s, _, _, _ in top]
    r_docs     = [d for _, d, _, _ in top]
    r_metas    = [m for _, _, m, _ in top]
    r_dists    = [dist for _, _, _, dist in top]

    return r_docs, r_metas, r_dists, r_scores, confident


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
        special = re.findall(r'cve-\d{4}-\d+|t\d{4}(?:\.\d+)?', text)
        # BUG CORRIGÉ : \w+ inclut l'underscore, donc "pass_the_hash" ou
        # "win_security_overpass_the_hash" devenait UN SEUL token opaque qui
        # ne matchait jamais "pass" ou "hash" séparés dans la requête — alors
        # que tout ce corpus (noms de fichiers Sigma, MITRE, hayabusa...) est
        # en snake_case. Résultat : BM25 était quasi aveugle sur tout ce
        # corpus (confirmé empiriquement — la requête "Pass-the-Hash" ne
        # matchait aucun des fichiers pass_the_hash.txt du corpus).
        # On traite underscore ET tiret comme des séparateurs de mots avant
        # de tokeniser, pour que "pass_the_hash" devienne ["pass","the","hash"].
        normalized = re.sub(r'[_\-]', ' ', text)
        words = re.findall(r'\b[a-z0-9]+\b', normalized)
        tokens = special + words
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


# ── TRADUCTION DE REQUÊTE (pour le reranker cross-lingue) ──────────────────
_translation_cache = {}


def translate_query_en(question: str, ollama_url: str = "http://localhost:11434",
                        model: str = "mistral") -> str:
    """
    Traduit la question en anglais pour le cross-encoder (voir la note dans
    rerank() : ms-marco-MiniLM-L-6-v2 est English-only et rejette du contenu
    anglais parfaitement pertinent quand la question est en français).

    Retourne la question originale si la traduction échoue (le double
    scoring dans rerank() devient alors un no-op silencieux, pas une
    erreur). Résultat mis en cache par question exacte pour éviter de
    retraduire deux fois la même requête (ex: rerank() principal +
    lexical_rescue() dans soc_ask_v2.py).
    """
    if question in _translation_cache:
        return _translation_cache[question]

    import urllib.request
    import json

    prompt = (
        f"Translate the following cybersecurity question to English. "
        f"Reply with ONLY the translated question, nothing else. "
        f"If it is already in English, repeat it unchanged.\n\n"
        f"Question: {question}"
    )
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 100}
    }).encode()

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
            translated = data.get("response", "").strip().strip('"')
            if translated:
                _translation_cache[question] = translated
                return translated
    except Exception:
        pass

    _translation_cache[question] = question
    return question


# ── DISTILLATION DE REQUÊTE (pour l'embedding vectoriel) ───────────────────
# Cas confirmé en pratique : une question réaliste d'analyste SOC — longue,
# multi-parties, avec du contexte narratif et des instructions de format
# ("distingue les faits des hypothèses", "cite uniquement les sources...")
# — s'embedde en un vecteur "moyenné" sur des dizaines de directions
# sémantiques différentes, ce qui noie le signal technique réellement
# discriminant. Mesuré : sur "Sur un poste Windows, j'observe powershell.exe
# lancé par winword.exe..." (question complète, ~500 caractères), AUCUN des
# 10 voisins vectoriels les plus proches n'est pertinent (dist 0.66-0.71,
# tous hors-sujet). La même question réduite à ses faits techniques
# ("powershell.exe lancé par winword.exe, activité malveillante ?") retrouve
# immédiatement T1059.001_PowerShell.txt en position 1 (dist 0.641). C'est
# le cas d'usage PRINCIPAL d'un assistant SOC (les analystes décrivent des
# scénarios, pas des mots-clés isolés), pas un cas limite.
#
# Principe : distiller la question en une requête courte et dense en entités
# techniques (noms de processus, outils, comportements observés) UNIQUEMENT
# pour l'étape d'embedding vectoriel — la question complète reste utilisée
# telle quelle pour le prompt final envoyé au LLM (qui doit répondre à
# TOUTES les parties de la vraie question), et pour le reranker cross-encoder
# (qui juge bien mieux avec le contexte complet — le problème est spécifique
# au premier étage, l'embedding, pas au jugement de pertinence en aval).
_distillation_cache = {}

# Seuil arbitraire mais justifié : en dessous, une question est déjà courte
# et dense (ex: "Explique T1059", "Qu'est-ce que Pass-the-Hash ?") — la
# distiller n'apporterait rien et ajouterait un appel LLM inutile sur la
# majorité des requêtes courtes, qui n'ont pas ce problème.
DISTILLATION_MIN_LENGTH = 120


def distill_retrieval_query(question: str, ollama_url: str = "http://localhost:11434",
                             model: str = "mistral") -> str:
    """
    NON UTILISÉE PAR retrieval() ACTUELLEMENT — conservée pour référence.
    L'hypothèse de départ (une question longue noie le signal, il faut la
    raccourcir) s'est révélée incomplète : la comparaison A/B a montré que
    c'est la LANGUE qui domine, pas la longueur (question EN complète,
    traduite mot pour mot : dist 0.471 ; distillation FR/EN : dist
    0.51-0.59 et instable run-to-run même à température 0). retrieval()
    utilise donc translate_query_en (traduction, tâche contrainte et fiable)
    pour l'embedding, pas cette fonction (résumé, tâche ouverte sujette à
    dérive du modèle). Gardée au cas où un besoin de distillation pure
    (indépendant de la langue) se représenterait, mais pas comme mécanisme
    de premier recours.

    Réduit une question longue/narrative à ses entités techniques
    essentielles, pour l'utiliser comme requête d'embedding à la place de
    la question complète (voir note ci-dessus). Retourne la question
    originale si elle est déjà courte, ou si la distillation échoue.
    """
    if len(question) < DISTILLATION_MIN_LENGTH:
        return question
    if question in _distillation_cache:
        return _distillation_cache[question]

    import urllib.request
    import json

    # Mesuré A/B sur le même cas réel (powershell.exe lancé par winword.exe) :
    # une phrase naturelle anglaise embarque nettement mieux avec
    # nomic-embed-text qu'une liste de mots-clés séparés par virgules —
    # meilleure distance 0.471 (et trouve la bonne règle Sigma) contre 0.524
    # pour la liste de mots-clés. nomic-embed-text est visiblement optimisé
    # pour du langage naturel, pas pour des sacs de mots. La traduction en
    # anglais est volontaire (comme pour le reranker cross-lingue) : le
    # corpus est majoritairement anglais (MITRE/Sigma/CISA/Atomic).
    # L'exemple concret ci-dessous cadre le style attendu (une phrase
    # factuelle et dense, pas une liste), et le troncage en Python après
    # coup borne la longueur même si le modèle déborde quand même.
    prompt = (
        "Rewrite this SOC analyst question as ONE short, natural English "
        "sentence stating only the technical facts observed (process/file "
        "names, IPs, protocols, actions). No interpretation, no added "
        "facts, no meta-instructions about answer format or sourcing.\n\n"
        "Example:\n"
        "Question: Sur un serveur Linux j'observe une connexion SSH depuis "
        "une IP inconnue suivie de la création d'un cron job suspect, "
        "quelles hypothèses envisager et quelles traces examiner ?\n"
        "Sentence: SSH connection from an unknown IP followed by creation "
        "of a suspicious cron job on a Linux server.\n\n"
        f"Question: {question}\n"
        "Sentence:"
    )
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        # stop sur "." : empêche le modèle de dériver dans une deuxième
        # phrase après avoir déjà correctement formulé la première (observé
        # en pratique) — il s'arrête net au premier point plutôt que de se
        # faire couper à mi-mot par num_predict après avoir déjà ajouté du
        # bruit interprétatif non demandé.
        "options": {"temperature": 0.0, "num_predict": 60, "stop": ["."]}
    }).encode()

    try:
        req = urllib.request.Request(
            f"{ollama_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
            distilled = data.get("response", "").strip().strip('"')
            # Garde-fou dur : observé en pratique que mistral formule une
            # première phrase propre et factuelle, PUIS dérive dans une
            # deuxième ("... on a Windows system. Consider examining
            # PowerShell logs...") qui réintroduit exactement le bruit
            # interprétatif que le prompt lui demande d'éviter — et cette
            # deuxième phrase se fait souvent couper à mi-mot par
            # num_predict. On ne garde que la première phrase complète
            # (jusqu'au premier point), avec un plafond de mots en filet de
            # sécurité si même la première phrase déborde. Cohérent avec le
            # principe déjà appliqué ailleurs (porte de confiance au
            # retrieval) : ne pas faire reposer la fiabilité sur la seule
            # docilité du LLM.
            first_sentence = distilled.split(".")[0].strip()
            distilled = " ".join(first_sentence.split()[:25])
            # Deuxième garde-fou : même à température 0, deux appels
            # identiques ont produit des sorties très différentes en
            # pratique (un paragraphe complet une fois, le seul mot
            # "PowerShell." une autre) — la génération locale n'est pas
            # parfaitement reproductible. Une distillation à moins de 4 mots
            # a de bonnes chances d'avoir perdu l'essentiel des faits de la
            # question (ex: juste "PowerShell" au lieu de "PowerShell.exe
            # launched by Winword.exe...") ; dans ce cas, la question
            # complète est encore un meilleur pari pour l'embedding qu'une
            # distillation appauvrie.
            if distilled and len(distilled.split()) >= 4:
                _distillation_cache[question] = distilled
                return distilled
    except Exception:
        pass

    _distillation_cache[question] = question
    return question


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
            r"T1053|T1547|T1055|T1136",
            r"ransomware|rançongiciel|chiffrement.*impact",
            r"T1486|T1490|T1489|T1562"        ],
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
        # 'dfir' ajouté : confirmé en pratique que "Cobalt Strike" (l'un des
        # mots-clés qui déclenche justement cet agent) vit dans le thème
        # 'dfir' (COBALTSTRIKE.txt, BEACONING.txt, detectioneterradicationimplantC2.txt) —
        # sans ce thème, l'agent THREAT_HUNT ne pouvait structurellement
        # jamais trouver ce contenu, quel que soit le retrieval.
        "themes": ["mitre", "blog", "abuse", "anssi", "dfir"],
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
