#!/usr/bin/env python3
"""
SOC RAG ELITE V2 — Assistant SOC/DFIR/Red/Blue Team local
BLINDÉ v2.1 — Anti-dérive, prompts stricts, filtrage intelligent par mode

Usage :
  python3.13 soc_ask_v2.py --rebuild
  python3.13 soc_ask_v2.py --mode blue  --question "comment détecter un pass-the-hash"
  python3.13 soc_ask_v2.py --mode red   --question "techniques de pivoting Windows"
  python3.13 soc_ask_v2.py --mode hunt  --question "chasser Cobalt Strike dans les logs"
  python3.13 soc_ask_v2.py --mode extract --question "règles Sigma pour Kerberoasting"
  python3.13 soc_ask_v2.py --mode blue  --theme mitre --question "T1550 Pass-the-Hash"
  python3.13 soc_ask_v2.py --mode blue  --no-filter --question "..."  (tout chercher)
  python3.13 soc_ask_v2.py  (menu interactif)
"""

import os
import re
import argparse
from tqdm import tqdm
import chromadb
try:
    from soc_reranker import rerank, bm25_filter, reciprocal_rank_fusion, route_query, hyde_query, translate_query_en
    RERANKING_ENABLED     = True
    HYBRID_SEARCH_ENABLED = True
    HYDE_ENABLED          = False
except ImportError:
    RERANKING_ENABLED     = False
    HYBRID_SEARCH_ENABLED = False
    HYDE_ENABLED          = False
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings

# ===================== CONFIG =====================
SOC_BRAIN_PATH = os.path.expanduser("~/soc-brain")
DB_PATH        = os.path.expanduser("~/CYBER/soc-stack/soc-chroma-db-v2")
os.makedirs(DB_PATH, exist_ok=True)

BATCH_SIZE  = 200
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL   = "mistral"

# Seuil de distance ChromaDB — au-delà, le chunk est rejeté comme hors-sujet
# 0.0 = identique, 1.0 = très proche, 1.5 = lointain, 2.0 = sans rapport
MAX_DISTANCE = 1.3

# ===================== CHUNKING =====================
# chunk_size relevé de 600 → 1200 pour préserver le contexte des fichiers
# MITRE/CISA/NVD fortement structurés (en-tête ID/Nom/Tactique/Plateformes +
# DESCRIPTION). À 600, l'en-tête (générique, quasi-identique d'un fichier à
# l'autre) se retrouvait souvent isolé dans son propre chunk sans la
# description qui le rend distinctif sémantiquement — ce qui causait des
# faux-positifs au retrieval entre techniques MITRE différentes.
# overlap monté à 150 pour garder un ratio overlap/chunk_size cohérent
# avec l'ancien réglage (80/600 ≈ 13% → 150/1200 = 12.5%).
CHUNK_SIZE    = 1200
CHUNK_OVERLAP = 150

# ===================== MAPPING DOSSIER → THÈME =====================
# COMPLET — tous les dossiers de soc-brain sont couverts
FOLDER_THEME_MAP = {
    # === Sources Threat Intelligence officielles ===
    "mitre_attack":            "mitre",
    "mitre_car":               "mitre",
    "cisa_kev":                "cisa",
    "nvd_cve":                 "nvd",
    "sigma_rules":             "sigma",
    "sigma_rules_git":         "sigma",
    "sigma_extracted":         "sigma",
    "hayabusa":                "hayabusa",
    "hayabusa_rules":          "hayabusa",
    "atomic_red_team":         "atomic",
    "mordor":                  "dfir",
    "threat_intel_collective": "blog",
    "threat_blogs":            "blog",
    "anssi":                   "anssi",
    "abuse_ch":                "abuse",

    # === Ressources défensives / SOC ===
    "playbooks":               "playbook",
    "dfir":                    "dfir",
    "detection":               "detection",
    "sysmon":                  "detection",
    "wazuh":                   "detection",
    "suricata":                "detection",
    "hardening":               "hardening",

    # === Références techniques cyber ===
    "ssh":                     "ssh",
    "pivoting":                "pivoting",
    "network":                 "network",
    "reseau":                  "network",
    "bash":                    "bash",
    "processus":               "linux_ref",
    "linux":                   "linux_ref",
    "rhcsa":                   "linux_ref",

    # === Livres / divers ===
    "books-cyber":             "books_cyber",
    "books-afrique":           "books_general",
    "books-geop":              "books_general",
    "misc":                    "misc",
    "divers":                  "misc",
    "reference":               "reference",
}

# ===================== THÈMES AUTO PAR MODE =====================
# Quand pas de --theme : on restreint automatiquement aux sources pertinentes
# Cela évite que les livres généraux et références Linux polluent les réponses cyber
MODE_AUTO_THEMES = {
    "blue": [
        "mitre", "sigma", "cisa", "nvd", "dfir", "playbook",
        "detection", "hayabusa", "abuse", "blog", "anssi",
        "atomic", "ssh", "hardening", "network"
    ],
    "red": [
        "mitre", "sigma", "atomic", "pivoting", "dfir",
        "network", "hayabusa", "bash"
    ],
    "hunt": [
        "mitre", "sigma", "hayabusa", "dfir", "abuse", "blog",
        "playbook", "detection", "anssi", "atomic"
    ],
    "extract": [
        "mitre", "sigma", "cisa", "nvd", "hayabusa", "atomic",
        "dfir", "detection", "playbook", "anssi"
    ],
    "synthesis": [
        "mitre", "sigma", "cisa", "nvd", "dfir", "blog",
        "playbook", "abuse", "anssi", "atomic", "hayabusa",
        "detection", "books_cyber"
    ],
    "checklist": [
        "dfir", "playbook", "mitre", "sigma", "cisa",
        "detection", "anssi", "hardening", "network", "ssh"
        # network + ssh ajoutés : tout le contenu SSH réel du corpus
        # (SSHMISSIONELITE.txt, SSH14JOURSFORMATION.txt, PROTOCOLDURGENCESSH.txt...)
        # vit dans le dossier reseau/ -> thème 'network' (detect_theme() tague
        # par dossier, pas par nom de fichier), donc une question "comment
        # durcir SSH" en mode checklist ne pouvait structurellement jamais
        # trouver ce contenu — bug confirmé empiriquement (0 résultat pertinent
        # malgré du contenu existant), pas un problème de retrieval.
    ],
}

# Thèmes considérés "généraux" — avertissement si présents
GENERAL_THEMES = {"misc", "books_general", "linux_ref", "reference"}

# ===================== INIT CLIENT =====================
client = chromadb.Client(settings=chromadb.config.Settings(
    persist_directory=DB_PATH,
    is_persistent=True
))


def get_collection():
    return client.get_or_create_collection(name="soc_elite")


collection = get_collection()


def get_embeddings():
    return OllamaEmbeddings(model=EMBED_MODEL)


# ===================== PARSE ARGS =====================
def parse_args():
    parser = argparse.ArgumentParser(
        description="SOC RAG Elite V2 — Blindé v2.1",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--mode", type=str,
                        choices=["extract", "synthesis", "checklist", "red", "blue", "hunt"],
                        help="Mode de réponse")
    parser.add_argument("--theme", type=str,
                        help="Forcer un thème : mitre, cisa, sigma, hayabusa, dfir, playbook...")
    parser.add_argument("--source", type=str,
                        help="Filtrer par nom de fichier précis")
    parser.add_argument("--topk", type=int, default=8,
                        help="Nombre de chunks à récupérer (défaut : 8)")
    parser.add_argument("--question", type=str,
                        help="Question à poser au RAG")
    parser.add_argument("--rebuild", action="store_true",
                        help="Reconstruire la base vectorielle depuis ~/soc-brain")
    parser.add_argument("--stats", action="store_true",
                        help="Afficher les statistiques de la base")
    parser.add_argument("--no-filter", action="store_true",
                        help="Désactiver le filtrage auto par mode (chercher dans TOUT)")
    return parser.parse_args()


# ===================== MENU INTERACTIF =====================
def menu_interactif():
    print("\n" + "="*56)
    print("   SOC RAG ELITE V2 — Menu interactif (v2.1 Blindé)")
    print("="*56)
    print("Modes :")
    print("  1) Extraction stricte  — Event IDs, commandes, règles exactes")
    print("  2) Synthèse experte    — explication pédagogique complète")
    print("  3) Checklist SOC       — liste opérationnelle prête à l'emploi")
    print("  4) Red Team            — attaques, pivoting, persistence")
    print("  5) Blue Team           — détection, logs, SIEM, Sigma")
    print("  6) Threat Hunting      — hypothèses, IOC, requêtes de chasse")
    print()

    choice   = input("Mode (1-6) : ").strip()
    mapping  = {"1": "extract", "2": "synthesis", "3": "checklist",
                "4": "red",     "5": "blue",       "6": "hunt"}
    mode     = mapping.get(choice, "synthesis")
    question = input("\nQuestion : ").strip()

    print()
    print("Thèmes disponibles (laisser vide = filtrage auto selon le mode) :")
    print("  mitre  cisa  nvd  sigma  hayabusa  atomic  dfir  playbook")
    print("  blog   abuse anssi  detection  ssh  hardening  network")
    theme = input("Thème (Entrée = auto) : ").strip()

    topk_raw = input("Chunks (défaut 8) : ").strip()

    return {
        "mode":      mode,
        "question":  question,
        "theme":     theme if theme else None,
        "topk":      int(topk_raw) if topk_raw.isdigit() else 8,
        "source":    None,
        "no_filter": False,
    }


# ===================== DÉTECTION DU THÈME =====================
def detect_theme(filepath: str) -> str:
    """Détecte le thème d'un fichier selon son chemin complet."""
    path_lower = filepath.lower().replace("\\", "/")

    for folder, theme in FOLDER_THEME_MAP.items():
        if f"/{folder}/" in path_lower or path_lower.endswith(f"/{folder}"):
            return theme

    fname = os.path.basename(path_lower)
    if re.search(r"t\d{4}", fname):     return "mitre"
    if "cve-" in fname:                  return "nvd"
    if "sigma" in fname:                 return "sigma"
    if "hayabusa" in fname:              return "hayabusa"
    if "atomic" in fname:                return "atomic"
    if "playbook" in fname:              return "playbook"
    if "ransomware" in fname:            return "dfir"
    if "anssi" in fname:                 return "anssi"
    if "ssh" in fname:                   return "ssh"
    if "network" in fname:               return "network"
    if "wazuh" in fname:                 return "detection"
    if "sysmon" in fname:                return "detection"
    if "suricata" in fname:              return "detection"

    return "misc"


# ===================== BUILD DB =====================
def build_db():
    global collection

    print("\n" + "="*56)
    print("  REBUILD BASE VECTORIELLE — v2.1 Blindé")
    print("="*56)
    print("📚 Chargement des fichiers .txt et .md...")

    all_docs = []

    for ext, glob_pattern in [("txt", "**/*.txt"), ("md", "**/*.md")]:
        try:
            loader = DirectoryLoader(
                SOC_BRAIN_PATH,
                glob=glob_pattern,
                loader_cls=TextLoader,
                loader_kwargs={"encoding": "utf-8", "autodetect_encoding": True},
                silent_errors=True
            )
            docs = loader.load()
            all_docs.extend(docs)
            print(f"  ✅ {len(docs)} fichiers .{ext} chargés")
        except Exception as e:
            print(f"  ⚠️  Erreur chargement .{ext} : {e}")

    if not all_docs:
        print("❌ Aucun fichier trouvé dans ~/soc-brain")
        print("   Lance d'abord : python3.13 soc_feed.py")
        return

    print(f"\n  📄 Total : {len(all_docs)} fichiers")

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n---\n", "\n", " "]
    )
    chunks = splitter.split_documents(all_docs)
    print(f"  🔪 {len(chunks)} chunks créés")

    print("\n🔢 Vectorisation en cours...")
    embeddings = get_embeddings()

    try:
        client.delete_collection(name="soc_elite")
        print("  🗑️  Ancienne collection supprimée")
    except Exception:
        pass

    collection = client.get_or_create_collection(name="soc_elite")

    texts        = [doc.page_content for doc in chunks]
    metadatas    = []
    theme_counts = {}

    for doc in chunks:
        source   = doc.metadata.get("source", "inconnu")
        basename = os.path.basename(source)
        theme    = detect_theme(source)
        theme_counts[theme] = theme_counts.get(theme, 0) + 1
        metadatas.append({
            "source": basename,
            "theme":  theme,
            "path":   source,
        })

    total_batches = (len(chunks) + BATCH_SIZE - 1) // BATCH_SIZE
    print(f"\n  📦 Insertion par batches de {BATCH_SIZE}...")

    for i in tqdm(range(0, len(texts), BATCH_SIZE), total=total_batches, desc="Indexation"):
        batch_texts = texts[i:i + BATCH_SIZE]
        batch_metas = metadatas[i:i + BATCH_SIZE]
        batch_ids   = [str(i + j) for j in range(len(batch_texts))]
        batch_vecs  = embeddings.embed_documents(batch_texts)
        collection.add(
            documents=batch_texts,
            metadatas=batch_metas,
            ids=batch_ids,
            embeddings=batch_vecs
        )

    print(f"\n✅ Base vectorielle créée — {len(chunks)} chunks indexés")
    print(f"   Fichiers : {len(all_docs)}")
    print(f"\n   Répartition par thème :")
    for theme, count in sorted(theme_counts.items(), key=lambda x: -x[1]):
        flag = " ⚠️  (général)" if theme in GENERAL_THEMES else ""
        print(f"     {theme:<22} : {count:>5} chunks{flag}")


# ===================== STATS =====================
def show_stats():
    try:
        count = collection.count()
        print(f"\n📊 STATISTIQUES BASE VECTORIELLE")
        print(f"  Collection      : soc_elite")
        print(f"  Chunks indexés  : {count}")
        print(f"  Modèle embed    : {EMBED_MODEL}")
        print(f"  Modèle LLM      : {LLM_MODEL}")
        print(f"  DB path         : {DB_PATH}")
        print(f"  Seuil distance  : {MAX_DISTANCE} (chunks > seuil → rejetés)")
        print(f"  Chunk size      : {CHUNK_SIZE} (overlap {CHUNK_OVERLAP})")
        print(f"\n  Thèmes cyber    : {', '.join(sorted(MODE_AUTO_THEMES['blue']))}")
        print(f"  Thèmes généraux : {', '.join(sorted(GENERAL_THEMES))}")
    except Exception as e:
        print(f"⚠️  Impossible de lire les stats : {e}")


# ===================== BOOST FICHIERS "APERÇU" (README/index) ==============
# Cas confirmé en pratique : "Que fait Atomic Red Team ?" — le corpus contient
# un README.md qui répond exactement à la question ("Atomic Red Team™ is a
# library of tests mapped to the MITRE ATT&CK framework..."), mais le thème
# 'atomic' contient aussi 262 autres fichiers atomics_TXXXX.yaml.txt, tous
# des tests structurés très proches entre eux dans l'espace vectoriel — au
# point que même en filtrant sur le seul thème 'atomic' (sans dilution
# multi-thème), AUCUN des 15 chunks les plus proches du README n'est le
# README lui-même (vérifié empiriquement : distances 0.479-0.486 pour les
# 15 fichiers atomics_*, le README n'apparaît nulle part dans ce top-15).
# Contrairement au cas Pass-the-Hash, ce n'est pas un problème cross-lingue
# (tout est en anglais ici) — c'est la densité du cluster de chunks très
# similaires qui noie le seul document de synthèse. Le filet lexical BM25
# sur les noms de fichiers ne peut pas non plus le retrouver : "README.md"
# ne contient aucun mot-clé thématique.
# Solution : pour une question de type "qu'est-ce que X / que fait X",
# on injecte D'OFFICE les fichiers de type README/index/aperçu du périmètre
# thématique actif dans le pool soumis au reranker — pas comme un match
# garanti (contrairement à l'injection par ID exact), juste pour leur
# garantir une place dans la compétition dont le retrieval vectoriel les
# aurait sinon exclus d'office. Le reranker cross-lingue tranche ensuite
# normalement s'ils sont vraiment pertinents.
DEFINITIONAL_PATTERN = re.compile(
    r"^\s*(qu['’]est-ce que|que fait|c['’]est quoi|what is|what does|explique|explain)\b",
    re.IGNORECASE
)
INDEX_FILENAME_PATTERN = re.compile(r"(^|/)(readme|_index|_all|_about|index)", re.IGNORECASE)


def is_definitional_question(question: str) -> bool:
    return bool(DEFINITIONAL_PATTERN.search(question.strip()))


def find_overview_files(where_filter: dict, exclude_docs: set, max_files: int = 15):
    # max_files=15 (pas 5) : mesuré empiriquement que le périmètre multi-thème
    # d'un mode comme 'red' (8 thèmes) contient déjà 6 fichiers aperçu à lui
    # seul — un plafond bas coupait le vrai fichier pertinent avant qu'il
    # n'atteigne le reranker (cas confirmé : README.md d'Atomic Red Team
    # exclu par le plafond à 5, alors qu'il score +9.29 une fois évalué).
    # Le coût d'inclure quelques fichiers de plus est négligeable (chacun
    # n'est qu'un chunk de plus dans un pool de reranking déjà bien plus
    # gros), donc mieux vaut pécher par excès d'inclusion ici.
    """Retourne jusqu'à max_files chunks provenant de fichiers 'aperçu'
    (README/index/_all/_about) dans le périmètre thématique actif, pour
    leur garantir une place dans le pool du reranker (voir note ci-dessus).
    Un seul chunk par fichier (le premier rencontré) — un README est
    généralement court, pas besoin de plusieurs chunks.

    BUG CORRIGÉ : le dédoublonnage se faisait sur le seul nom de fichier
    (`source`, un basename), pas sur le chemin complet. Or plusieurs projets
    différents partagent des noms génériques identiques — ex: le README.md
    d'Atomic Red Team ET celui de Hayabusa portent tous deux le nom
    "README.md". Le dédoublonnage par basename gardait arbitrairement le
    premier rencontré (Hayabusa, par accident d'ordre d'itération) et
    excluait silencieusement celui qui répondait vraiment à la question
    (Atomic Red Team) — avant même que le reranker n'ait la chance de les
    départager. On déduplique maintenant par chemin complet (`path`, la
    métadonnée qui conserve le dossier d'origine avant troncature en
    basename dans build_db()) : les deux README distincts sont conservés
    comme candidats séparés, et c'est le reranker cross-lingue qui tranche
    lequel est réellement pertinent pour la question posée."""
    try:
        pool = collection.get(where=where_filter, include=["documents", "metadatas"])
    except Exception:
        return []

    seen_paths = set()
    found = []
    for doc, meta in zip(pool.get("documents", []), pool.get("metadatas", [])):
        if doc in exclude_docs:
            continue
        fname = meta.get("source", "")
        # 'path' est le chemin complet original ; à défaut (anciens index
        # sans ce champ), on retombe sur le basename comme avant.
        full_path = meta.get("path", fname)
        if full_path in seen_paths:
            continue
        if INDEX_FILENAME_PATTERN.search(fname):
            seen_paths.add(full_path)
            found.append((doc, meta, None))
            if len(found) >= max_files:
                break
    return found


# ===================== DÉTECTION D'ID EXACT (T-CODE / CVE) =====================
# nomic-embed-text discrimine mal les identifiants courts comme "T1059" :
# une requête "Explique T1059" peut renvoyer T1052 plus proche en distance
# vectorielle que T1059 lui-même (confirmé empiriquement — voir notes projet).
# Pour ces cas, on fait un matching lexical exact AVANT la requête vectorielle
# et on injecte le(s) chunk(s) correspondant(s) en tête de liste, plutôt que
# de dépendre uniquement de l'embedding pour les retrouver.
ID_PATTERNS = [
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE),   # T1059, T1059.001
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),     # CVE-2024-12345
]


def detect_exact_id(question: str) -> list:
    """Extrait les identifiants techniques exacts (T-codes MITRE, CVE-IDs)
    mentionnés explicitement dans la question. Retourne une liste de
    chaînes en majuscules, sans doublons, dans l'ordre d'apparition."""
    found = []
    for pattern in ID_PATTERNS:
        for match in pattern.finditer(question):
            ident = match.group(0).upper()
            if ident not in found:
                found.append(ident)
    return found


def fetch_by_exact_id(ident: str, theme: str = None, max_files: int = 2,
                       chunks_per_file: int = 2):
    """Récupère directement les chunks dont le nom de fichier source
    correspond à l'identifiant exact demandé, indépendamment de l'embedding.
    Retourne une liste de tuples (doc, meta, dist) avec dist=0.0 (score
    parfait artificiel) pour garantir leur survie au reranking en aval.

    Priorité de matching :
      1. Fichier exact (ex: question "T1059" → "T1059_Command_and_..."),
         identifié par le nom de fichier qui commence par l'ID suivi
         immédiatement d'un underscore (séparateur entre ID et nom).
      2. Sous-techniques (ex: "T1059.003_Windows_Command_Shell") seulement
         si aucun fichier exact n'a été trouvé, ou en complément limité.
    Le matching est fait par fichier distinct, pas par chunk, pour éviter
    qu'un même fichier soit injecté plusieurs fois en doublon si plusieurs
    de ses chunks matchent la condition.

    NOTE PERF : collection.get() charge tout le thème filtré en mémoire
    avant le filtrage Python sur le nom de fichier (ChromaDB ne supporte
    pas nativement un "contains" fiable sur les métadonnées). Sur un thème
    volumineux (ex: sigma, ~8800 chunks), ça ajoute un léger délai. Comme
    cette fonction n'est appelée que si un ID exact est détecté dans la
    question (pas à chaque requête), c'est un compromis acceptable pour
    l'instant. À optimiser plus tard si la latence devient gênante (ex:
    indexer une table id→chunk_ids séparée au moment du build_db()).
    """
    where_clause = {"theme": {"$eq": theme}} if theme else None
    try:
        # ChromaDB ne supporte pas le "contains" sur les métadonnées de façon
        # native et fiable selon les versions ; on récupère un lot large filtré
        # par thème (ou tout si pas de thème) puis on filtre côté Python sur
        # le nom de fichier, ce qui est fiable quelle que soit la version.
        results = collection.get(
            where=where_clause,
            include=["documents", "metadatas"]
        )
    except Exception as e:
        print(f"  ⚠️  Erreur lors de la recherche par ID exact '{ident}' : {e}")
        return []

    ident_normalized = ident.replace("-", "_").upper()
    exact_file_chunks = {}      # nom de fichier exact → liste de (doc, meta)
    subtechnique_chunks = {}    # nom de fichier sous-technique → liste de (doc, meta)

    for doc, meta in zip(results.get("documents", []), results.get("metadatas", [])):
        src_raw = meta.get("source", "")
        src = src_raw.upper().replace("-", "_")
        if not src.startswith(ident_normalized):
            continue
        # Fichier exact : "T1059_..." (underscore juste après l'ID, pas un point)
        if src.startswith(ident_normalized + "_"):
            exact_file_chunks.setdefault(src_raw, []).append((doc, meta))
        # Sous-technique : "T1059.003_..." (point juste après l'ID)
        elif src.startswith(ident_normalized + "."):
            subtechnique_chunks.setdefault(src_raw, []).append((doc, meta))

    matches = []
    # Priorité 1 : fichier(s) exact(s)
    for fname, chunks in list(exact_file_chunks.items())[:max_files]:
        for doc, meta in chunks[:chunks_per_file]:
            matches.append((doc, meta, 0.0))

    # Priorité 2 : sous-techniques, seulement pour compléter si peu/pas de
    # résultats exacts trouvés (ex: l'utilisateur a demandé "T1059" mais le
    # corpus n'a que des sous-techniques, pas de fichier parent).
    if not exact_file_chunks:
        for fname, chunks in list(subtechnique_chunks.items())[:max_files]:
            for doc, meta in chunks[:chunks_per_file]:
                matches.append((doc, meta, 0.0))

    return matches


# ===================== FILET DE SECOURS LEXICAL (BM25 sur noms de fichiers) ==
# Cas confirmé en pratique : "Qu'est-ce que Pass-the-Hash ?" — le contenu
# existe bien dans la base (T1550.002_Pass_the_Hash.txt, plusieurs règles
# Sigma pass_the_hash), mais l'embedding nomic-embed-text rapproche une
# question en langage naturel de guides génériques de brute-force plutôt que
# de la fiche technique/règle correspondante : dans le pool vectoriel top-K,
# ces fichiers pourtant pertinents ne remontent jamais, donc ni le filtre de
# distance ni le reranker cross-encoder ne les voient jamais passer.
# Comme les fichiers de ce corpus sont nommés très littéralement d'après leur
# sujet (T1550.002_Pass_the_Hash.txt, win_security_pass_the_hash_2.txt...),
# une recherche BM25 sur les NOMS DE FICHIERS (pas le contenu, trop bruité
# par des mots courants comme "hash" qui apparaît dans des tonnes de fichiers
# IOC/hashcat sans rapport) retrouve ces fichiers de façon fiable. On ne
# s'y fie pas aveuglément : les candidats trouvés repassent par le même
# reranker cross-encoder que le chemin normal avant d'être acceptés.
def lexical_rescue(question: str, where_filter: dict, topk: int, exclude_docs: set,
                    query_en: str = None, bm25_query: str = None):
    """Tente de retrouver des chunks pertinents par matching lexical sur les
    noms de fichiers quand la recherche vectorielle n'a rien trouvé de fiable.
    Retourne (docs, metas, dists, scores, confident) — même contrat que rerank().
    bm25_query : requête à utiliser pour le matching BM25 (typiquement la
    traduction anglaise, `query_en` — les noms de fichiers du corpus sont
    en anglais). Retombe sur `question` si non fournie."""
    if not (HYBRID_SEARCH_ENABLED and RERANKING_ENABLED):
        return [], [], [], [], False
    try:
        pool = collection.get(where=where_filter, include=["documents", "metadatas"])
    except Exception as e:
        print(f"  ⚠️  Filet lexical : erreur ChromaDB : {e}")
        return [], [], [], [], False

    by_file = {}
    for doc, meta in zip(pool.get("documents", []), pool.get("metadatas", [])):
        fname = meta.get("source", "")
        by_file.setdefault(fname, []).append((doc, meta))
    if not by_file:
        return [], [], [], [], False

    filenames = list(by_file.keys())
    top_idx = bm25_filter(bm25_query or question, filenames, top_n=min(15, len(filenames)))

    cand_docs, cand_metas, cand_dists = [], [], []
    for i in top_idx:
        for doc, meta in by_file[filenames[i]][:2]:   # max 2 chunks/fichier
            if doc in exclude_docs:
                continue
            cand_docs.append(doc)
            cand_metas.append(meta)
            cand_dists.append(None)  # pas de distance vectorielle pour ces candidats

    if not cand_docs:
        return [], [], [], [], False

    print(f"  🔤 Filet lexical (BM25 filenames) : {len(cand_docs)} candidat(s) trouvé(s), vérification par reranker...")
    r_docs, r_metas, r_dists, r_scores, confident = rerank(
        question, cand_docs, cand_metas, cand_dists, top_n=topk, query_en=query_en
    )
    if confident:
        print(f"  ✅ Filet lexical : {len(r_docs)} chunk(s) confirmé(s) pertinent(s) par le reranker")
    return r_docs, r_metas, r_dists, r_scores, confident


# ===================== RETRIEVAL V3 — HYBRID + RERANKING =====================
def retrieval(question: str, mode: str, theme: str = None, topk: int = 8,
              source: str = None, no_filter: bool = False):
    from collections import Counter
    embeddings = get_embeddings()
    # Traduction anglaise de la question — sert À LA FOIS au reranker
    # cross-lingue (voir la note dans soc_reranker.rerank : le cross-encoder
    # est English-only) ET à l'embedding vectoriel lui-même.
    #
    # Comparaison A/B mesurée sur un cas réel (question longue et narrative
    # d'analyste : "powershell.exe lancé par winword.exe, connexion réseau
    # sortante...") :
    #   - question FR complète, brute           : dist 0.66  (rien de pertinent)
    #   - distillation FR/EN par LLM             : dist 0.51-0.59 (instable
    #     d'un run à l'autre, voir git blame — la tâche "résume en ne
    #     gardant que les faits" laisse trop de prise à la dérive du modèle)
    #   - question EN complète, TRADUITE mot pour mot (pas résumée) : dist
    #     0.471, trouve une vraie règle de détection pertinente
    # Conclusion : c'est la LANGUE de la requête qui domine, pas sa longueur
    # — traduire (tâche contrainte, fiable) marche mieux et est bien plus
    # stable que distiller (tâche ouverte, sujette à dérive). Et comme
    # query_en est de toute façon déjà calculée pour le reranker, la
    # réutiliser pour l'embedding n'ajoute aucun appel LLM supplémentaire.
    query_en = translate_query_en(question, model=LLM_MODEL) if RERANKING_ENABLED else None
    query_for_embedding = query_en if query_en else question
    agent_config = None
    if not theme and not no_filter:
        agent_config = route_query(question)
        if agent_config:
            print(f"  🤖 Agent détecté : {agent_config['agent_name']}")
            topk = max(topk, agent_config.get("topk_boost", topk))
    if HYDE_ENABLED and not theme:
        hyde_text = hyde_query(question, model=LLM_MODEL)
        query_embedding = embeddings.embed_query(hyde_text)
    else:
        query_embedding = embeddings.embed_query(query_for_embedding)
    where_filter = None
    if theme:
        where_filter = {"theme": {"$eq": theme}}
        fetch_k = topk * 4
    elif agent_config and not no_filter:
        where_filter = {"theme": {"$in": agent_config["themes"]}}
        fetch_k = topk * 4
    elif not no_filter and mode in MODE_AUTO_THEMES:
        where_filter = {"theme": {"$in": MODE_AUTO_THEMES[mode]}}
        fetch_k = topk * 4
    else:
        fetch_k = topk * 4
    try:
        results = collection.query(
            query_embeddings=[query_embedding],
            n_results=min(fetch_k, max(1, collection.count())),
            where=where_filter,
            include=["documents", "metadatas", "distances"]
        )
    except Exception as e:
        print(f"⚠️  Erreur ChromaDB : {e}")
        return [], [], [], False

    # ── Injection par ID exact (T-code MITRE / CVE) ──────────────────────
    # Si la question mentionne un identifiant exact, on le récupère par
    # matching lexical direct plutôt que de compter uniquement sur
    # l'embedding, qui peut mal discriminer ces identifiants courts.
    exact_ids = detect_exact_id(question)
    injected_items = []
    if exact_ids:
        # On ne filtre par thème que si un thème a été explicitement forcé ;
        # sinon on cherche sur toute la collection (le nom de fichier seul
        # suffit à identifier la bonne technique, peu importe le thème).
        search_theme = theme if theme else None
        for ident in exact_ids:
            found = fetch_by_exact_id(ident, theme=search_theme)
            if found:
                print(f"  🎯 ID exact détecté '{ident}' → {len(found)} chunk(s) injecté(s) directement")
                injected_items.extend(found)
            else:
                print(f"  ℹ️  ID exact détecté '{ident}' mais aucun fichier correspondant trouvé")

    raw_items = list(injected_items)  # les chunks injectés passent en tête
    injected_docs = {doc for doc, _, _ in injected_items}
    rejected = 0
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0]
    ):
        if source and meta.get("source", "") != source:
            continue
        # Évite les doublons : un chunk déjà injecté par ID exact ne doit
        # pas être recompté depuis les résultats vectoriels classiques.
        if doc in injected_docs:
            continue
        if dist > MAX_DISTANCE:
            rejected += 1
            continue
        raw_items.append((doc, meta, dist))
    if rejected > 0:
        print(f"  🚫 {rejected} chunk(s) rejeté(s) (distance > {MAX_DISTANCE})")

    # ── Boost fichiers "aperçu" pour les questions définitionnelles ──────
    # Voir la note détaillée sur find_overview_files : ces fichiers sont
    # ajoutés au pool normal (pas épinglés comme les ID exacts) — ils
    # passeront par le même reranker cross-lingue que tout le reste, ce
    # qui leur garantit juste une chance d'être jugés, là où le retrieval
    # vectoriel seul les exclurait souvent d'office (cluster de chunks
    # techniques très similaires qui noie le document de synthèse).
    if is_definitional_question(question) and where_filter:
        already = {d for d, _, _ in raw_items}
        overview_items = find_overview_files(where_filter, exclude_docs=already)
        if overview_items:
            print(f"  📰 {len(overview_items)} fichier(s) aperçu (README/index) ajouté(s) au pool pour question définitionnelle")
            raw_items.extend(overview_items)

    if not raw_items:
        return [], [], [], False
    # Max 3 chunks par fichier source
    source_count = Counter()
    filtered = []
    for item in raw_items:
        src = item[1].get("source", "")
        if source_count[src] < 3:
            filtered.append(item)
            source_count[src] += 1
    raw_items = filtered
    raw_docs  = [d for d, _, _ in raw_items]
    raw_metas = [m for _, m, _ in raw_items]
    raw_dists = [dist for _, _, dist in raw_items]
    if HYBRID_SEARCH_ENABLED and len(raw_docs) > 5:
        try:
            bm25_top = bm25_filter(question, raw_docs, top_n=min(15, len(raw_docs)))
            fused = reciprocal_rank_fusion(
                list(zip(raw_docs, raw_metas, raw_dists)),
                bm25_top, k=60
            )
            raw_docs  = [d for d, _, _ in fused]
            raw_metas = [m for _, m, _ in fused]
            raw_dists = [dist for _, _, dist in fused]
        except Exception as e:
            print(f"  ⚠️  Hybrid search ignoré : {e}")

    # ── Séparation des chunks injectés avant reranking ───────────────────
    # Un chunk injecté par ID exact a déjà été validé comme pertinent par
    # matching lexical direct (ex: question "T1059" → fichier "T1059_...").
    # Le cross-encoder du reranker n'a aucune notion de cette garantie et
    # pourrait lui donner un score moyen, le faisant disparaître du top-N
    # face à des chunks vectoriellement proches mais hors-sujet. On les
    # retire donc du pool soumis au reranker, et on les recolle en tête du
    # résultat final après coup pour garantir leur présence.
    pinned_docs, pinned_metas, pinned_dists = [], [], []
    rerank_pool_docs, rerank_pool_metas, rerank_pool_dists = [], [], []
    for d, m, dist in zip(raw_docs, raw_metas, raw_dists):
        if d in injected_docs:
            pinned_docs.append(d)
            pinned_metas.append(m)
            pinned_dists.append(dist)
        else:
            rerank_pool_docs.append(d)
            rerank_pool_metas.append(m)
            rerank_pool_dists.append(dist)

    # Le reranker ne reçoit que le pool non-épinglé, et ne doit remplir que
    # les places restantes après les chunks épinglés.
    remaining_slots = max(0, topk - len(pinned_docs))

    # confident indique si le contexte final est un vrai match ou un repli
    # de dernier recours. Un chunk épinglé par ID exact (pinned_docs) est
    # toujours un match fiable (matching lexical direct, pas une supposition
    # du reranker) — donc leur seule présence suffit à faire confiance au
    # contexte, indépendamment de ce que dit le reranker sur le reste.
    confident = bool(pinned_docs)

    if RERANKING_ENABLED and remaining_slots > 0 and len(rerank_pool_docs) > remaining_slots:
        try:
            result = rerank(question, rerank_pool_docs, rerank_pool_metas,
                             rerank_pool_dists, top_n=remaining_slots, query_en=query_en)
            if len(result) == 5:
                reranked_docs, reranked_metas, reranked_dists, rerank_scores, rerank_confident = result
                confident = confident or rerank_confident
                print(f"  🎯 Reranking : {len(rerank_pool_docs)} → {len(reranked_docs)} chunks "
                      f"(top score: {rerank_scores[0]:.3f})" if rerank_scores else
                      f"  🎯 Reranking : {len(rerank_pool_docs)} → {len(reranked_docs)} chunks")
            else:
                reranked_docs, reranked_metas, reranked_dists = result[0], result[1], result[2]
                confident = True  # forme de retour inattendue : ne pas bloquer, comportement pré-existant
        except Exception as e:
            print(f"  ⚠️  Reranking ignoré : {e}")
            reranked_docs = rerank_pool_docs[:remaining_slots]
            reranked_metas = rerank_pool_metas[:remaining_slots]
            reranked_dists = rerank_pool_dists[:remaining_slots]
            confident = True  # reranker indisponible : pas de jugement possible, ne pas bloquer
    else:
        reranked_docs  = rerank_pool_docs[:remaining_slots]
        reranked_metas = rerank_pool_metas[:remaining_slots]
        reranked_dists = rerank_pool_dists[:remaining_slots]
        if not RERANKING_ENABLED or remaining_slots <= 0:
            # Reranking non effectué (désactivé, ou déjà comblé par les
            # chunks épinglés) : pas de nouveau jugement de pertinence, donc
            # pas de raison de dégrader une confiance déjà acquise ailleurs
            # (ex: pinned_docs) — mais on ne l'invente pas non plus ici.
            confident = confident or not rerank_pool_docs

    # ── Filet de secours lexical ──────────────────────────────────────────
    # Le retrieval vectoriel + reranking n'a rien trouvé de fiable : avant
    # d'abandonner, on tente un matching BM25 sur les noms de fichiers du
    # même périmètre thématique (voir lexical_rescue ci-dessus pour le cas
    # concret qui a motivé ce filet).
    if not confident:
        rescue_docs, rescue_metas, rescue_dists, rescue_scores, rescue_confident = lexical_rescue(
            question, where_filter, topk, exclude_docs=set(raw_docs), query_en=query_en,
            bm25_query=query_for_embedding
        )
        if rescue_confident:
            reranked_docs, reranked_metas, reranked_dists = rescue_docs, rescue_metas, rescue_dists
            confident = True

    if pinned_docs:
        print(f"  📌 {len(pinned_docs)} chunk(s) épinglé(s) en tête (ID exact), "
              f"{len(reranked_docs)} chunk(s) complémentaire(s) après reranking")

    final_docs  = pinned_docs + reranked_docs
    final_metas = pinned_metas + reranked_metas
    final_dists = pinned_dists + reranked_dists
    sources = []
    for meta, dist in zip(final_metas, final_dists):
        src      = meta.get("source", "inconnu")
        ttheme   = meta.get("theme", "?")
        dist_txt = f"{dist:.3f}" if isinstance(dist, (int, float)) else "lexical"
        sources.append(f"{src} [{ttheme}]  (dist: {dist_txt})")
    return final_docs, sources, final_dists, confident
# ===================== PROMPT BUILDER BLINDÉ =====================
def build_prompt(docs: list, mode: str, question: str, sources: list) -> str:
    """
    Prompts anti-hallucination.
    Principe : le LLM répond UNIQUEMENT depuis les documents fournis.
    Il ne doit PAS utiliser ses connaissances générales pour compléter.
    """

    context = "\n\n---\n\n".join(docs)

    # Règle absolue commune à tous les modes
    anti_hallucination = """\
⚠️  RÈGLE ABSOLUE — ANTI-HALLUCINATION (à respecter impérativement) :
1. Tu réponds UNIQUEMENT en te basant sur les documents fournis ci-dessous.
2. Si l'information demandée N'EST PAS dans les documents : écris
   "⚠️ Non documenté dans les sources disponibles."
3. INTERDIT d'utiliser ta mémoire d'entraînement pour compléter ou enrichir.
4. INTERDIT d'inventer des Event IDs, des commandes, des règles, des CVE, des techniques.
5. Si un document est hors-sujet par rapport à la question : IGNORE-LE.
6. Cite le fichier source RÉEL entre crochets après chaque information, par
   exemple [T1059_Command_and_Scripting_Interpreter.txt] — utilise le nom
   exact d'un des fichiers listés dans "Sources" ci-dessous, jamais un nom
   générique ou inventé. Si tu ne connais pas le nom exact, ne mets pas de
   citation plutôt que d'en inventer une.
"""

    mode_instructions = {

        "extract": """\
MODE EXTRACTION STRICTE :
- Extrais uniquement les éléments PRÉSENTS dans les documents : commandes, Event IDs, règles, IOC, hashes.
- Pour chaque élément extrait : [SOURCE: <nom_de_fichier_réel_tiré_de_la_liste_Sources>] Type: valeur
- Si un document ne contient pas d'éléments extractibles pour cette question : indique-le.
- Sections : ## Commandes ## Event IDs Windows ## Règles Sigma ## IOC ## Scripts
- AUCUN ajout personnel. AUCUNE improvisation.""",

        "synthesis": """\
MODE SYNTHÈSE EXPERTE :
- Synthèse pédagogique basée UNIQUEMENT sur les documents fournis.
- Structure : Contexte → Mécanisme → Détection/Prévention → Limites des sources
- Si les documents couvrent partiellement le sujet : indique clairement ce qui manque.
- AUCUN ajout de ta mémoire générale.""",

        "checklist": """\
MODE CHECKLIST OPÉRATIONNELLE :
- Génère une checklist basée UNIQUEMENT sur ce qui est dans les documents.
- Format : □ [ACTION CONCRÈTE] — [SOURCE: <nom_de_fichier_réel_tiré_de_la_liste_Sources>]
- Sections : □ Immédiat (0-30min)  □ Investigation  □ Containment  □ Documentation
- N'ajoute AUCUN item absent des documents.""",

        "red": """\
MODE RED TEAM :
- Extrais uniquement les techniques offensives documentées dans les sources.
- Format tableau : | Technique | Outil | Commande | ID ATT&CK | [SOURCE] |
- Si un document mentionne une technique sans détail suffisant : note-le.
- Ne complète PAS avec des techniques de ta mémoire absentes des documents.""",

        "blue": """\
MODE BLUE TEAM — DÉTECTION :
- Extrais les méthodes de détection PRÉSENTES dans les documents fournis.
- Format tableau : | Menace | Event ID | Log Source | Règle Sigma | [SOURCE] |
- Requêtes SIEM (KQL/SPL) : uniquement celles présentes dans les documents.
- RÈGLE CRITIQUE : si un document parle de Linux alors que la question concerne
  Windows/NTLM/Kerberos → IGNORE ce document complètement.
- RÈGLE CRITIQUE : si un document parle d'escalade de privilèges Linux alors que
  la question concerne Pass-the-Hash, PtT, NTLM relay → IGNORE ce document.
- IOC et artefacts forensiques : uniquement ceux mentionnés dans les documents.""",

        "hunt": """\
MODE THREAT HUNTING :
- Génère des hypothèses basées UNIQUEMENT sur les documents fournis.
- Format par hypothèse :
  🎯 HYPOTHÈSE : [issue du document X]
  📋 DONNÉES   : [logs/sources mentionnés dans les documents]
  🔍 REQUÊTE   : [si présente dans les documents]
  🚩 IOC       : [indicateurs mentionnés dans les documents]
- Si les documents sont insuffisants pour une hypothèse : dis-le clairement.""",
    }

    prompt = f"""\
Tu es un analyste SOC/DFIR senior. Réponds en français, de façon précise et opérationnelle.
Mode actif : {mode.upper()}
Question   : {question}
Sources    : {', '.join(sources)}

{anti_hallucination}

{mode_instructions.get(mode, mode_instructions["synthesis"])}

===== DOCUMENTS À ANALYSER =====

{context}

===== FIN DES DOCUMENTS =====

Réponds maintenant en respectant STRICTEMENT les règles ci-dessus.
Si les documents fournis ne permettent pas de répondre complètement,
dis-le explicitement plutôt que de compléter depuis ta mémoire.
"""
    return prompt


# ===================== LLM =====================
def ask_ollama(prompt: str) -> str:
    from llm_config import get_llm
    try:
        llm      = get_llm()
        response = llm.invoke(prompt)
        return response.content if hasattr(response, "content") else str(response)
    except Exception as e:
        return f"❌ Erreur LLM : {e}"


# ===================== DÉTECTION DE CITATIONS FABRIQUÉES =====================
# Vérifie que chaque nom de fichier cité entre crochets dans la réponse
# ([fichier.txt] ou [SOURCE: fichier.txt]) correspond bien à une des sources
# réellement récupérées. Une citation qui ne matche aucune source retournée
# est soit une hallucination pure (fichier inventé), soit un signe que le
# modèle a mélangé sa mémoire d'entraînement avec le contexte fourni — dans
# les deux cas, une violation mesurable de la règle anti-hallucination #6.
#
# FAUX POSITIF corrigé (cas confirmé en pratique) : en mode "extract" sur
# "Explique une règle Sigma", le document récupéré est le README.md du
# dépôt SigmaHQ, qui contient lui-même un lien markdown littéral
# "[CONTRIBUTING](./CONTRIBUTING.md)". Le LLM a fidèlement extrait ce
# contenu — exactement ce que le mode extract lui demande de faire — mais
# le crochet [CONTRIBUTING.md] ressemble à une citation de source et se
# faisait signaler à tort comme fabriqué. Pour distinguer une vraie
# fabrication (ex: "t1558.003.md", confirmé absent de tout document
# récupéré) d'une citation qui reprend un nom mentionné dans le texte
# source lui-même (pas seulement dans la liste des noms de fichiers
# récupérés), on vérifie maintenant aussi la présence verbatim du nom cité
# dans le contenu des documents — pas seulement dans leurs noms de fichier.
CITATION_PATTERN = re.compile(r"\[(?:SOURCE:\s*)?([A-Za-z0-9_.\-]+\.(?:txt|md|yml|yaml|json))\]", re.IGNORECASE)


def check_citations(response: str, sources: list, docs: list = None) -> list:
    """Retourne la liste des fichiers cités dans la réponse mais absents
    des sources réellement récupérées ET absents du contenu des documents
    (citations potentiellement fabriquées)."""
    known_files = set()
    for s in sources:
        # sources est de la forme "fichier.txt [theme]  (dist: 0.xx)"
        fname = s.split(" [")[0].strip()
        known_files.add(fname.lower())

    docs_text_lower = " ".join(docs).lower() if docs else ""

    cited = {m.group(1).lower() for m in CITATION_PATTERN.finditer(response)}
    fabricated = sorted(
        c for c in cited
        if c not in known_files and c not in docs_text_lower
    )
    return fabricated


# ===================== PIPELINE COMPLET (retrieval → génération) =====================
def answer_question(question: str, mode: str, theme: str = None, topk: int = 8,
                     source: str = None, no_filter: bool = False) -> dict:
    """
    Point d'entrée unique pour poser une question au RAG, utilisé par le
    CLI (main()) et par les scripts d'évaluation (eval_rag.py,
    soc_healthcheck.py) — une seule implémentation de la porte
    anti-hallucination, pour ne pas la dupliquer et risquer qu'elle diverge.

    Retourne un dict :
      docs, sources, distances : résultats bruts du retrieval
      confident   : le retrieval a-t-il trouvé un vrai match (pas un repli) ?
      abstained   : True si on a refusé d'appeler le LLM (aucun doc, ou
                    aucun doc suffisamment pertinent selon le reranker)
      response    : texte de réponse (LLM, ou message d'abstention)
      fabricated_citations : fichiers cités par le LLM mais absents des
                    sources réellement récupérées (liste vide si aucun,
                    toujours [] si abstained=True puisqu'aucun LLM appelé)
    """
    docs, sources, distances, confident = retrieval(question, mode, theme, topk, source, no_filter)

    if not docs:
        return {
            "docs": [], "sources": [], "distances": [], "confident": False,
            "abstained": True,
            "response": "⚠️ Aucun document trouvé avec les filtres actuels.",
            "fabricated_citations": [],
        }

    if not confident:
        # Le retrieval n'a renvoyé que des chunks de repli (aucun n'a passé
        # le seuil de pertinence du reranker) — on refuse d'appeler le LLM
        # plutôt que de compter sur ses instructions pour ignorer un
        # contexte qu'on sait déjà mauvais. C'est le garde-fou qui a manqué
        # sur le cas "Pass-the-Hash" (retrieval hors-sujet + LLM qui a quand
        # même essayé de répondre en inventant des IDs de règles).
        return {
            "docs": docs, "sources": sources, "distances": distances, "confident": False,
            "abstained": True,
            "response": ("⚠️ Non documenté dans les sources disponibles. "
                         "Le retrieval n'a trouvé aucun document suffisamment pertinent "
                         "(les chunks les plus proches ont été rejetés par le reranker) — "
                         "essaie de reformuler la question, ou utilise --theme/--no-filter "
                         "pour élargir la recherche."),
            "fabricated_citations": [],
        }

    prompt   = build_prompt(docs, mode, question, sources)
    response = ask_ollama(prompt)
    fabricated = check_citations(response, sources, docs=docs)

    return {
        "docs": docs, "sources": sources, "distances": distances, "confident": True,
        "abstained": False,
        "response": response,
        "fabricated_citations": fabricated,
    }


# ===================== DISPLAY =====================
def display_response(response: str, sources: list, mode: str, question: str,
                     distances: list = None, auto_filter: bool = False, theme: str = None):

    print("\n" + "="*60)
    print(f"  SOC RAG ELITE V2 — {mode.upper()}")
    print("="*60)
    print(f"  Question : {question}")

    if theme:
        print(f"  Filtre   : thème '{theme}' (forcé par --theme)")
    elif auto_filter:
        print(f"  Filtre   : auto-mode '{mode}' (sources cyber uniquement)")
    else:
        print(f"  Filtre   : AUCUN (--no-filter actif)")

    print("="*60 + "\n")
    print(response)

    print("\n" + "="*60)
    print("  SOURCES CONSULTÉES")
    print("="*60)

    sorted_sources = sorted(sources)
    for i, s in enumerate(sorted_sources):
        dist_str = ""
        if distances and i < len(distances) and isinstance(distances[i], (int, float)):
            dist_str = f"  (dist: {distances[i]:.3f})"
        print(f"  • {s}{dist_str}")

    # Avertissement si des sources générales sont présentes
    general_present = [s for s in sources if any(f"[{t}]" in s for t in GENERAL_THEMES)]
    if general_present:
        print(f"\n  ⚠️  {len(general_present)} source(s) générale(s) incluse(s) :")
        for g in general_present:
            print(f"     - {g}")
        print(f"  → Utilise --theme [mitre|sigma|cisa|dfir|...] pour filtrer.")
    print()


# ===================== MAIN =====================
def main():
    args = parse_args()

    if args.stats:
        show_stats()
        return

    if args.rebuild:
        build_db()
        if not args.mode and not args.question:
            return

    if not args.mode or not args.question:
        inputs    = menu_interactif()
        mode      = inputs["mode"]
        question  = inputs["question"]
        theme     = inputs["theme"]
        topk      = inputs["topk"]
        source    = inputs["source"]
        no_filter = inputs.get("no_filter", False)
    else:
        mode      = args.mode
        question  = args.question
        theme     = args.theme
        topk      = args.topk
        source    = args.source
        no_filter = getattr(args, "no_filter", False)

    if not question:
        print("⚠️  Aucune question fournie.")
        return

    auto_filter  = not theme and not no_filter
    filter_label = (
        f", thème='{theme}' (forcé)"   if theme      else
        f", auto-filtre mode '{mode}'" if auto_filter else
        ", AUCUN filtre (--no-filter)"
    )
    print(f"\n🔍 Recherche en cours... (topk={topk}{filter_label})")

    result = answer_question(question, mode, theme, topk, source, no_filter)
    docs, sources, distances = result["docs"], result["sources"], result["distances"]

    if not docs:
        print("⚠️  Aucun document trouvé avec les filtres actuels.")
        if auto_filter:
            print(f"   Essaie sans filtre de thème :")
            print(f"   python3.13 soc_ask_v2.py --mode {mode} --no-filter --question '{question}'")
        print("   Ou rebuild : python3.13 soc_ask_v2.py --rebuild")
        return

    print(f"📄 {len(docs)} chunks dans {len(sources)} source(s)")
    if result["abstained"]:
        print("🛑 Contexte jugé insuffisamment pertinent — LLM non appelé.\n")
    else:
        print(f"🤖 Génération... (LLM: {LLM_MODEL})\n")

    display_response(result["response"], sources, mode, question, distances, auto_filter, theme)

    if result["fabricated_citations"]:
        print("⚠️  CITATIONS SUSPECTES — cité(es) par le LLM mais absente(s) des sources récupérées :")
        for f in result["fabricated_citations"]:
            print(f"     - {f}")
        print("  → Vérifie cette réponse manuellement, le LLM a probablement halluciné.\n")


if __name__ == "__main__":
    main()
