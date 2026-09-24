#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          SOC-BRAIN RAG ELITE — Version 3.0                  ║
║  Assistant IA Local · Multi-domaine · LangChain + ChromaDB  ║
║  Auteur : Naanasba · GitHub : Naanasba99                    ║
╚══════════════════════════════════════════════════════════════╝
Usage:
  python3 soc_ask.py "ta question"          → poser une question
  python3 soc_ask.py --rebuild              → reconstruire la base
  python3 soc_ask.py --rebuild --fast       → rebuild rapide (TXT+MD seulement)
  python3 soc_ask.py --stats                → statistiques de la base
  python3 soc_ask.py --search "mot"         → chercher dans les sources
  python3 soc_ask.py --interactive          → mode conversation continu
"""

import sys
import os
import time
import json
import hashlib
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────
#   CONFIGURATION — modifier ici uniquement
# ─────────────────────────────────────────────

NOTES_DIR   = os.path.expanduser("~/CYBER/soc-stack/soc-brain")
DB_DIR      = os.path.expanduser("~/CYBER/soc-stack/soc-chroma-db")
HISTORY_FILE = os.path.expanduser("~/CYBER/soc-stack/soc_history.json")
LOG_FILE     = os.path.expanduser("~/CYBER/soc-stack/soc_queries.log")

# Modèles — changer ici pour upgrader
EMBED_MODEL = "nomic-embed-text"   # → remplacer par "bge-m3" pour upgrade
LLM_MODEL   = "mistral:7b"        # → remplacer par "deepseek-r1:7b" ou "llama4:8b"

# Paramètres de chunking
CHUNK_SIZE    = 1000   # taille des chunks en caractères
CHUNK_OVERLAP = 100    # chevauchement entre chunks
TOP_K         = 12     # nombre de chunks récupérés par question

# ─────────────────────────────────────────────
#   COULEURS TERMINAL
# ─────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    GRAY   = "\033[90m"
    BG_DARK= "\033[40m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║          SOC-BRAIN RAG ELITE — Version 3.0                  ║
║  LLM: {LLM_MODEL:<20} Embed: {EMBED_MODEL:<15}║
║  Base: {DB_DIR.replace(os.path.expanduser('~'), '~'):<54}║
╚══════════════════════════════════════════════════════════════╝{C.RESET}""")

def info(msg):    print(f"{C.CYAN}  ℹ  {msg}{C.RESET}")
def success(msg): print(f"{C.GREEN}  ✅  {msg}{C.RESET}")
def warning(msg): print(f"{C.YELLOW}  ⚠  {msg}{C.RESET}")
def error(msg):   print(f"{C.RED}  ✗  {msg}{C.RESET}")
def step(msg):    print(f"{C.BLUE}  →  {msg}{C.RESET}")

# ─────────────────────────────────────────────
#   IMPORTS LANGCHAIN
# ─────────────────────────────────────────────

def check_imports():
    missing = []
    packages = {
        "langchain_community": "langchain-community",
        "langchain_text_splitters": "langchain-text-splitters",
        "langchain_ollama": "langchain-ollama",
        "langchain_chroma": "langchain-chroma",
        "langchain_core": "langchain-core",
    }
    for module, package in packages.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if missing:
        error(f"Packages manquants : {', '.join(missing)}")
        print(f"\n  Installer avec :\n  pip3 install {' '.join(missing)} --break-system-packages\n")
        sys.exit(1)

import warnings
warnings.filterwarnings("ignore")
check_imports()

from langchain_community.document_loaders import (
    DirectoryLoader, TextLoader, PyPDFLoader, Docx2txtLoader
)
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_ollama import OllamaEmbeddings, OllamaLLM
from langchain_chroma import Chroma
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser

# ─────────────────────────────────────────────
#   PROMPT ÉLITE — POLYVALENT MULTI-DOMAINE
# ─────────────────────────────────────────────

PROMPT_TEMPLATE = """You are a SOC analyst assistant. Your knowledge comes EXCLUSIVELY from the context below.

ABSOLUTE RULES:
1. Answer ONLY based on what is explicitly written in the context below.
2. If the answer is NOT in the context, respond EXACTLY with:
   "NOT FOUND IN CORPUS — verify manually: https://attack.mitre.org or official documentation."
3. NEVER generate YAML, commands, rule IDs, CVEs, or code that are not present in the context.
4. NEVER infer, extrapolate, or connect unrelated sources to fabricate an answer.
5. Detect the question language and respond in that same language.
6. Always cite the source filename in parentheses for every claim.
7. If sources contradict each other, flag it explicitly.

Context extracted from personal library:
─────────────────────────────────────────────────
{context}
─────────────────────────────────────────────────

Question: {question}

Answer (strictly based on context above — no invention):"""

# ─────────────────────────────────────────────
#   VÉRIFICATION OLLAMA
# ─────────────────────────────────────────────

def check_ollama():
    import urllib.request
    try:
        urllib.request.urlopen("http://localhost:11434", timeout=3)
        return True
    except Exception:
        return False

def check_model_available(model_name):
    import subprocess
    result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
    return model_name.split(":")[0] in result.stdout

# ─────────────────────────────────────────────
#   EMBEDDINGS
# ─────────────────────────────────────────────

def get_embeddings():
    return OllamaEmbeddings(model=EMBED_MODEL)

# ─────────────────────────────────────────────
#   BUILD DB — AVEC BARRE DE PROGRESSION
# ─────────────────────────────────────────────

def build_db(fast_mode=False):
    """Reconstruire la base vectorielle ChromaDB"""
    banner()
    print()

    # Vérifications
    if not check_ollama():
        error("Ollama n'est pas démarré. Lance : ollama serve &")
        sys.exit(1)

    if not os.path.exists(NOTES_DIR):
        error(f"Dossier source introuvable : {NOTES_DIR}")
        sys.exit(1)

    start_total = time.time()

    # ── Chargement des documents ──
    info(f"Chargement des documents depuis {NOTES_DIR}")
    print()

    all_docs = []

    loaders_config = [
        ("**/*.txt",  TextLoader,     {"encoding": "utf-8", "autodetect_encoding": True}, "TXT"),
        ("**/*.md",   TextLoader,     {"encoding": "utf-8", "autodetect_encoding": True}, "MD"),
        ("**/*.yml",  TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "YAML"),
        ("**/*.yaml", TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "YAML"),
        ("**/*.json", TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "JSON"),
    ]

    if not fast_mode:
        loaders_config += [
            ("**/*.pdf",  PyPDFLoader,    {}, "PDF"),
            ("**/*.docx", Docx2txtLoader, {}, "DOCX"),
            ("**/*.yml",  TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "YAML"),
            ("**/*.yaml", TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "YAML"),
            ("**/*.json", TextLoader, {"encoding": "utf-8", "autodetect_encoding": True}, "JSON"),
        ]
    else:
        warning("Mode rapide activé — PDF et DOCX ignorés")

    for glob, loader_cls, kwargs, label in loaders_config:
        step(f"Chargement des fichiers {label}...")
        try:
            loader_kwargs = kwargs if kwargs else None
            loader = DirectoryLoader(
                NOTES_DIR,
                glob=glob,
                loader_cls=loader_cls,
                loader_kwargs=loader_kwargs,
                silent_errors=True,
                show_progress=False,
            )
            docs = loader.load()
            success(f"{len(docs):>6,} fichiers {label} chargés")
            all_docs.extend(docs)
        except Exception as e:
            warning(f"Erreur chargement {label} : {e}")

    print()
    print(f"  {C.BOLD}{'─'*50}{C.RESET}")
    print(f"  {C.GREEN}{C.BOLD}📦 TOTAL : {len(all_docs):,} fichiers chargés{C.RESET}")
    print(f"  {C.BOLD}{'─'*50}{C.RESET}")
    print()

    if not all_docs:
        error("Aucun document trouvé. Vérifie le dossier soc-brain.")
        sys.exit(1)

    # ── Chunking ──
    step(f"Découpage en chunks (taille={CHUNK_SIZE}, chevauchement={CHUNK_OVERLAP})...")
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks = splitter.split_documents(all_docs)
    success(f"{len(chunks):,} chunks créés")
    print()

    # ── Vectorisation ──
    info(f"Vectorisation avec {EMBED_MODEL}...")
    warning("Ne pas fermer ce terminal — processus long")
    print()

    t_vec_start = time.time()

    # Supprimer l'ancienne base si elle existe
    if os.path.exists(DB_DIR):
        import shutil
        step("Suppression de l'ancienne base...")
        shutil.rmtree(DB_DIR)

    # Vectorisation par batch pour éviter les blocages
    BATCH_SIZE = 500
    db = None
    total_batches = (len(chunks) // BATCH_SIZE) + 1

    for i in range(0, len(chunks), BATCH_SIZE):
        batch = chunks[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        elapsed = time.time() - t_vec_start
        pct = (i / len(chunks)) * 100 if len(chunks) > 0 else 0

        # Barre de progression
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"\r  {C.CYAN}[{bar}]{C.RESET} {pct:.0f}% — batch {batch_num}/{total_batches} ({elapsed:.0f}s)", end="", flush=True)

        try:
            if db is None:
                db = Chroma.from_documents(
                    batch,
                    get_embeddings(),
                    persist_directory=DB_DIR
                )
            else:
                db.add_documents(batch)
        except Exception as e:
            print()
            warning(f"Erreur batch {batch_num} : {e} — on continue")
            continue

    print()
    print()

    # ── Sauvegarde des métadonnées ──
    meta = {
        "date_rebuild": datetime.now().isoformat(),
        "total_files": len(all_docs),
        "total_chunks": len(chunks),
        "embed_model": EMBED_MODEL,
        "llm_model": LLM_MODEL,
        "chunk_size": CHUNK_SIZE,
        "chunk_overlap": CHUNK_OVERLAP,
        "fast_mode": fast_mode,
        "duration_seconds": int(time.time() - start_total),
    }
    meta_path = os.path.join(DB_DIR, "meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    total_time = int(time.time() - start_total)
    hours, remainder = divmod(total_time, 3600)
    minutes, seconds = divmod(remainder, 60)

    print(f"""  {C.GREEN}{C.BOLD}╔══════════════════════════════════════╗
  ║   ✅  BASE VECTORIELLE CRÉÉE !      ║
  ╠══════════════════════════════════════╣
  ║  Fichiers  : {len(all_docs):>8,}                ║
  ║  Chunks    : {len(chunks):>8,}                ║
  ║  Durée     : {hours:02d}h {minutes:02d}m {seconds:02d}s              ║
  ╚══════════════════════════════════════╝{C.RESET}""")

# ─────────────────────────────────────────────
#   STATISTIQUES
# ─────────────────────────────────────────────

def show_stats():
    """Afficher les statistiques de la base"""
    banner()
    print()

    meta_path = os.path.join(DB_DIR, "meta.json")
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)
        print(f"""  {C.CYAN}{C.BOLD}STATISTIQUES DE LA BASE{C.RESET}
  {'─'*45}
  {C.GREEN}Dernier rebuild  :{C.RESET} {meta.get('date_rebuild', 'inconnu')[:19]}
  {C.GREEN}Total fichiers   :{C.RESET} {meta.get('total_files', 0):,}
  {C.GREEN}Total chunks     :{C.RESET} {meta.get('total_chunks', 0):,}
  {C.GREEN}Modèle LLM       :{C.RESET} {meta.get('llm_model', '?')}
  {C.GREEN}Modèle Embedding :{C.RESET} {meta.get('embed_model', '?')}
  {C.GREEN}Chunk size       :{C.RESET} {meta.get('chunk_size', '?')}
  {C.GREEN}Durée rebuild    :{C.RESET} {meta.get('duration_seconds', 0)//3600:02d}h {(meta.get('duration_seconds', 0)%3600)//60:02d}m
  {'─'*45}""")
    else:
        warning("Aucun fichier de métadonnées. Lance --rebuild d'abord.")

    # Compter les fichiers dans soc-brain
    if os.path.exists(NOTES_DIR):
        print(f"\n  {C.CYAN}{C.BOLD}CONTENU DE SOC-BRAIN{C.RESET}")
        print(f"  {'─'*45}")
        exts = {}
        for f in Path(NOTES_DIR).rglob("*"):
            if f.is_file():
                ext = f.suffix.lower() or "sans extension"
                exts[ext] = exts.get(ext, 0) + 1
        for ext, count in sorted(exts.items(), key=lambda x: -x[1])[:10]:
            bar = "█" * min(count // 500, 20)
            print(f"  {C.GREEN}{ext:<12}{C.RESET} {count:>8,}  {C.CYAN}{bar}{C.RESET}")
        print(f"  {'─'*45}")

    # Historique des requêtes
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)
        print(f"\n  {C.CYAN}{C.BOLD}DERNIÈRES REQUÊTES{C.RESET}")
        print(f"  {'─'*45}")
        for entry in history[-5:]:
            ts = entry.get("timestamp", "")[:16]
            q  = entry.get("question", "")[:60]
            print(f"  {C.GRAY}{ts}{C.RESET}  {q}")
        print(f"  {'─'*45}")

# ─────────────────────────────────────────────
#   CHARGEMENT DE LA BASE
# ─────────────────────────────────────────────

def load_db():
    """Charger la base vectorielle existante"""
    if not os.path.exists(DB_DIR):
        error(f"Base vectorielle introuvable : {DB_DIR}")
        error("Lance d'abord : python3 soc_ask.py --rebuild")
        sys.exit(1)

    if not check_ollama():
        error("Ollama n'est pas démarré. Lance : ollama serve &")
        sys.exit(1)

    return Chroma(
        persist_directory=DB_DIR,
        embedding_function=get_embeddings()
    )

# ─────────────────────────────────────────────
#   SAUVEGARDER L'HISTORIQUE
# ─────────────────────────────────────────────

def save_history(question, answer, sources):
    """Sauvegarder la requête dans l'historique JSON"""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                history = json.load(f)
        except Exception:
            history = []

    history.append({
        "timestamp": datetime.now().isoformat(),
        "question": question,
        "sources": sources,
        "answer_length": len(answer),
    })

    # Garder les 200 dernières entrées
    history = history[-200:]

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)

def log_query(question, sources, duration):
    """Logger la requête dans un fichier log"""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        srcs = ", ".join(sources[:3])
        f.write(f"[{ts}] ({duration:.1f}s) Q: {question[:100]} | Sources: {srcs}\n")

# ─────────────────────────────────────────────
#   POSER UNE QUESTION
# ─────────────────────────────────────────────

def ask(question, db=None, verbose=True):
    """Poser une question au système RAG"""
    if db is None:
        db = load_db()

    # ── Reformulation technique de la question ──
# ── Reformulation technique de la question ──
    llm_reformulate = OllamaLLM(model=LLM_MODEL, temperature=0.0)
    reformulate_prompt = f"""Extract the key technical terms from this question for searching a cybersecurity knowledge base.
Include: MITRE technique IDs (T1078), tool names (Wazuh, Sigma), attack names, protocol names, CVE IDs.
Output ONLY space-separated technical terms. No sentences. No explanation.

Question: {question}
Technical terms:"""
    try:
        technical_query = llm_reformulate.invoke(reformulate_prompt).strip()
        if verbose:
            print(f"  {C.GRAY}🔄 Reformulation : {technical_query}{C.RESET}")
    except Exception:
        technical_query = question

    # ── Fin reformulation ──

    if verbose:
        print()
        print(f"  {C.CYAN}{C.BOLD}🔍 Question :{C.RESET} {question}")
        print(f"  {C.GRAY}{'─'*60}{C.RESET}")
        print()

    # Créer le retriever avec k=TOP_K chunks
    retriever = db.as_retriever(
        search_type="similarity",
        search_kwargs={"k": TOP_K}
    )

    # Construire le prompt
    prompt = PromptTemplate(
        input_variables=["context", "question"],
        template=PROMPT_TEMPLATE
    )

    # Récupérer les sources pour affichage
    relevant_docs = retriever.invoke(technical_query)
    sources = list(set([
        os.path.basename(doc.metadata.get("source", "inconnu"))
        for doc in relevant_docs
    ]))

    # Pipeline RAG
    def format_docs(docs):
        return "\n\n".join([
            f"[Source: {os.path.basename(doc.metadata.get('source', 'inconnu'))}]\n{doc.page_content}"
            for doc in docs
        ])

    llm = OllamaLLM(
        model=LLM_MODEL,
        temperature=0.1,       # peu de créativité — on veut de la précision
        num_ctx=4096,          # fenêtre de contexte
    )

    chain = (
        {"context": retriever | format_docs, "question": RunnablePassthrough()}
        | prompt
        | llm
        | StrOutputParser()
    )

    # Chronomètre
    t_start = time.time()

    if verbose:
        print(f"  {C.YELLOW}{C.BOLD}💬 Réponse :{C.RESET}")
        print()

    # Streaming de la réponse
    answer = ""
    if verbose:
        print(f"  ", end="")
        for chunk in chain.stream(question):
            print(chunk, end="", flush=True)
            answer += chunk
        print()
    else:
        answer = chain.invoke(question)

    duration = time.time() - t_start

    # Afficher les sources
    if verbose:
        print()
        print(f"  {C.GRAY}{'─'*60}{C.RESET}")
        print(f"  {C.MAGENTA}{C.BOLD}📁 Sources utilisées ({len(sources)}) :{C.RESET}")
        for src in sources[:8]:
            print(f"     {C.CYAN}→{C.RESET} {src}")
        print(f"  {C.GRAY}⏱  {duration:.1f}s  |  {TOP_K} chunks analysés  |  {LLM_MODEL}{C.RESET}")
        print()

    # Sauvegarder
    try:
        save_history(question, answer, sources)
        log_query(question, sources, duration)
    except Exception:
        pass

    return answer, sources

# ─────────────────────────────────────────────
#   RECHERCHE DANS LES SOURCES
# ─────────────────────────────────────────────

def search_sources(keyword):
    """Chercher des fichiers par mot clé dans soc-brain"""
    banner()
    print()
    info(f"Recherche de '{keyword}' dans soc-brain...")
    print()

    results = []
    for f in Path(NOTES_DIR).rglob("*"):
        if f.is_file() and keyword.lower() in f.name.lower():
            results.append(f)

    if results:
        success(f"{len(results)} fichier(s) trouvé(s) :")
        print()
        for r in results[:30]:
            rel = str(r).replace(NOTES_DIR, "soc-brain")
            print(f"  {C.CYAN}→{C.RESET} {rel}")
    else:
        warning(f"Aucun fichier trouvé pour '{keyword}'")

    print()

# ─────────────────────────────────────────────
#   MODE INTERACTIF
# ─────────────────────────────────────────────

def interactive_mode():
    """Mode conversation continu"""
    banner()
    print()
    info("Mode interactif — tape 'exit' ou 'quit' pour quitter")
    info("Commandes spéciales : 'stats', 'clear', 'history'")
    print()

    db = load_db()
    success("Base vectorielle chargée. Prêt.")
    print()

    while True:
        try:
            question = input(f"  {C.CYAN}{C.BOLD}❯ {C.RESET}").strip()

            if not question:
                continue

            if question.lower() in ["exit", "quit", "bye", "q"]:
                print(f"\n  {C.YELLOW}À bientôt !{C.RESET}\n")
                break

            if question.lower() == "stats":
                show_stats()
                continue

            if question.lower() == "clear":
                os.system("clear")
                banner()
                continue

            if question.lower() == "history":
                if os.path.exists(HISTORY_FILE):
                    with open(HISTORY_FILE) as f:
                        hist = json.load(f)
                    print(f"\n  {C.CYAN}Dernières questions :{C.RESET}")
                    for i, h in enumerate(hist[-10:], 1):
                        print(f"  {C.GRAY}{i:2}. {h['timestamp'][:16]}{C.RESET}  {h['question'][:70]}")
                    print()
                continue

            ask(question, db=db)

        except KeyboardInterrupt:
            print(f"\n\n  {C.YELLOW}Interruption. Tape 'exit' pour quitter proprement.{C.RESET}\n")
            continue
        except EOFError:
            break

# ─────────────────────────────────────────────
#   POINT D'ENTRÉE PRINCIPAL
# ─────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    # Aucun argument
    if not args:
        banner()
        print(f"""
  {C.YELLOW}Usage :{C.RESET}
    python3 soc_ask.py "ta question"        → poser une question
    python3 soc_ask.py --rebuild            → reconstruire la base (tous formats)
    python3 soc_ask.py --rebuild --fast     → rebuild rapide (TXT+MD seulement)
    python3 soc_ask.py --stats              → statistiques de la base
    python3 soc_ask.py --search "mot"       → chercher un fichier
    python3 soc_ask.py --interactive        → mode conversation continu

  {C.GRAY}Configuration actuelle :{C.RESET}
    LLM      : {LLM_MODEL}
    Embedding: {EMBED_MODEL}
    Top-K    : {TOP_K} chunks
    Base     : {DB_DIR.replace(os.path.expanduser('~'), '~')}
""")
        return

    # --rebuild
    if "--rebuild" in args:
        fast_mode = "--fast" in args
        build_db(fast_mode=fast_mode)
        return

    # --stats
    if "--stats" in args:
        show_stats()
        return

    # --interactive
    if "--interactive" in args:
        interactive_mode()
        return

    # --search
    if "--search" in args:
        idx = args.index("--search")
        if idx + 1 < len(args):
            search_sources(args[idx + 1])
        else:
            error("Fournis un mot-clé après --search")
        return

    # Question directe
    question = " ".join(args)
    if question.startswith('"') and question.endswith('"'):
        question = question[1:-1]

    if not question:
        error("Question vide.")
        return

    ask(question)

if __name__ == "__main__":
    main()
