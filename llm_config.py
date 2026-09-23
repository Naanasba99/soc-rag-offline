#!/usr/bin/env python3
"""
LLM Config — Switch local/Claude API
  Mode local (défaut) :
    python3 soc_ask_v2.py ...

  Mode Claude API :
    export LLM_PROVIDER=claude
    export ANTHROPIC_API_KEY=sk-ant-xxxxx
    python3 soc_ask_v2.py ...

  Retour local :
    unset LLM_PROVIDER
"""

import os

LLM_PROVIDER     = os.getenv("LLM_PROVIDER", "local")
LLM_MODEL_LOCAL  = "mistral"
LLM_MODEL_CLAUDE = "claude-haiku-4-5-20251001"

# Température basse : ce RAG fait de l'extraction/synthèse contrainte au
# contexte fourni, pas de la génération créative — une température par
# défaut (souvent ~0.7-0.8 côté Ollama) laisse trop de marge au modèle pour
# broder ou halluciner au lieu de coller strictement aux documents.
LLM_TEMPERATURE = float(os.getenv("SOC_LLM_TEMPERATURE", "0.1"))

# Bornes défensives : une génération observée en pratique a pris 2114s (35min)
# sans qu'aucune cause ne soit visible côté retrieval — l'appel Ollama
# lui-même s'est bloqué, et comme aucune limite n'était configurée, rien
# n'aurait empêché un blocage indéfini. num_predict borne la longueur max
# de sortie (1024 tokens est largement suffisant pour ces formats de
# réponse — tableaux, checklists — et évite une génération qui dérive) ;
# le timeout HTTP force un échec explicite plutôt qu'un gel silencieux.
LLM_NUM_PREDICT   = int(os.getenv("SOC_LLM_NUM_PREDICT", "1024"))
LLM_TIMEOUT_S     = int(os.getenv("SOC_LLM_TIMEOUT_S", "120"))

def get_llm():
    if LLM_PROVIDER == "claude":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "❌ ANTHROPIC_API_KEY non définie.\n"
                "   Lance : export ANTHROPIC_API_KEY=sk-ant-xxxxx"
            )
        from langchain_anthropic import ChatAnthropic
        print(f"🤖 LLM : Claude API ({LLM_MODEL_CLAUDE})")
        return ChatAnthropic(
            model=LLM_MODEL_CLAUDE,
            api_key=api_key,
            max_tokens=2048,
            temperature=LLM_TEMPERATURE
        )
    else:
        from langchain_ollama import OllamaLLM
        # SOC_LLM_MODEL permet de tester un autre modèle local (ex: qwen2.5:7b)
        # sans modifier le code — utilisé par eval_rag.py pour comparer.
        model_name = os.getenv("SOC_LLM_MODEL", LLM_MODEL_LOCAL)
        print(f"🤖 LLM : Ollama local ({model_name}, temperature={LLM_TEMPERATURE}, "
              f"num_predict={LLM_NUM_PREDICT}, timeout={LLM_TIMEOUT_S}s)")
        return OllamaLLM(
            model=model_name,
            temperature=LLM_TEMPERATURE,
            num_predict=LLM_NUM_PREDICT,
            client_kwargs={"timeout": LLM_TIMEOUT_S},
        )
