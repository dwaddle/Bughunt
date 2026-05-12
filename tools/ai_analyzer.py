#!/usr/bin/env python3
"""
AI-Analyzer: Leverages local LLMs (Ollama) for intelligent security insights.
Part of the Bughunt project (OWASP A04: Insecure Design).
"""

import requests
import json
import argparse
import sys

OLLAMA_URL = "http://localhost:11434/api/generate"
# Preferred model order (Fastest first)
MODELS = ["llama3.2:1b", "gemma3:latest", "qwen2.5-coder:latest"]

def get_ai_insight(context_type, data):
    print(f"[*] Requesting AI insight (Timeout: 300s). This may take a while on CPU...")
    
    # Use a very short, specific prompt to reduce token generation time
    prompt = f"""
    Task: Pentest Analysis of {context_type}.
    Rule: Give only 2 bullet points.
    1. Most likely vulnerability.
    2. Next test command.
    
    Data: {data[:1500]}
    """
    
    # Try the first model that's available
    current_model = MODELS[0] 
    
    payload = {
        "model": current_model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": 100, # Limit the number of tokens to speed up
            "temperature": 0.3
        }
    }
    
    try:
        # 5 minute timeout for slow hardware
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        if response.status_code == 200:
            return response.json().get('response', "AI Analysis empty.")
        else:
            return f"Ollama Error ({response.status_code})"
    except requests.exceptions.Timeout:
        return "AI Analysis timed out after 300s. CPU too slow for this model."
    except Exception as e:
        return f"AI Error: {e}"

def main():
    parser = argparse.ArgumentParser(description="AI-Analyzer (Ollama)")
    parser.add_argument("file", help="File content to analyze")
    parser.add_argument("--type", default="HTML content", help="Type of data (HTML, Headers, etc.)")
    args = parser.parse_args()
    
    with open(args.file, 'r') as f:
        content = f.read()
    
    insight = get_ai_insight(args.type, content)
    print("\n=== AI EXPERT OPINION ===")
    print(insight)

if __name__ == "__main__":
    main()
