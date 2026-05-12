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
MODEL = "gemma3:latest" # Primary model

def get_ai_insight(context_type, data):
    print(f"[*] Requesting AI insight for {context_type} (this may take a minute)...")
    
    prompt = f"""
    You are a Senior Penetration Tester assistant. 
    Analyze the following {context_type} and suggest:
    1. The most likely security vulnerability.
    2. A specific next step or payload to test it.
    
    Data to analyze:
    ---
    {data[:3000]}
    ---
    Be concise, technical, and actionable. Provide a 3-bullet point summary.
    """
    
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        # Increased timeout to 120s for local inference
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        if response.status_code == 200:
            return response.json().get('response', "AI could not generate an analysis.")
        else:
            return f"Ollama returned error code: {response.status_code}"
    except requests.exceptions.Timeout:
        return "AI Analysis timed out. Local inference is taking too long (> 120s)."
    except requests.exceptions.ConnectionError:
        return "AI Analysis failed: Cannot connect to Ollama. Is 'ollama serve' running?"
    except Exception as e:
        return f"AI Analysis encountered an unexpected error: {e}"

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
