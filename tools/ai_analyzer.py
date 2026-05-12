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
MODEL = "gemma3:latest" # Using gemma3 for its general reasoning

def get_ai_insight(context_type, data):
    print(f"[*] Requesting AI insight for {context_type}...")
    
    prompt = f"""
    You are a Senior Penetration Tester assistant. 
    Analyze the following {context_type} and suggest:
    1. The most likely security vulnerability.
    2. A specific next step or payload to test it.
    
    Data to analyze:
    ---
    {data[:2000]}
    ---
    Be concise, technical, and actionable. Provide a 3-bullet point summary.
    """
    
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=30)
        if response.status_code == 200:
            return response.json().get('response', "AI could not generate an analysis.")
    except Exception as e:
        return f"AI Analysis failed: Is Ollama running? Error: {e}"
    
    return "AI Analysis unavailable."

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
