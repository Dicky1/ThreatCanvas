# ThreatCanvas AI Backend

This is the core backend engine for compiling natural language attack scenarios into deterministic Cyber Intermediate Representation (CIR) graphs.

## Run Locally
1. `python -m venv venv`
2. `source venv/bin/activate`
3. `pip install -r requirements.txt`
4. `cp .env.example .env`
5. `uvicorn app.main:app --reload`