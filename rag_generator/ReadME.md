# Pakistan Travel RAG — Secret Spots Explorer

An AI-powered travel assistant that uses Retrieval-Augmented Generation (RAG) to recommend hidden gems, restaurants, and attractions across Pakistan, built with LangChain, FAISS, and Groq.

---

## Overview

Secure RAG-based AI travel recommendation system for exploring destinations, attractions, and restaurants across Pakistan. It combines a curated dataset of hidden travel spots across Pakistan with a large language model to generate personalized, itinerary-style travel recommendations. Instead of pulling generic results off the internet, the system retrieves real, structured data (places, budgets, timings, categories) and hands that to an LLM to turn into natural, useful travel advice.

---

## Features

- **Semantic search over real travel data** — a FAISS vector store built from a hand-curated "Secret Spots" dataset of restaurants and attractions.
- **LLM-powered recommendations** — uses Groq's LLM inference (through LangChain) to turn retrieved data into natural itineraries.
- **Travel intent parsing** — understands queries about cities, budgets, and timing.
- **Budget-aware filtering** — categorizes and filters places by budget level.
- **Timing-aware matching** — matches places against opening hours and time-of-day slots.
- **Security-first design**
  - Prompt injection detection
  - Rate limiting per user session
  - Safe path validation (no directory traversal)
  - Input sanitization on every query
  - FAISS index integrity verification via checksums
- **Itinerary quality checks** — generated itineraries are reviewed for completeness before being shown to the user.

---

## How it works

1. **Data ingestion** — raw travel data ("Secret Spots Travel Dataset") is cleaned, normalized, and enriched in `encoding.py`.
2. **Vector indexing** — the cleaned data is embedded using HuggingFace sentence embeddings and stored in a FAISS index in `vector_db.py`.
3. **Query understanding** — user queries are parsed for travel intent: city, budget, timing, place type.
4. **Retrieval** — relevant places are retrieved and filtered from the vector store based on that intent.
5. **Generation** — the retrieved context is passed to a Groq-hosted LLM through LangChain to generate a natural, itinerary-style response in `main.py`.
6. **Quality check** — the generated response is analyzed for completeness before it's returned to the user.

---

## Tech stack

| Layer | Technology |
|---|---|
| LLM inference | [Groq](https://groq.com/) via `langchain-groq` |
| Orchestration | [LangChain](https://www.langchain.com/) / LangGraph |
| Vector store | [FAISS](https://github.com/facebookresearch/faiss) |
| Embeddings | HuggingFace Sentence Transformers |
| Data handling | Pandas |
| Language | Python 3.13 |

---

## Project structure

```
final_rag_LLM/
└── rag_generator/
    ├── main.py              # Entry point — runs the RAG pipeline
    ├── encoding.py          # Data cleaning + document creation
    ├── vector_db.py         # Retrieval, filtering, and itinerary logic
    ├── load_model.py        # LLM loading and configuration
    ├── test_model.py        # Testing utilities
    ├── requirements.txt     # Python dependencies
    └── Secret Spots Travel Dataset.csv   # Core travel dataset
```

---

## Getting started

### Prerequisites
- Python 3.13+
- A [Groq API key](https://console.groq.com/)

### Installation

```bash
# Clone the repository
git clone https://github.com/Ayesha-Ahmed07/final-rag-llm-fyp.git
cd final-rag-llm-fyp/rag_generator

# Install dependencies
pip install -r requirements.txt

# Set up your environment variables
echo "GROQ_API_KEY=your_key_here" > .env
```

### Run it

```bash
python main.py
```

---

## Security highlights

- API keys are validated for format before use.
- All file paths are checked against directory traversal.
- User queries are sanitized and scanned for prompt injection attempts.
- Requests are rate-limited to prevent abuse.
- The FAISS index is checksum-verified before loading.

---


## Author

**Ayesha Ahmed**
RAG-based Travel Recommendation System

---

## License

This project is available under the MIT License — feel free to explore, learn from, and build on it.
