"""
Pytest configuration — register custom markers and load .env.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root so live tests can find ANTHROPIC_API_KEY
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: tests that hit the live Claude API (require ANTHROPIC_API_KEY)"
    )
