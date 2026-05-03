import httpx
import json
import logging
from typing import Type, TypeVar, Optional
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)
logger = logging.getLogger("PRAWN.OllamaClient")

class OllamaClient:
    """
    Client for interfacing with local Ollama instance.
    Includes Pydantic validation helpers for structured output.
    """
    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.endpoint = f"{self.base_url}/api/generate"

    async def generate_structured(self, prompt: str, response_model: Type[T], timeout: float = 90.0) -> Optional[T]:
        """
        Generates a response from Ollama and parses it into the provided Pydantic model.
        Ensures the 'format': 'json' is respected by the local LLM.
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.endpoint, json=payload, timeout=timeout)
                response.raise_for_status()
                
                result = response.json()
                raw_json = result.get("response", "").strip()
                
                if not raw_json or raw_json == "null":
                    return None
                
                data = json.loads(raw_json)
                return response_model.model_validate(data)
                
        except (httpx.HTTPError, json.JSONDecodeError, ValidationError) as e:
            logger.error(f"Structured generation failed for model {response_model.__name__}: {e}")
            return None

    async def generate_text(self, prompt: str, timeout: float = 60.0) -> str:
        """Generates a plain text response from Ollama."""
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(self.endpoint, json=payload, timeout=timeout)
                response.raise_for_status()
                return response.json().get("response", "").strip()
        except httpx.HTTPError as e:
            logger.error(f"Text generation failed: {e}")
            return ""