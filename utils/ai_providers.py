# Enhanced AI provider system supporting multiple LLM providers
# for comprehensive SQL injection analysis and recommendations.

import os
import time
import logging
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass
from enum import Enum
import asyncio
from dotenv import load_dotenv

# Provider imports
try:
    from groq import Groq
except ImportError:
    Groq = None

try:
    import openai
except ImportError:
    openai = None

try:
    import anthropic
except ImportError:
    anthropic = None

try:
    from transformers import AutoTokenizer, AutoModelForCausalLM
    import torch
except ImportError:
    AutoTokenizer = AutoModelForCausalLM = torch = None

load_dotenv()
logger = logging.getLogger(__name__)


class AIProvider(Enum):
    # Available AI providers
    GROQ = "groq"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LOCAL = "local"


@dataclass
class AIResponse:
    # Standardized AI response structure
    content: str
    provider: AIProvider
    model: str
    tokens_used: int = 0
    response_time: float = 0.0
    success: bool = True
    error: Optional[str] = None


class AIProviderManager:
    # Manages multiple AI providers with fallback mechanisms
    
    def __init__(self):
        self.providers = {}
        self.active_providers = []
        self._setup_providers()
    
    def _setup_providers(self):
        # Initialize available AI providers
        
        # Setup Groq
        if Groq and os.getenv("GROQ_API_KEY"):
            try:
                self.providers[AIProvider.GROQ] = GroqProvider()
                self.active_providers.append(AIProvider.GROQ)
            except Exception as e:
                logger.warning(f"Failed to initialize Groq: {e}")
        
        # Setup OpenAI
        if openai and os.getenv("OPENAI_API_KEY"):
            try:
                self.providers[AIProvider.OPENAI] = OpenAIProvider()
                self.active_providers.append(AIProvider.OPENAI)
            except Exception as e:
                logger.warning(f"Failed to initialize OpenAI: {e}")
        
        # Setup Anthropic
        if anthropic and os.getenv("ANTHROPIC_API_KEY"):
            try:
                self.providers[AIProvider.ANTHROPIC] = AnthropicProvider()
                self.active_providers.append(AIProvider.ANTHROPIC)
            except Exception as e:
                logger.warning(f"Failed to initialize Anthropic: {e}")
        
        # Setup Ollama (if enabled)
        if os.getenv("ENABLE_OLLAMA", "false").lower() == "true":
            try:
                self.providers[AIProvider.OLLAMA] = OllamaProvider()
                self.active_providers.append(AIProvider.OLLAMA)
            except Exception as e:
                logger.warning(f"Failed to initialize Ollama: {e}")
        
        # Setup Local (if enabled)
        if os.getenv("ENABLE_LOCAL_LLM", "false").lower() == "true":
            try:
                self.providers[AIProvider.LOCAL] = LocalLLMProvider()
                self.active_providers.append(AIProvider.LOCAL)
            except Exception as e:
                logger.warning(f"Failed to initialize Local LLM: {e}")
    
    async def get_response(
        self, 
        prompt: str, 
        provider: Optional[AIProvider] = None,
        max_retries: int = 3,
        **kwargs
    ) -> AIResponse:
        
        
        providers_to_try = [provider] if provider else self.active_providers
        for attempt_provider in providers_to_try:
            if attempt_provider not in self.providers:
                continue
                
            try:
                response = await self.providers[attempt_provider].get_response(
                    prompt, max_retries=max_retries, **kwargs
                )
                if response.success:
                    return response
            except Exception as e:
                logger.warning(f"Provider {attempt_provider} failed: {e}")
                continue
        
        return AIResponse(
            content="",
            provider=AIProvider.GROQ,
            model="fallback",
            success=False,
            error="All providers failed"
        )
    
    def get_available_providers(self) -> List[AIProvider]:
        
        return self.active_providers.copy()
    
    def reinitialize_providers(self):
        
        self.providers = {}
        self.active_providers = []
        self._setup_providers()


class BaseAIProvider:
    
    
    def __init__(self):
        self.default_model = None
        self.rate_limit_delay = 1.0
        self.last_request_time = 0
    
    async def _rate_limit(self):
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - time_since_last)
        self.last_request_time = time.time()
    
    async def get_response(self, prompt: str, **kwargs) -> AIResponse:
        
        raise NotImplementedError


class GroqProvider(BaseAIProvider):
    
    
    def __init__(self):
        super().__init__()
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.default_model = "qwen/qwen3-32b"
        self.rate_limit_delay = 0.5
    
    async def get_response(
        self, 
        prompt: str, 
        model: Optional[str] = None,
        max_retries: int = 3,
        **kwargs
    ) -> AIResponse:
        
        
        model = model or self.default_model
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                await self._rate_limit()
                
                response = self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=model,
                    timeout=kwargs.get('timeout', 30),
                )
                
                content = response.choices[0].message.content
                tokens = getattr(response.usage, 'total_tokens', 0) if hasattr(response, 'usage') else 0
                
                return AIResponse(
                    content=content,
                    provider=AIProvider.GROQ,
                    model=model,
                    tokens_used=tokens,
                    response_time=time.time() - start_time,
                    success=True
                )
                
            except Exception as e:
                if attempt == max_retries - 1:
                    return AIResponse(
                        content="",
                        provider=AIProvider.GROQ,
                        model=model,
                        response_time=time.time() - start_time,
                        success=False,
                        error=str(e)
                    )
                await asyncio.sleep(2 ** attempt)


class OpenAIProvider(BaseAIProvider):
    
    
    def __init__(self):
        super().__init__()
        self.client = openai.AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.default_model = "gpt-4o-mini"
        self.rate_limit_delay = 1.0
    
    async def get_response(
        self, 
        prompt: str, 
        model: Optional[str] = None,
        max_retries: int = 3,
        **kwargs
    ) -> AIResponse:
        
        
        model = model or self.default_model
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                await self._rate_limit()
                
                response = await self.client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=model,
                    timeout=kwargs.get('timeout', 30),
                )
                
                content = response.choices[0].message.content
                tokens = response.usage.total_tokens if response.usage else 0
                
                return AIResponse(
                    content=content,
                    provider=AIProvider.OPENAI,
                    model=model,
                    tokens_used=tokens,
                    response_time=time.time() - start_time,
                    success=True
                )
                
            except Exception as e:
                if attempt == max_retries - 1:
                    return AIResponse(
                        content="",
                        provider=AIProvider.OPENAI,
                        model=model,
                        response_time=time.time() - start_time,
                        success=False,
                        error=str(e)
                    )
                await asyncio.sleep(2 ** attempt)


class AnthropicProvider(BaseAIProvider):
    
    
    def __init__(self):
        super().__init__()
        self.client = anthropic.AsyncAnthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        self.default_model = "claude-3-haiku-20240307"
        self.rate_limit_delay = 1.0
    
    async def get_response(
        self, 
        prompt: str, 
        model: Optional[str] = None,
        max_retries: int = 3,
        **kwargs
    ) -> AIResponse:
        
        
        model = model or self.default_model
        start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                await self._rate_limit()
                
                response = await self.client.messages.create(
                    model=model,
                    max_tokens=kwargs.get('max_tokens', 4096),
                    messages=[{"role": "user", "content": prompt}],
                )
                
                content = response.content[0].text
                tokens = getattr(response.usage, 'input_tokens', 0) + getattr(response.usage, 'output_tokens', 0)
                
                return AIResponse(
                    content=content,
                    provider=AIProvider.ANTHROPIC,
                    model=model,
                    tokens_used=tokens,
                    response_time=time.time() - start_time,
                    success=True
                )
                
            except Exception as e:
                if attempt == max_retries - 1:
                    return AIResponse(
                        content="",
                        provider=AIProvider.ANTHROPIC,
                        model=model,
                        response_time=time.time() - start_time,
                        success=False,
                        error=str(e)
                    )
                await asyncio.sleep(2 ** attempt)


class OllamaProvider(BaseAIProvider):
    
    
    def __init__(self):
        super().__init__()
        import requests
        self.requests = requests
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.default_model = os.getenv("OLLAMA_MODEL", "llama3.2")
        self.rate_limit_delay = 0.5
    
    def update_model(self, model_name: str):
        
        self.default_model = model_name
    
    async def get_response(
        self, 
        prompt: str, 
        model: Optional[str] = None,
        max_retries: int = 3,
        **kwargs
    ) -> AIResponse:
        
        
        model = model or self.default_model
        start_time = time.time()
        
        logger.info(f"Ollama provider: Using model {model}")
        logger.info(f"Ollama provider: Base URL {self.base_url}")
        
        for attempt in range(max_retries):
            try:
                await self._rate_limit()
                
                # Check if Ollama is running
                try:
                    health_check = self.requests.get(f"{self.base_url}/api/tags", timeout=5)
                    if health_check.status_code != 200:
                        raise Exception("Ollama service not available")
                except Exception as e:
                    raise Exception(f"Ollama service not running: {e}")
                
                # Make the API call
                response = self.requests.post(
                    f"{self.base_url}/api/generate",
                    json={
                        "model": model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": kwargs.get('temperature', 0.7),
                            "top_p": kwargs.get('top_p', 0.9),
                            "num_predict": kwargs.get('max_tokens', 512)
                        }
                    },
                    timeout=kwargs.get('timeout', 120)  # Increased timeout for complex prompts
                )
                
                if response.status_code != 200:
                    raise Exception(f"Ollama API error: {response.status_code}")
                
                result = response.json()
                content = result.get('response', '')
                
                return AIResponse(
                    content=content,
                    provider=AIProvider.OLLAMA,
                    model=model,
                    tokens_used=result.get('eval_count', 0),
                    response_time=time.time() - start_time,
                    success=True
                )
                
            except Exception as e:
                logger.warning(f"Ollama provider attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    return AIResponse(
                        content="",
                        provider=AIProvider.OLLAMA,
                        model=model,
                        response_time=time.time() - start_time,
                        success=False,
                        error=str(e)
                    )
                await asyncio.sleep(2 ** attempt)


class LocalLLMProvider(BaseAIProvider):
    
    
    def __init__(self):
        super().__init__()
        model_name = os.getenv("LOCAL_MODEL", "microsoft/DialoGPT-medium")
        
        if not (AutoTokenizer and AutoModelForCausalLM and torch):
            raise ImportError("transformers and torch are required for local LLM")
        
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            device_map="auto" if torch.cuda.is_available() else None,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
        )
        self.default_model = model_name
        self.rate_limit_delay = 0.1
    
    async def get_response(
        self, 
        prompt: str, 
        model: Optional[str] = None,
        max_retries: int = 1,
        **kwargs
    ) -> AIResponse:
        
        
        start_time = time.time()
        
        try:
            # Add special tokens if tokenizer doesn't have pad_token
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            inputs = self.tokenizer.encode(prompt, return_tensors="pt")
            
            with torch.no_grad():
                outputs = self.model.generate(
                    inputs,
                    max_new_tokens=kwargs.get('max_tokens', 512),
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
            response_text = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            # Remove the original prompt from response
            if response_text.startswith(prompt):
                response_text = response_text[len(prompt):].strip()
            
            return AIResponse(
                content=response_text,
                provider=AIProvider.LOCAL,
                model=self.default_model,
                tokens_used=len(outputs[0]),
                response_time=time.time() - start_time,
                success=True
            )
            
        except Exception as e:
            return AIResponse(
                content="",
                provider=AIProvider.LOCAL,
                model=self.default_model,
                response_time=time.time() - start_time,
                success=False,
                error=str(e)
            )


# Global AI manager instance
ai_manager = AIProviderManager()


async def get_ai_response(
    prompt: str, 
    provider: Optional[AIProvider] = None,
    **kwargs
) -> AIResponse:
    
    return await ai_manager.get_response(prompt, provider, **kwargs)


def get_available_ai_providers() -> List[str]:
    
    return [provider.value for provider in ai_manager.get_available_providers()]
