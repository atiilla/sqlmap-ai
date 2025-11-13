import os
import logging
import time
from typing import Optional
from dotenv import load_dotenv
from groq import Groq
from groq.types.chat import ChatCompletion

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_groq_response(
    prompt: str,
    model: str = "qwen/qwen3-32b",  # replaced qwen-qwq-32b with qwen/qwen3-32b, per deprecation notice -> https://console.groq.com/docs/deprecations#july-14-2025-qwen-qwq-32b
    role: str = "user",
    max_retries: int = 3,
    retry_delay: int = 2,
    timeout: int = 30,
) -> Optional[str]:
    # Get API key from environment variable with fallback
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable not set")

    client = Groq(api_key=api_key)

    # Retry logic with exponential backoff
    for attempt in range(max_retries):
        try:
            # Create chat completion
            chat_completion: ChatCompletion = client.chat.completions.create(
                messages=[
                    {
                        "role": role,
                        "content": prompt,
                    }
                ],
                model=model,
                timeout=timeout,
            )

            # Validate and return the response
            if chat_completion.choices and chat_completion.choices[0].message.content:
                return chat_completion.choices[0].message.content
            else:
                logger.error("Received an empty or invalid response from Groq API.")
                return None

        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
            else:
                logger.error(f"All {max_retries} attempts failed. Last error: {str(e)}")
                return None

    return None
