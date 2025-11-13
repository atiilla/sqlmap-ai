__version__ = "2.0.7"
__author__ = "Atilla"
__email__ = "atilla@tuta.io"
__description__ = "AI-powered SQL injection testing tool with multiple AI providers"

# Import main components
from .config_manager import config_manager, get_config
from .security_manager import security_manager
from .runner import SQLMapRunner
from .parser import extract_sqlmap_info
from .ai_analyzer import ai_suggest_next_steps
from .adaptive_testing import run_adaptive_test_sequence

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__description__",
    "config_manager",
    "get_config",
    "security_manager",
    "SQLMapRunner",
    "extract_sqlmap_info",
    "ai_suggest_next_steps",
    "run_adaptive_test_sequence",
] 