from typing import Dict, Any
from .state import ScanState
from services.validation import validate_code

def validation_node(state: ScanState) -> Dict[str, Any]:
    """
    Validation Node - First node in the LangGraph pipeline.
    Validates the code syntax before analysis begins.
    """
    code = state["code"]
    lang = state["language"]
    
    is_valid, error_msg, syntax_errors = validate_code(code, lang)
    
    print(f"[Validation Node] is_valid: {is_valid}, syntax_errors: {len(syntax_errors)}")
    return {
        "is_valid": is_valid,
        "validation_error": error_msg,
        "syntax_errors": syntax_errors
    }
