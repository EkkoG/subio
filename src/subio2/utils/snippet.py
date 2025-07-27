"""Snippet loading utility for templates."""
import os
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger('SubIO2.SnippetLoader')


def load_snippets(snippet_dir: Optional[str]) -> str:
    """Load all snippets from directory and convert to Jinja2 macros.
    
    Args:
        snippet_dir: Path to snippet directory
        
    Returns:
        String containing all snippets as Jinja2 macros
    """
    if not snippet_dir or not os.path.exists(snippet_dir):
        return ""
    
    final_snippet_text = ""
    snippet_path = Path(snippet_dir)
    
    for snippet_file in snippet_path.iterdir():
        if not snippet_file.is_file():
            continue
            
        # Validate filename to prevent path traversal
        if '..' in snippet_file.name or '/' in snippet_file.name or '\\' in snippet_file.name:
            logger.error(f"Invalid snippet filename: {snippet_file.name}")
            continue
        
        try:
            snippet_text = snippet_file.read_text(encoding='utf-8')
            
            # Parse snippet format: first line is parameters, rest is content
            lines = snippet_text.split('\n')
            if not lines:
                logger.error(f"Empty snippet file: {snippet_file.name}")
                continue
                
            args = lines[0].strip()
            if not args:
                logger.error(f"Snippet {snippet_file.name} missing parameters")
                continue
                
            content = '\n'.join(lines[1:])
            
            # Convert to Jinja2 macro
            macro_name = snippet_file.stem  # filename without extension
            final_snippet_text += f"{{% macro {macro_name}({args}) -%}}\n{content}\n{{%- endmacro -%}}\n"
            
        except Exception as e:
            logger.error(f"Failed to read snippet {snippet_file.name}: {e}")
            continue
    
    return final_snippet_text