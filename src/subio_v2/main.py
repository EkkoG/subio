import sys
import os
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.utils.logger import logger

# Supported config file extensions in priority order
CONFIG_EXTENSIONS = [".toml", ".yaml", ".yml", ".json", ".json5"]


def find_default_config() -> str | None:
    """Find default config file by checking supported extensions."""
    for ext in CONFIG_EXTENSIONS:
        path = f"config{ext}"
        if os.path.exists(path):
            return path
    return None


def main():
    # Default config path or arg
    config_path = None
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    else:
        config_path = find_default_config()
    
    if not config_path or not os.path.exists(config_path):
        logger.error(f"Config file not found. Looked for: {', '.join(f'config{ext}' for ext in CONFIG_EXTENSIONS)}")
        return

    # Ensure dist exists
    if not os.path.exists("dist"):
        os.makedirs("dist")

    engine = WorkflowEngine(config_path)
    engine.run()

if __name__ == "__main__":
    main()
