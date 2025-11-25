import sys
import os
import argparse
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
    parser = argparse.ArgumentParser(description="SubIO v2 - Subscription converter")
    parser.add_argument("config", nargs="?", help="Path to config file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without uploading (generate files only)",
    )
    args = parser.parse_args()

    # Default config path or arg
    config_path = args.config or find_default_config()

    if not config_path or not os.path.exists(config_path):
        logger.error(f"Config file not found. Looked for: {', '.join(f'config{ext}' for ext in CONFIG_EXTENSIONS)}")
        return

    # Ensure dist exists
    if not os.path.exists("dist"):
        os.makedirs("dist")

    engine = WorkflowEngine(config_path, dry_run=args.dry_run)
    engine.run()

if __name__ == "__main__":
    main()
