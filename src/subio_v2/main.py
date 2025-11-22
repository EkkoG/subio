import sys
import os
from subio_v2.workflow.engine import WorkflowEngine

def main():
    # Default config path or arg
    config_path = "config.toml"
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}")
        return

    # Ensure dist exists
    if not os.path.exists("dist"):
        os.makedirs("dist")

    engine = WorkflowEngine(config_path)
    engine.run()

if __name__ == "__main__":
    main()

