import os
import sys
import argparse
from datetime import datetime, timezone
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.crypto import age
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


def _cmd_age_keygen(args):
    """Generate a new X25519 key pair."""
    try:
        secret_key, public_key = age.generate_x25519_keypair()
    except Exception as e:
        logger.error(f"Key generation failed: {e}")
        sys.exit(1)

    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"# created: {created}")
    print(f"# public key: {public_key}")
    print(secret_key)


def _cmd_age_convert(args):
    """Convert a secret key to its public key."""
    try:
        public_key = age.secret_key_to_public(args.secret_key)
    except Exception as e:
        logger.error(f"Failed to convert secret key: {e}")
        sys.exit(1)
    print(public_key)


def _cmd_age_encrypt(args):
    """Encrypt a file with an age public key."""
    public_key, source, target = args.public_key, args.source, args.target

    if source == "-":
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(source, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            logger.error(f"Source file not found: {source}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to read source file: {e}")
            sys.exit(1)

    try:
        encrypted = age.encrypt_bytes(data, public_key)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        sys.exit(1)

    if target == "-":
        sys.stdout.buffer.write(encrypted)
    else:
        try:
            with open(target, "wb") as f:
                f.write(encrypted)
            logger.success(f"Encrypted: {source} -> {target}")
        except Exception as e:
            logger.error(f"Failed to write target file: {e}")
            sys.exit(1)


def _cmd_age_decrypt(args):
    """Decrypt an age-encrypted file with a secret key."""
    secret_key, source, target = args.secret_key, args.source, args.target

    if source == "-":
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(source, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            logger.error(f"Source file not found: {source}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to read source file: {e}")
            sys.exit(1)

    try:
        decrypted = age.decrypt_bytes(data, secret_key)
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        sys.exit(1)

    if target == "-":
        sys.stdout.buffer.write(decrypted)
    else:
        try:
            with open(target, "wb") as f:
                f.write(decrypted)
            logger.success(f"Decrypted: {source} -> {target}")
        except Exception as e:
            logger.error(f"Failed to write target file: {e}")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="subio",
        description="SubIO v2 - Subscription converter.",
    )
    subparsers = parser.add_subparsers(
        title="subcommands", dest="subcommand", metavar="<subcommand>"
    )

    # subio convert [config] [--dry-run] [--clean-gist]
    convert_parser = subparsers.add_parser(
        "convert",
        help="Convert subscriptions",
        description="Convert proxy subscriptions using the given config file.",
    )
    convert_parser.add_argument("config", nargs="?", help="Path to config file")
    convert_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without pushing to remote (clone, commit locally only)",
    )
    convert_parser.add_argument(
        "--clean-gist",
        action="store_true",
        help="Clean all existing files in gist before uploading",
    )

    # subio age {keygen,convert,encrypt,decrypt}
    age_parser = subparsers.add_parser(
        "age",
        help="Age encryption utilities",
        description="Age encryption utilities for managing keys and files.",
    )
    age_sub = age_parser.add_subparsers(
        title="commands", dest="age_command", metavar="<command>"
    )

    keygen = age_sub.add_parser("keygen", help="Generate a new X25519 key pair")
    keygen.set_defaults(age_func=_cmd_age_keygen)

    convert = age_sub.add_parser("convert", help="Convert secret key to public key")
    convert.add_argument("secret_key", help="Age secret key (AGE-SECRET-KEY-1...)")
    convert.set_defaults(age_func=_cmd_age_convert)

    encrypt = age_sub.add_parser("encrypt", help="Encrypt a file with age public key")
    encrypt.add_argument("public_key", help="Age public key (age1...)")
    encrypt.add_argument("source", help="Source file path (or '-' for stdin)")
    encrypt.add_argument("target", nargs="?", default="-", help="Target file path (or '-' for stdout, default: '-')")
    encrypt.set_defaults(age_func=_cmd_age_encrypt)

    decrypt = age_sub.add_parser("decrypt", help="Decrypt an age-encrypted file")
    decrypt.add_argument("secret_key", help="Age secret key (AGE-SECRET-KEY-1...)")
    decrypt.add_argument("source", help="Source file path (or '-' for stdin)")
    decrypt.add_argument("target", nargs="?", default="-", help="Target file path (or '-' for stdout, default: '-')")
    decrypt.set_defaults(age_func=_cmd_age_decrypt)

    args = parser.parse_args()

    # Handle "age" subcommand
    if args.subcommand == "age":
        if hasattr(args, "age_func"):
            args.age_func(args)
        else:
            age_parser.print_help()
        return

    # Handle "convert" subcommand
    if args.subcommand == "convert":
        config_path = args.config or find_default_config()

        if not config_path or not os.path.exists(config_path):
            logger.error(
                f"Config file not found. Looked for: {', '.join(f'config{ext}' for ext in CONFIG_EXTENSIONS)}"
            )
            return

        if not os.path.exists("dist"):
            os.makedirs("dist")

        engine = WorkflowEngine(
            config_path, dry_run=args.dry_run, clean_gist=args.clean_gist
        )
        engine.run()
        return

    # No subcommand given
    parser.print_help()


if __name__ == "__main__":
    main()
