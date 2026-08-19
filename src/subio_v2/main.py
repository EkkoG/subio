import argparse
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from subio_v2.crypto import age
from subio_v2.errors import WorkflowError
from subio_v2.utils.logger import logger
from subio_v2.workflow.engine import WorkflowEngine

# Supported config file extensions in priority order
CONFIG_EXTENSIONS = [".toml", ".yaml", ".yml", ".json", ".json5"]


def _atomic_write_bytes(target: str, data: bytes) -> None:
    target_path = Path(target).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{target_path.name}.", suffix=".tmp", dir=target_path.parent
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, target_path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


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
            _atomic_write_bytes(target, encrypted)
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
            _atomic_write_bytes(target, decrypted)
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
        help="Generate and validate locally without contacting upload targets",
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
    encrypt.add_argument(
        "target",
        nargs="?",
        default="-",
        help="Target file path (or '-' for stdout, default: '-')",
    )
    encrypt.set_defaults(age_func=_cmd_age_encrypt)

    decrypt = age_sub.add_parser("decrypt", help="Decrypt an age-encrypted file")
    decrypt.add_argument("secret_key", help="Age secret key (AGE-SECRET-KEY-1...)")
    decrypt.add_argument("source", help="Source file path (or '-' for stdin)")
    decrypt.add_argument(
        "target",
        nargs="?",
        default="-",
        help="Target file path (or '-' for stdout, default: '-')",
    )
    decrypt.set_defaults(age_func=_cmd_age_decrypt)

    args = parser.parse_args()

    # Handle "age" subcommand
    if args.subcommand == "age":
        if hasattr(args, "age_func"):
            args.age_func(args)
        else:
            age_parser.print_help()
        return 0

    # Handle "convert" subcommand
    if args.subcommand == "convert":
        config_path = args.config or find_default_config()

        if not config_path or not os.path.exists(config_path):
            logger.error(
                f"Config file not found. Looked for: {', '.join(f'config{ext}' for ext in CONFIG_EXTENSIONS)}"
            )
            return 1

        try:
            engine = WorkflowEngine(
                config_path, dry_run=args.dry_run, clean_gist=args.clean_gist
            )
            engine.run()
        except WorkflowError as exc:
            logger.error(str(exc))
            return 1
        return 0

    # No subcommand given
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
