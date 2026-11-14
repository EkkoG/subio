import argparse
import json
import os
import sys
import tempfile
from contextlib import ExitStack, nullcontext
from datetime import datetime, timezone
from pathlib import Path

from subio_v2.core.errors import (
    ConfigError,
    ConfigParseError,
    WorkflowError,
)
from subio_v2.infrastructure import age
from subio_v2.infrastructure.files import filename_aliases, set_private_permissions
from subio_v2.infrastructure.logging import LOG_LEVELS, logger
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.parameters import (
    ParameterError,
    normalize_parameters,
)
from subio_v2.workflow.report import build_report, render_report

# Supported config file extensions in priority order
CONFIG_EXTENSIONS = [".toml", ".yaml", ".yml", ".json", ".json5"]


def _atomic_write_bytes(target: str, data: bytes) -> None:
    target_path = Path(target).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=".subio-write-", suffix=".tmp", dir=target_path.parent
    )
    try:
        with os.fdopen(fd, "wb") as output:
            set_private_permissions(output.fileno(), temp_name)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, target_path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def find_default_config() -> str | None:
    """Find default config file by checking supported extensions."""
    for ext in CONFIG_EXTENSIONS:
        path = f"config{ext}"
        if os.path.exists(path):
            return path
    return None


def _resolve_config_path(config: str | None) -> str | None:
    path = config or find_default_config()
    if not path or not os.path.exists(path):
        logger.error(
            "Config file not found. Looked for: "
            + ", ".join(f"config{ext}" for ext in CONFIG_EXTENSIONS)
        )
        return None
    return path


def _write_report(report: dict, output_format: str, output: str | None) -> None:
    content = render_report(report, output_format)
    if output:
        _atomic_write_bytes(output, content.encode("utf-8"))
        logger.info(f"Report written to {output}")
    elif output_format == "json":
        sys.stdout.write(content)
    else:
        print(content, end="")


def _config_secrets(config):
    return [
        config.age_secret_key,
        *(provider.age_secret_key for provider in config.providers),
        *(uploader.token for uploader in config.uploaders),
        *(str(spec.default) for artifact in config.artifacts
          for spec in artifact.params.values() if spec.default is not None),
    ]


def _run_init(args) -> int:
    from subio_v2.workflow.starter import initialize_project

    try:
        config_path = initialize_project(
            Path(args.directory), preset=args.preset,
            targets=tuple(args.target or ("mihomo",)),
        )
    except (OSError, ValueError) as exc:
        logger.error(f"Project initialization failed: {exc}")
        return 1
    logger.success(f"Project created: {config_path}")
    logger.info("Replace the example servers and passwords before client use")
    return 0


def _subscription_qr(url: str) -> bytes:
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
    except ImportError:
        raise ParameterError("Install subio[qr] to create QR codes") from None
    try:
        return qrcode.make(url, image_factory=SvgPathImage).to_string()
    except (qrcode.exceptions.DataOverflowError, ValueError):
        # qrcode 8.2 can reject auto-fit version 41 with ValueError.
        raise ParameterError("Subscription URL exceeds QR code capacity") from None


def _run_links(args) -> int:
    from dataclasses import asdict
    from subio_v2.workflow.subscription_links import build_subscription_links

    try:
        pairs = []
        for raw in args.param:
            name, separator, value = raw.partition("=")
            if not separator:
                raise ParameterError("Rendering parameter must use NAME=VALUE")
            pairs.append((name, value))
        config_path = args.config or find_default_config()
        if config_path is None:
            raise ParameterError("Config file not found")
        config = ConfigLoader.load(config_path)
        links = build_subscription_links(
            config, args.base_url, os.environ.get("SUBIO_RENDER_TOKEN", ""),
            artifact_name=args.artifact, parameter_pairs=tuple(pairs),
        )
        if args.qr and len(links) != 1:
            raise ParameterError("Select one output with --artifact to create a QR code")
        if args.qr and args.output and Path(args.qr).resolve() == Path(args.output).resolve():
            raise ParameterError("Link output and QR output must use different files")
        qr = _subscription_qr(links[0].url) if args.qr else None
        if args.qr and args.output:
            output_path, qr_path = Path(args.output).resolve(), Path(args.qr).resolve()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            qr_path.parent.mkdir(parents=True, exist_ok=True)
            if output_path.parent.samefile(qr_path.parent):
                aliases = filename_aliases(output_path.parent, (output_path.name, qr_path.name))
                if aliases[output_path.name] == aliases[qr_path.name]:
                    raise ParameterError("Link output and QR output must use different files")
        if args.report_format == "json":
            content = json.dumps([asdict(link) for link in links], ensure_ascii=False, indent=2) + "\n"
        else:
            content = "".join(
                f"{link.file_name} ({link.target})\n  URL: {link.url}\n"
                + (f"  Import: {link.install_url}\n" if link.install_url else "")
                for link in links
            )
        if args.output:
            _atomic_write_bytes(args.output, content.encode("utf-8"))
        if qr is not None:
            _atomic_write_bytes(args.qr, qr)
        if not args.output:
            sys.stdout.write(content)
    except ParameterError as exc:
        logger.error(str(exc))
        return 1
    except (WorkflowError, OSError, ValueError) as exc:
        logger.error(f"Subscription link generation failed ({type(exc).__name__})")
        return 1
    return 0


def _run_convert(args) -> int:
    parameter_mode = bool(args.param)
    redactions = [raw.partition("=")[2] for raw in args.param]
    try:
        with logger.redacting(redactions) if any(redactions) else nullcontext():
            pairs = []
            for raw in args.param:
                name, separator, value = raw.partition("=")
                if not separator:
                    raise ParameterError("Rendering parameter must use NAME=VALUE")
                pairs.append((name, value))
            parameter_pairs = tuple(pairs)
            # Check transport-independent limits even when there are no artifacts.
            normalize_parameters({}, parameter_pairs)
            config_path = _resolve_config_path(args.config)
            if config_path is None:
                if parameter_mode:
                    raise ConfigError("Config file not found")
                return 1
            config = ConfigLoader.load(config_path)
        parameter_mode = parameter_mode or any(item.parameterized for item in config.providers)
        redactions.extend(_config_secrets(config))
        with logger.redacting(redactions) if any(redactions) else nullcontext():
            engine = WorkflowEngine(
                config_path,
                dry_run=args.dry_run,
                clean_gist=args.clean_gist,
                write_manifest=args.write_manifest,
                clean_dist=args.clean_dist,
                parameter_pairs=parameter_pairs,
                config=config,
            )
            engine.run()
    except ConfigParseError as exc:
        # Syntax failures can contain defaults before parameter mode is knowable.
        location = ""
        if exc.line is not None:
            location = f"; line={exc.line}"
            if exc.column is not None:
                location += f"; column={exc.column}"
        logger.error(f"Conversion failed: config_error{location}")
        return 1
    except Exception as exc:
        if not parameter_mode:
            if not isinstance(exc, WorkflowError):
                raise
        with logger.redacting(redactions) if any(redactions) else nullcontext():
            logger.error(f"{type(exc).__name__}: {exc}" if parameter_mode else str(exc))
        return 1
    return 0


def _run_check(args) -> int:
    quiet = args.report_format == "json" and args.output is None
    context = logger.silenced() if quiet else nullcontext()
    with context, ExitStack() as scopes:
        config_path = _resolve_config_path(args.config)
        if config_path is None:
            report = build_report(fatal_error="Config file not found")
        else:
            try:
                config = ConfigLoader.load(config_path)
                scopes.enter_context(logger.redacting(_config_secrets(config)))
                engine = WorkflowEngine(config_path, dry_run=True, config=config)
                preparation = engine.prepare()
                report = build_report(
                    preparation.provider_result,
                    preparation.artifact_result,
                    dist_dir=Path("dist") if args.compare_dist else None,
                    ruleset_metadata=preparation.ruleset_metadata,
                )
            except WorkflowError as exc:
                report = build_report(
                    fatal_error=str(exc),
                    extra_issues=tuple(getattr(exc, "issues", ())),
                )
    _write_report(report, args.report_format, args.output)
    return 1 if report["status"] == "error" else 0


def _run_inspect(args) -> int:
    quiet = args.report_format == "json" and args.output is None
    context = logger.silenced() if quiet else nullcontext()
    with context, ExitStack() as scopes:
        config_path = _resolve_config_path(args.config)
        if config_path is None:
            report = build_report(fatal_error="Config file not found")
        else:
            try:
                config = ConfigLoader.load(config_path)
                scopes.enter_context(logger.redacting(_config_secrets(config)))
                engine = WorkflowEngine(config_path, dry_run=True, config=config)
                if args.inspect_command == "providers":
                    provider_result = engine.load_providers()
                    report = build_report(provider_result)
                else:
                    preparation = engine.prepare()
                    report = build_report(
                        preparation.provider_result,
                        preparation.artifact_result,
                        ruleset_metadata=preparation.ruleset_metadata,
                    )
            except WorkflowError as exc:
                report = build_report(
                    fatal_error=str(exc),
                    extra_issues=tuple(getattr(exc, "issues", ())),
                )
    _write_report(report, args.report_format, args.output)
    return 1 if report["status"] == "error" else 0


def _run_serve(args) -> int:
    try:
        from subio_v2.server import serve
    except ImportError:
        logger.error("Serving requires the server extra: install subio[server]")
        return 1
    config_path = args.config or find_default_config()
    if config_path is None:
        logger.error("Render service configuration is invalid")
        return 1
    return serve(config_path, host=args.host, port=args.port, log_level=args.log_level,
                 refresh_interval=args.refresh_interval,
                 max_snapshot_age=args.max_snapshot_age)


def _positive_seconds(value: str) -> int:
    try:
        seconds = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Seconds must be a positive integer") from None
    if seconds <= 0:
        raise argparse.ArgumentTypeError("Seconds must be a positive integer")
    return seconds


def _serve_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Port must be an integer from 1 to 65535") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("Port must be an integer from 1 to 65535")
    return port


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
        public_key = age.secret_key_to_public(_age_identity(args))
    except Exception as e:
        logger.error(f"Failed to convert secret key ({type(e).__name__})")
        sys.exit(1)
    print(public_key)


def _age_identity(args) -> str:
    if args.identity_file is None:
        return args.secret_key
    try:
        content = Path(args.identity_file).read_text(encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("Cannot read identity file") from exc
    identities = [line.strip() for line in content.splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]
    if len(identities) != 1 or age.verify_secret_key(identities[0]) is not None:
        raise ValueError("Identity file requires one valid X25519 identity")
    return identities[0]


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
    source, target = args.source, args.target
    try:
        secret_key = _age_identity(args)
    except Exception as exc:
        logger.error(f"Failed to load secret key ({type(exc).__name__})")
        sys.exit(1)

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
        logger.error(f"Decryption failed ({type(e).__name__})")
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

    from subio_v2.workflow.starter import STARTER_PRESETS, STARTER_TARGETS

    init_parser = subparsers.add_parser("init", help="Create an editable starter project")
    init_parser.add_argument("directory", nargs="?", default=".", help="New or empty directory")
    init_parser.add_argument("--preset", choices=STARTER_PRESETS, default="basic")
    init_parser.add_argument("--target", choices=STARTER_TARGETS, action="append",
                             help="Output target; repeat for multiple targets (default: mihomo)")

    links_parser = subparsers.add_parser("links", help="Build subscription and client import URLs")
    links_parser.add_argument("config", nargs="?", help="Path to config file")
    links_parser.add_argument("--base-url", required=True, help="Public service URL, including any proxy prefix")
    links_parser.add_argument("--artifact", help="Select one concrete output filename")
    links_parser.add_argument("--param", action="append", default=[], metavar="NAME=VALUE")
    links_parser.add_argument("--format", dest="report_format", choices=("text", "json"), default="text")
    links_parser.add_argument("--output", help="Write links to a private file instead of stdout")
    links_parser.add_argument("--qr", metavar="SVG_FILE", help="Write a local QR code for one output; requires subio[qr]")

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
    convert_parser.add_argument(
        "--write-manifest",
        action="store_true",
        help="Write the generated artifact manifest under dist",
    )
    convert_parser.add_argument(
        "--clean-dist",
        action="store_true",
        help="Remove only stale artifacts recorded by the previous manifest",
    )
    convert_parser.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Bind an artifact parameter; repeat for multiple literal values",
    )

    report_formats = ("text", "json")
    serve_parser = subparsers.add_parser(
        "serve", help="Serve authenticated GET renders"
    )
    serve_parser.add_argument("config", nargs="?", help="Path to config file")
    serve_parser.add_argument("--host", default="127.0.0.1", metavar="HOST",
                              help="Bind address (default: 127.0.0.1; use 0.0.0.0 for all IPv4 interfaces)")
    serve_parser.add_argument("--port", type=_serve_port, default=8000,
                              metavar="PORT", help="Listening port (default: 8000)")
    serve_parser.add_argument("--log-level", type=str.lower, choices=tuple(LOG_LEVELS), default="info",
                              help="Service log threshold (default: info; debug adds resource details)")
    serve_parser.add_argument("--refresh-interval", type=_positive_seconds, default=300,
                              metavar="SECONDS", help="Wait between resource refreshes (default: 300)")
    serve_parser.add_argument("--max-snapshot-age", type=_positive_seconds, default=900,
                              metavar="SECONDS", help="Maximum resource age, at least refresh interval (default: 900)")

    check_parser = subparsers.add_parser(
        "check",
        help="Validate and render without writing artifacts or uploading",
        description="Run the complete workflow prepare stage without side effects.",
    )
    check_parser.add_argument("config", nargs="?", help="Path to config file")
    check_parser.add_argument("--format", dest="report_format", choices=report_formats, default="text")
    check_parser.add_argument("--output", help="Write the report to a file")
    check_parser.add_argument(
        "--compare-dist",
        action="store_true",
        help="Compare generated artifact hashes with the dist directory",
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect providers or generated artifacts",
    )
    inspect_sub = inspect_parser.add_subparsers(
        title="inspect targets", dest="inspect_command", metavar="<target>"
    )
    for target in ("providers", "artifacts"):
        target_parser = inspect_sub.add_parser(target)
        target_parser.add_argument("config", nargs="?", help="Path to config file")
        target_parser.add_argument(
            "--format", dest="report_format", choices=report_formats, default="text"
        )
        target_parser.add_argument("--output", help="Write the report to a file")

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
    convert.add_argument("secret_key", nargs="?", help="Legacy age secret key in argv")
    convert.add_argument("--identity-file", help="File with one X25519 identity")
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
    decrypt.add_argument("--identity-file", help="File with one X25519 identity")
    decrypt.add_argument("paths", nargs="*", metavar="ARG",
                         help="SOURCE [TARGET], or legacy SECRET_KEY SOURCE [TARGET]; '-' uses stdin/stdout")
    decrypt.set_defaults(age_func=_cmd_age_decrypt)

    if sys.argv[1:2] == ["convert"]:
        # argparse otherwise includes unrecognized arguments and their values.
        def convert_parse_error(_message):
            convert_parser.exit(
                2, "subio convert: error: invalid_arguments; use subio convert --help\n"
            )

        parser.error = convert_parser.error = convert_parse_error
    elif sys.argv[1:2] == ["links"]:
        def links_parse_error(_message):
            links_parser.exit(2, "subio links: error: invalid_arguments; use subio links --help\n")

        parser.error = links_parser.error = links_parse_error
    elif sys.argv[1:2] == ["age"]:
        def age_parse_error(_message):
            age_parser.exit(2, "subio age: error: invalid_arguments; use subio age --help\n")

        for command_parser in (parser, age_parser, keygen, convert, encrypt, decrypt):
            command_parser.error = age_parse_error
    args = parser.parse_args()
    if args.subcommand == "init":
        return _run_init(args)
    if args.subcommand == "links":
        return _run_links(args)
    if args.subcommand == "serve" and args.max_snapshot_age < args.refresh_interval:
        parser.error("Maximum snapshot age must be at least the refresh interval")

    # Handle "age" subcommand
    if args.subcommand == "age":
        if args.age_command == "convert":
            if (args.identity_file is not None) == (args.secret_key is not None):
                convert.error("Select one identity input")
        elif args.age_command == "decrypt":
            paths = args.paths
            if args.identity_file is None:
                if not 2 <= len(paths) <= 3:
                    decrypt.error("Expected SECRET_KEY SOURCE [TARGET]")
                args.secret_key, *paths = paths
            elif not 1 <= len(paths) <= 2:
                decrypt.error("Expected SOURCE [TARGET]")
            args.source = paths[0]
            args.target = paths[1] if len(paths) == 2 else "-"
        if hasattr(args, "age_func"):
            args.age_func(args)
        else:
            age_parser.print_help()
        return 0

    # Handle "convert" subcommand
    if args.subcommand == "convert":
        return _run_convert(args)

    if args.subcommand == "check":
        return _run_check(args)

    if args.subcommand == "serve":
        return _run_serve(args)

    if args.subcommand == "inspect":
        if not args.inspect_command:
            inspect_parser.print_help()
            return 0
        return _run_inspect(args)

    # No subcommand given
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
