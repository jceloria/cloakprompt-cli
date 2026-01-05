#!/usr/bin/env python3
"""
CLI entry point for cloakprompt.

A command-line tool for redacting sensitive information from text before sending to LLMs.
"""

import logging
import os
from pathlib import Path
from typing import Optional, cast

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from cloakprompt.core.parser import ConfigParser
from cloakprompt.utils.utils import setup_logging, print_banner, print_summary
from cloakprompt.core.redactor import TextRedactor
from cloakprompt.utils.file_loader import InputLoader
from cloakprompt.utils.xdg_config import XDGConfig
from cloakprompt import __version__

# Initialize Typer app
app = typer.Typer(
    name="cloakprompt",
    help="Redact sensitive information from text before sending to LLMs",
    add_completion=False
)

# Initialize Rich console
console = Console()
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def find_config_path(config_arg: Optional[str]) -> Optional[str]:
    """
    Find configuration file path with XDG fallback.

    Args:
        config_arg: Config path from command line argument

    Returns:
        Config file path if found, None otherwise
    """
    # If config argument is provided, use it
    if config_arg:
        config_path = Path(config_arg)
        if config_path.exists():
            return str(config_path)
        else:
            logger.warning(f"Config file not found: {config_arg}")
            return None

    # Otherwise, try to find config in XDG locations
    xdg_config_path = XDGConfig.find_config_file()
    if xdg_config_path:
        logger.info(f"Using config from XDG location: {xdg_config_path}")
        return str(xdg_config_path)

    # No config found
    return None


@app.command()
def redact(
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Text to redact"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="File to redact"),
    stdin: bool = typer.Option(False, "--stdin", help="Read from stdin"),
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Custom configuration file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress all output except errors"),
    summary: bool = typer.Option(False, "--summary", "-s", help="Show pattern summary and exit"),
    details: bool = typer.Option(True, "--details", "-d", help="Show detailed redaction information")
):
    """
    Redact sensitive information from text, files, or stdin.

    Configuration is loaded from:
    1. --config option if provided
    2. XDG config location (~/.config/cloakprompt-cli/config.yaml) if exists
    3. Default built-in patterns otherwise

    Examples:
        cloakprompt redact --text "my secret key is AKIA1234567890ABCDEF"
        cloakprompt redact --file config.log
        echo "secret data" | cloakprompt redact --stdin
        cloakprompt redact --file app.log --config security.yaml
    """
    try:
        # Setup logging
        setup_logging(verbose, quiet)

        # Print banner (unless quiet mode)
        if not quiet:
            print_banner(console)

        # Find config file
        config_path = find_config_path(config)

        # Initialize components
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=quiet
        ) as progress:
            task_id = progress.add_task("Initializing redactor...", total=None)

            config_parser = ConfigParser()
            redactor = TextRedactor(config_parser)

            progress.update(task_id, description="Redactor ready")

        # Show pattern summary if requested
        if summary:
            if not quiet:
                print_summary(console, redactor, config_path)
            return

        # Load input
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                disable=quiet
            ) as progress:
                progress.add_task("Loading input...", total=None)

                input_text = InputLoader.load_input(
                    text=text,
                    file_path=file,
                    use_stdin=stdin
                )

                progress.update(task_id, description="Input loaded")

        except Exception as e:
            console.print(f"[red]Error loading input: {e}[/red]")
            raise typer.Exit(1)

        # Perform redaction
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                disable=quiet
            ) as progress:
                progress.add_task("Redacting sensitive information...", total=None)

                # config_path is already None if no config is found

                if details:
                    result = redactor.redact_with_details(input_text, config_path)
                    redacted_text = result['redacted_text']
                    redactions = result['redactions']
                    total_redactions = result['total_redactions']
                    if file is not None:
                        input_file_path = cast(str, file)
                        file_name, file_extension = os.path.splitext(input_file_path)
                        output_path = f"{file_name}_redacted{file_extension}"
                        with open(output_path, 'w', encoding='utf-8') as output_file:
                            output_file.write(redacted_text)
                else:
                    redacted_text = redactor.redact_text(input_text, config_path)
                    redactions = []
                    total_redactions = 0

                progress.update(task_id, description="Redaction complete")

        except Exception as e:
            console.print(f"[red]Error during redaction: {e}[/red]")
            raise typer.Exit(1)

        # Output results
        if not quiet:
            if total_redactions > 0:
                console.print(f"[green]✓ Redacted {total_redactions} sensitive items[/green]")
            else:
                console.print("[yellow]ℹ No sensitive information found[/yellow]")

        # Print redacted text to stdout
        if not quiet and file is None:
            logger.info(f"Redacted {total_redactions} sensitive items from text")
            print(redacted_text)
        elif file is not None and not quiet:
            input_file_path = cast(str, file)
            file_name, _ = os.path.splitext(input_file_path)
            directory = os.path.dirname(file_name) or "current directory"
            print(f'Redaction completed successfully. Check the {directory}.')

        # Show detailed information if requested
        if details and redactions and not quiet:
            console.print("\n[bold]Redaction Details:[/bold]")

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Pattern", style="cyan")
            table.add_column("Position", style="green")
            table.add_column("Replacement", style="yellow")

            for redaction in redactions:
                position = f"{redaction['start_pos']}-{redaction['end_pos']}"
                table.add_row(
                    redaction['pattern_name'],
                    position,
                    redaction['replacement']
                )

            console.print(table)

    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        raise typer.Exit(130)
    except Exception as e:
        if not quiet:
            console.print(f"[red]Unexpected error: {e}[/red]")
        logger.exception("Unexpected error occurred")
        raise typer.Exit(1)


@app.command()
def patterns(
    config: Optional[str] = typer.Option(None, "--config", "-c", help="Custom configuration file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """Show available redaction patterns."""
    try:
        setup_logging(verbose)
        print_banner(console)

        config_parser = ConfigParser()
        redactor = TextRedactor(config_parser)

        # Find config file
        config_path = find_config_path(config)
        print_summary(console, redactor, config_path)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def config_path():
    """Show where CloakPrompt looks for configuration files."""
    console.print("[bold]Configuration Search Paths:[/bold]")

    # Current directory
    console.print(f"Current directory: {Path.cwd() / 'config.yaml'}")

    # XDG paths
    xdg_config = XDGConfig()
    config_dirs = xdg_config.get_config_dirs()

    for i, config_dir in enumerate(config_dirs):
        prefix = "→ " if i == 0 else "  "
        app_config_path = config_dir / xdg_config.APP_NAME / xdg_config.CONFIG_FILENAME
        console.print(f"{prefix}{app_config_path}")

    # Check if config exists
    found_config = xdg_config.find_config_file()
    if found_config:
        console.print(f"\n[green]✓ Config found at: {found_config}[/green]")
    else:
        console.print("\n[yellow]ℹ No config file found in XDG locations[/yellow]")

    # Default config location for writing
    default_path = xdg_config.get_default_config_path()
    console.print(f"\n[bold]Default config location (for writing):[/bold]")
    console.print(f"→ {default_path}")


@app.command()
def init_config(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config file")
):
    """Create a default configuration file in XDG location."""
    try:
        import yaml

        # Get default config location
        xdg_config = XDGConfig()
        # Create config directory if it doesn't exist
        xdg_config.ensure_config_dir_exists()
        config_path = xdg_config.get_default_config_path()

        # Check if config already exists
        if config_path.exists() and not force:
            console.print(f"[yellow]Config already exists at: {config_path}[/yellow]")
            console.print("Use --force to overwrite")
            raise typer.Exit(1)

        # Create default config
        default_config = {
            "patterns": {
                "CUSTOM_PATTERNS": {
                    "description": "Your custom patterns",
                    "rules": [
                        {
                            "name": "example_domain",
                            "placeholder": "<REDACT_EXAMPLE_DOMAIN>",
                            "regex": "example\\.com"
                        }
                    ]
                }
            }
        }

        # Write config file
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

        console.print(f"[green]✓ Created default config at: {config_path}[/green]")
        console.print("\nYou can now edit this file to add your own patterns.")

    except Exception as e:
        console.print(f"[red]Error creating config: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    console.print(f"🔒 CloakPrompt v{__version__}")
    console.print("Secure text redaction for LLM interactions")


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
