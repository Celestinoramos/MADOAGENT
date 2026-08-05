"""Module entrypoint for `python -m mado`."""

from .cli import app


def main() -> None:
    """Run the Typer application."""
    app()


if __name__ == "__main__":
    main()
