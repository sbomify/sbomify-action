import click
import requests


@click.command()
def main() -> None:
    r = requests.get("https://example.com", timeout=5)
    click.echo(f"status={r.status_code}")


if __name__ == "__main__":
    main()
