"""ThreatHound CLI."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threathound.ioc import extract_from_path
from threathound.sigma import generate_sigma, save_sigma

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="threathound")
def main() -> None:
    """ThreatHound — Blue Team SOC Automation."""
    pass


@main.command()
@click.argument("path", type=click.Path(path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output JSON file")
@click.option("-r", "--recursive", is_flag=True, help="Recursive directory scan")
def ioc(path: Path, output: Path | None, recursive: bool) -> None:
    """Extract IOCs from files or directories."""
    results = extract_from_path(path, recursive=recursive)
    console.print(f"[green]Scanned {len(results)} file(s)[/green]")

    table = Table(title="Extracted IOCs")
    table.add_column("File", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Count", style="green")

    for result in results:
        iocs = result.get("iocs", {})
        if iocs:
            for ioc_type, values in iocs.items():
                table.add_row(str(result["file"]), ioc_type, str(len(values)))

    console.print(table)

    if output:
        output.write_text(json.dumps(results, indent=2), encoding="utf-8")
        console.print(f"[green]Saved to {output}[/green]")


@main.command()
@click.option("--title", required=True, help="Rule title")
@click.option("--logsource", required=True, help='Logsource JSON, e.g. {"product":"windows"}')
@click.option("--detection", required=True, help='Detection JSON')
@click.option("--level", default="medium", type=click.Choice(["informational", "low", "medium", "high", "critical"]))
@click.option("--tags", default="", help="Comma-separated MITRE tags")
@click.option("-o", "--output", default="-", help="Output file (- for stdout)")
def sigma(title: str, logsource: str, detection: str, level: str, tags: str, output: str) -> None:
    """Generate a Sigma rule from detection logic."""
    import json as json_mod

    ls = json_mod.loads(logsource)
    det = json_mod.loads(detection)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]

    rule = generate_sigma(
        title=title,
        logsource=ls,
        detection=det,
        level=level,
        tags=tag_list,
    )

    if output == "-":
        console.print(Panel(rule, title="Sigma Rule"))
    else:
        save_sigma(rule, output)
        console.print(f"[green]Sigma rule written to {output}[/green]")


@main.command()
def hunts() -> None:
    """Display pre-built Windows threat hunting commands."""
    commands = {
        "Failed Logins (Brute Force)": "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 | Group-Object {$_.Properties[5].Value} | Sort-Object Count -Descending | Select-Object -First 10",
        "After-Hours Logins": "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 500 | Where-Object { $_.TimeCreated.Hour -ge 21 -or $_.TimeCreated.Hour -le 6 }",
        "PowerShell Execution": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 100 | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}",
        "Service Installation": "Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 50 | Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}",
        "Process Creation (Sysmon)": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 200 | Select-Object TimeCreated, @{N='Image';E={$_.Properties[4].Value}}, @{N='CommandLine';E={$_.Properties[10].Value}}",
    }

    for name, cmd in commands.items():
        console.print(Panel(cmd, title=name))


if __name__ == "__main__":
    main()
