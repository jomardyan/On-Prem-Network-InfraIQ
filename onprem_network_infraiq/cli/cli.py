"""
Command-line interface for On-Prem Network InfraIQ.
"""

import asyncio
import click
import json
import sys
import ipaddress
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm

from .. import (
    NetworkScanner,
    VulnerabilityScanner,
    PortScanner,
    ScanConfiguration,
    SeverityLevel,
    __version__,
)

console = Console()


def print_banner():
    """Print the application banner."""
    banner = f"""
[bold cyan]╔══════════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]          🔍 On-Prem Network InfraIQ v{__version__}                [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]              Python Network Scanner                      [bold cyan]║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════════╝[/bold cyan]

[bold yellow]⚠️  Use only on networks you own or have explicit permission to test![/bold yellow]
"""
    console.print(banner)


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    On-Prem Network InfraIQ - Enterprise Network Scanner

    A comprehensive network discovery and security assessment tool.
    """
    pass


@cli.group()
def scan():
    """Network scanning commands."""
    pass


@cli.group()
def vuln():
    """Vulnerability scanning commands."""
    pass


@cli.command()
def interactive():
    """Launch interactive mode."""
    print_banner()

    while True:
        console.print("\n[bold green]🔍 Main Menu[/bold green]")
        console.print("1. Network Scanning")
        console.print("2. Vulnerability Assessment")
        console.print("3. Port Scanning")
        console.print("4. Network Utilities")
        console.print("5. Exit")

        try:
            choice = IntPrompt.ask("Select an option", choices=["1", "2", "3", "4", "5"])

            if choice == 1:
                asyncio.run(interactive_network_scan())
            elif choice == 2:
                asyncio.run(interactive_vulnerability_scan())
            elif choice == 3:
                asyncio.run(interactive_port_scan())
            elif choice == 4:
                interactive_network_utils()
            elif choice == 5:
                console.print(
                    "[bold green]Thank you for using On-Prem Network InfraIQ![/bold green]"
                )
                break

        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted by user[/bold red]")
            break
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")


async def interactive_network_scan():
    """Interactive network scanning."""
    console.print("\n[bold cyan]🌐 Network Scanning[/bold cyan]")

    # Get target
    target = Prompt.ask("Enter target (IP, hostname, or CIDR)")

    # Validate target
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
    except ValueError:
        console.print("[bold red]Invalid target format[/bold red]")
        return

    # Get scan configuration
    timeout = IntPrompt.ask("Timeout (seconds)", default=5)
    max_threads = IntPrompt.ask("Max threads", default=100)

    # Get ports
    port_choice = Prompt.ask(
        "Port selection", choices=["common", "top100", "custom"], default="common"
    )

    if port_choice == "custom":
        ports_input = Prompt.ask("Enter ports (comma-separated)")
        ports = [int(p.strip()) for p in ports_input.split(",")]
    else:
        ports = None

    # Create configuration
    config = ScanConfiguration(timeout=timeout, max_threads=max_threads, ports=ports or [])

    # Perform scan
    scanner = NetworkScanner(config)

    try:
        with console.status("[bold green]Scanning network...") as status:
            if "/" in target:
                results = await scanner.scan_network(target)
            else:
                results = await scanner.scan_host(target)

        # Display results
        display_scan_results(results)

        # Save results
        if results and Confirm.ask("Save results to file?"):
            filename = Prompt.ask(
                "Filename", default=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            save_results_to_file(results, filename)

    except Exception as e:
        console.print(f"[bold red]Scan failed: {e}[/bold red]")
    finally:
        scanner.close()


async def interactive_vulnerability_scan():
    """Interactive vulnerability scanning."""
    console.print("\n[bold red]🛡️ Vulnerability Assessment[/bold red]")

    # Get target
    target = Prompt.ask("Enter target (IP, hostname, or CIDR)")

    # Validate target
    try:
        if "/" in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
    except ValueError:
        console.print("[bold red]Invalid target format[/bold red]")
        return

    # Get scan configuration
    timeout = IntPrompt.ask("Timeout (seconds)", default=10)
    max_threads = IntPrompt.ask("Max threads", default=50)

    # Create configuration
    config = ScanConfiguration(
        timeout=timeout, max_threads=max_threads, include_vulnerability_scan=True
    )

    # Perform scan
    scanner = VulnerabilityScanner(config)

    try:
        with console.status("[bold red]Scanning for vulnerabilities...") as status:
            if "/" in target:
                results = await scanner.scan_network(target)
            else:
                results = await scanner.scan_host(target)

        # Display results
        display_vulnerability_results(results)

        # Save results
        if results and Confirm.ask("Save vulnerability report?"):
            filename = Prompt.ask(
                "Filename", default=f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            save_vulnerability_results(results, filename)

    except Exception as e:
        console.print(f"[bold red]Vulnerability scan failed: {e}[/bold red]")
    finally:
        scanner.close()


async def interactive_port_scan():
    """Interactive port scanning."""
    console.print("\n[bold blue]🔌 Port Scanning[/bold blue]")

    # Get target
    target = Prompt.ask("Enter target (IP or hostname)")

    # Validate target
    try:
        ipaddress.ip_address(target)
    except ValueError:
        console.print("[bold red]Invalid IP address[/bold red]")
        return

    # Get scan type
    scan_type = Prompt.ask("Scan type", choices=["tcp", "udp", "both"], default="tcp")

    # Get port range
    port_range = Prompt.ask(
        "Port range", choices=["common", "top100", "top1000", "all", "custom"], default="common"
    )

    # Create configuration
    config = ScanConfiguration(timeout=5, max_threads=100)
    scanner = PortScanner(config)

    try:
        with console.status("[bold blue]Scanning ports...") as status:
            if port_range == "custom":
                start_port = IntPrompt.ask("Start port", default=1)
                end_port = IntPrompt.ask("End port", default=1000)

                if scan_type in ["tcp", "both"]:
                    tcp_results = await scanner.scan_port_range(target, start_port, end_port, "tcp")
                else:
                    tcp_results = []

                if scan_type in ["udp", "both"]:
                    udp_results = await scanner.scan_port_range(target, start_port, end_port, "udp")
                else:
                    udp_results = []

                results = tcp_results + udp_results

            elif port_range == "common":
                if scan_type in ["tcp", "both"]:
                    tcp_results = await scanner.scan_common_ports(target, "tcp")
                else:
                    tcp_results = []

                if scan_type in ["udp", "both"]:
                    udp_results = await scanner.scan_common_ports(target, "udp")
                else:
                    udp_results = []

                results = tcp_results + udp_results

            else:
                # Top N ports
                count = (
                    100 if port_range == "top100" else 1000 if port_range == "top1000" else 65535
                )

                if scan_type in ["tcp", "both"]:
                    tcp_results = await scanner.scan_top_ports(target, count, "tcp")
                else:
                    tcp_results = []

                if scan_type in ["udp", "both"]:
                    udp_results = await scanner.scan_top_ports(target, count, "udp")
                else:
                    udp_results = []

                results = tcp_results + udp_results

        # Display results
        display_scan_results(results)

    except Exception as e:
        console.print(f"[bold red]Port scan failed: {e}[/bold red]")
    finally:
        scanner.close()


def interactive_network_utils():
    """Interactive network utilities."""
    console.print("\n[bold magenta]🔧 Network Utilities[/bold magenta]")

    while True:
        console.print("\n1. IP Address Information")
        console.print("2. Network Calculator")
        console.print("3. DNS Lookup")
        console.print("4. Ping Test")
        console.print("5. Back to Main Menu")

        try:
            choice = IntPrompt.ask("Select an option", choices=["1", "2", "3", "4", "5"])

            if choice == 1:
                ip_info()
            elif choice == 2:
                network_calculator()
            elif choice == 3:
                dns_lookup()
            elif choice == 4:
                ping_test()
            elif choice == 5:
                break

        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")


def ip_info():
    """Display IP address information."""
    ip = Prompt.ask("Enter IP address")

    try:
        ip_obj = ipaddress.ip_address(ip)

        table = Table(title="IP Address Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("IP Address", str(ip_obj))
        table.add_row("Version", f"IPv{ip_obj.version}")
        table.add_row("Is Private", str(ip_obj.is_private))
        table.add_row("Is Loopback", str(ip_obj.is_loopback))
        table.add_row("Is Multicast", str(ip_obj.is_multicast))

        if ip_obj.version == 4:
            table.add_row("Is Reserved", str(ip_obj.is_reserved))
            table.add_row("Is Link Local", str(ip_obj.is_link_local))

        console.print(table)

    except ValueError as e:
        console.print(f"[bold red]Invalid IP address: {e}[/bold red]")


def network_calculator():
    """Network calculator."""
    network = Prompt.ask("Enter network (CIDR notation)")

    try:
        network_obj = ipaddress.ip_network(network, strict=False)

        table = Table(title="Network Information")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Network", str(network_obj))
        table.add_row("Network Address", str(network_obj.network_address))
        table.add_row("Broadcast Address", str(network_obj.broadcast_address))
        table.add_row("Netmask", str(network_obj.netmask))
        table.add_row("Prefix Length", str(network_obj.prefixlen))
        table.add_row("Number of Hosts", str(network_obj.num_addresses))
        table.add_row("Number of Usable Hosts", str(network_obj.num_addresses - 2))

        console.print(table)

        # Show first few hosts
        hosts = list(network_obj.hosts())
        if hosts:
            console.print(f"\n[bold]First 10 hosts:[/bold]")
            for i, host in enumerate(hosts[:10]):
                console.print(f"  {i+1}. {host}")

    except ValueError as e:
        console.print(f"[bold red]Invalid network: {e}[/bold red]")


def dns_lookup():
    """DNS lookup."""
    hostname = Prompt.ask("Enter hostname")

    try:
        import socket

        ip = socket.gethostbyname(hostname)
        console.print(f"[bold green]{hostname} resolves to {ip}[/bold green]")

        # Reverse lookup
        try:
            reverse = socket.gethostbyaddr(ip)
            console.print(f"[bold blue]Reverse lookup: {reverse[0]}[/bold blue]")
        except:
            console.print("[bold yellow]Reverse lookup failed[/bold yellow]")

    except socket.gaierror as e:
        console.print(f"[bold red]DNS lookup failed: {e}[/bold red]")


def ping_test():
    """Ping test."""
    host = Prompt.ask("Enter host to ping")

    import subprocess
    import platform

    # Determine ping command based on OS
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "4", host]
    else:
        cmd = ["ping", "-c", "4", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            console.print(f"[bold green]Ping successful![/bold green]")
            console.print(result.stdout)
        else:
            console.print(f"[bold red]Ping failed![/bold red]")
            console.print(result.stderr)

    except subprocess.TimeoutExpired:
        console.print("[bold red]Ping timed out[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Ping error: {e}[/bold red]")


def display_scan_results(results):
    """Display scan results in a table."""
    if not results:
        console.print("[bold yellow]No results found[/bold yellow]")
        return

    # Filter open ports
    open_ports = [r for r in results if r.is_open]

    if not open_ports:
        console.print("[bold yellow]No open ports found[/bold yellow]")
        return

    table = Table(title="Scan Results")
    table.add_column("IP Address", style="cyan")
    table.add_column("Port", style="green")
    table.add_column("Service", style="blue")
    table.add_column("Response Time", style="yellow")
    table.add_column("Server Info", style="magenta")

    for result in open_ports:
        response_time = f"{result.ping_time:.1f}ms" if result.ping_time else "N/A"
        server_info = (
            result.server_info[:50] + "..." if len(result.server_info) > 50 else result.server_info
        )

        table.add_row(
            str(result.ip_address),
            str(result.port),
            result.service_name,
            response_time,
            server_info,
        )

    console.print(table)

    # Summary
    total_hosts = len(set(str(r.ip_address) for r in results))
    total_open_ports = len(open_ports)

    console.print(f"\n[bold green]Summary:[/bold green]")
    console.print(f"  Hosts scanned: {total_hosts}")
    console.print(f"  Open ports found: {total_open_ports}")


def display_vulnerability_results(results):
    """Display vulnerability results in a table."""
    if not results:
        console.print("[bold green]No vulnerabilities found[/bold green]")
        return

    # Group by severity
    critical = [r for r in results if r.severity == SeverityLevel.CRITICAL]
    high = [r for r in results if r.severity == SeverityLevel.HIGH]
    medium = [r for r in results if r.severity == SeverityLevel.MEDIUM]
    low = [r for r in results if r.severity == SeverityLevel.LOW]

    # Display summary
    console.print(f"\n[bold red]Vulnerability Summary:[/bold red]")
    console.print(f"  Critical: {len(critical)}")
    console.print(f"  High: {len(high)}")
    console.print(f"  Medium: {len(medium)}")
    console.print(f"  Low: {len(low)}")

    # Display detailed results
    table = Table(title="Vulnerability Results")
    table.add_column("Host", style="cyan")
    table.add_column("Port", style="green")
    table.add_column("Severity", style="red")
    table.add_column("Vulnerability", style="blue")
    table.add_column("Description", style="yellow")

    for result in results:
        severity_color = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "green",
        }.get(result.severity, "white")

        description = (
            result.description[:50] + "..." if len(result.description) > 50 else result.description
        )

        table.add_row(
            str(result.host),
            str(result.port),
            f"[{severity_color}]{result.severity}[/{severity_color}]",
            result.title,
            description,
        )

    console.print(table)


def save_results_to_file(results, filename):
    """Save scan results to a file."""
    try:
        # Convert results to JSON-serializable format
        json_results = []
        for result in results:
            json_results.append(
                {
                    "ip_address": str(result.ip_address),
                    "port": result.port,
                    "is_open": result.is_open,
                    "service_name": result.service_name,
                    "ping_time": result.ping_time,
                    "operating_system": result.operating_system,
                    "server_info": result.server_info,
                    "discovered_at": result.discovered_at.isoformat(),
                    "hostname": result.hostname,
                    "is_vulnerable": result.is_vulnerable,
                    "vulnerability_info": result.vulnerability_info,
                    "service_version": result.service_version,
                }
            )

        with open(filename, "w") as f:
            json.dump(
                {"scan_time": datetime.now().isoformat(), "results": json_results}, f, indent=2
            )

        console.print(f"[bold green]Results saved to {filename}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error saving results: {e}[/bold red]")


def save_vulnerability_results(results, filename):
    """Save vulnerability results to a file."""
    try:
        # Convert results to JSON-serializable format
        json_results = []
        for result in results:
            json_results.append(
                {
                    "host": str(result.host),
                    "port": result.port,
                    "service": result.service,
                    "vulnerability": result.vulnerability,
                    "severity": result.severity,
                    "title": result.title,
                    "description": result.description,
                    "recommendation": result.recommendation,
                    "cve_id": result.cve_id,
                    "cvss_score": result.cvss_score,
                    "discovered_at": result.discovered_at.isoformat(),
                }
            )

        with open(filename, "w") as f:
            json.dump(
                {"scan_time": datetime.now().isoformat(), "vulnerabilities": json_results},
                f,
                indent=2,
            )

        console.print(f"[bold green]Vulnerability report saved to {filename}[/bold green]")

    except Exception as e:
        console.print(f"[bold red]Error saving vulnerability report: {e}[/bold red]")


# Scan commands
@scan.command("network")
@click.argument("target")
@click.option("--ports", "-p", help="Comma-separated list of ports to scan")
@click.option("--timeout", "-t", default=5, help="Timeout in seconds")
@click.option("--threads", "-T", default=100, help="Number of threads")
@click.option("--output", "-o", help="Output file")
@click.option(
    "--format", "-f", default="json", type=click.Choice(["json", "csv"]), help="Output format"
)
def scan_network(target, ports, timeout, threads, output, format):
    """Scan a network range."""
    asyncio.run(_scan_network(target, ports, timeout, threads, output, format))


@scan.command("host")
@click.argument("target")
@click.option("--ports", "-p", help="Comma-separated list of ports to scan")
@click.option("--timeout", "-t", default=5, help="Timeout in seconds")
@click.option("--threads", "-T", default=100, help="Number of threads")
@click.option("--output", "-o", help="Output file")
@click.option(
    "--format", "-f", default="json", type=click.Choice(["json", "csv"]), help="Output format"
)
def scan_host(target, ports, timeout, threads, output, format):
    """Scan a single host."""
    asyncio.run(_scan_host(target, ports, timeout, threads, output, format))


# Vulnerability commands
@vuln.command("scan")
@click.argument("target")
@click.option("--timeout", "-t", default=10, help="Timeout in seconds")
@click.option("--threads", "-T", default=50, help="Number of threads")
@click.option("--output", "-o", help="Output file")
@click.option(
    "--format", "-f", default="json", type=click.Choice(["json", "csv"]), help="Output format"
)
def vulnerability_scan(target, timeout, threads, output, format):
    """Scan for vulnerabilities."""
    asyncio.run(_vulnerability_scan(target, timeout, threads, output, format))


# Implementation functions
async def _scan_network(target, ports, timeout, threads, output, format):
    """Scan network implementation."""
    try:
        # Parse ports
        ports_list = None
        if ports:
            ports_list = [int(p.strip()) for p in ports.split(",")]

        # Create configuration
        config = ScanConfiguration(timeout=timeout, max_threads=threads, ports=ports_list or [])

        # Create scanner
        scanner = NetworkScanner(config)

        # Perform scan
        with console.status(f"[bold green]Scanning network {target}..."):
            results = await scanner.scan_network(target)

        # Display results
        display_scan_results(results)

        # Save results
        if output:
            save_results_to_file(results, output)

        scanner.close()

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


async def _scan_host(target, ports, timeout, threads, output, format):
    """Scan host implementation."""
    try:
        # Parse ports
        ports_list = None
        if ports:
            ports_list = [int(p.strip()) for p in ports.split(",")]

        # Create configuration
        config = ScanConfiguration(timeout=timeout, max_threads=threads, ports=ports_list or [])

        # Create scanner
        scanner = NetworkScanner(config)

        # Perform scan
        with console.status(f"[bold green]Scanning host {target}..."):
            results = await scanner.scan_host(target)

        # Display results
        display_scan_results(results)

        # Save results
        if output:
            save_results_to_file(results, output)

        scanner.close()

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


async def _vulnerability_scan(target, timeout, threads, output, format):
    """Vulnerability scan implementation."""
    try:
        # Create configuration
        config = ScanConfiguration(
            timeout=timeout, max_threads=threads, include_vulnerability_scan=True
        )

        # Create scanner
        scanner = VulnerabilityScanner(config)

        # Perform scan
        with console.status(f"[bold red]Scanning {target} for vulnerabilities..."):
            if "/" in target:
                results = await scanner.scan_network(target)
            else:
                results = await scanner.scan_host(target)

        # Display results
        display_vulnerability_results(results)

        # Save results
        if output:
            save_vulnerability_results(results, output)

        scanner.close()

    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        sys.exit(1)


def main():
    """Main entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Fatal error: {e}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
