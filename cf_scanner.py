#!/usr/bin/env python3
"""
Cloudflare Edge IP Scanner & Performance Evaluator
==================================================
Fetches fresh Cloudflare IP ranges, generates a massive pool of random IPs,
performs multi-stage connectivity and speed tests, then selects the best
performing (clean) IPs for use with CDN/VLESS/Trojan setups.
All output is in English, the process is live, colourful, and highly engineered.

Author : High-Performance Networking Suite
Version: 4.2.0
License: MIT
"""

import argparse
import asyncio
import ipaddress
import json
import math
import os
import platform
import random
import re
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

# Third-party imports (install via pip)
try:
    import httpx
except ImportError:
    sys.exit("Please install httpx: pip install httpx")

try:
    from rich.console import Console
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskID,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
except ImportError:
    sys.exit("Please install rich: pip install rich")

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------

# Official Cloudflare IP range URLs
CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6"

# Fallback ranges (updated as of 2025)
FALLBACK_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

FALLBACK_IPV6_RANGES = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

# Test parameters
PING_COUNT = 4
PING_TIMEOUT = 2  # seconds
TCP_PORT = 443
TCP_TIMEOUT = 3.0
SPEED_TEST_BYTES = 5_000_000  # 5 MB
SPEED_TEST_TIMEOUT = 15.0
SPEED_TEST_HOST = "speed.cloudflare.com"
SPEED_TEST_PATH = "/__down?bytes=5000000"

# Concurrency limits
MAX_PING_WORKERS = 50
MAX_TCP_WORKERS = 80
MAX_SPEED_WORKERS = 20

# Scoring weights (higher value = more important)
WEIGHT_LATENCY = 0.4
WEIGHT_PACKET_LOSS = 0.3
WEIGHT_DOWNLOAD_SPEED = 0.2
WEIGHT_TCP_SUCCESS = 0.1

# Cache file for ranges
CACHE_FILE = Path.home() / ".cf_ip_ranges.json"
CACHE_TTL_HOURS = 6

# ------------------------------------------------------------------------------
# Rich Console Setup
# ------------------------------------------------------------------------------

console = Console()

# ------------------------------------------------------------------------------
# Helper Utilities
# ------------------------------------------------------------------------------


def is_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv6(ip: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def generate_ips_from_ranges(
    ranges: List[str], count: int, prefer_ipv4: bool = True
) -> List[str]:
    """
    Generate a set of unique, random IPs from the given CIDR ranges.
    Ensures no duplicates and respects the desired count.
    """
    ipv4_nets = []
    ipv6_nets = []
    for cidr in ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.version == 4:
                ipv4_nets.append(net)
            else:
                ipv6_nets.append(net)
        except ValueError:
            continue

    if prefer_ipv4:
        primary = ipv4_nets
        secondary = ipv6_nets
    else:
        primary = ipv6_nets
        secondary = ipv4_nets

    generated: Set[str] = set()
    attempts = 0
    max_attempts = count * 10

    # First, try to generate from primary pools
    while len(generated) < count and attempts < max_attempts:
        attempts += 1
        if primary:
            net = random.choice(primary)
            ip_int = random.randint(
                int(net.network_address) + 1, int(net.broadcast_address) - 1
            )
            ip = str(ipaddress.ip_address(ip_int))
        elif secondary:
            net = random.choice(secondary)
            ip_int = random.randint(
                int(net.network_address) + 1, int(net.broadcast_address) - 1
            )
            ip = str(ipaddress.ip_address(ip_int))
        else:
            break
        generated.add(ip)

    # If still not enough, fill from the other pool
    if len(generated) < count and secondary:
        while len(generated) < count and attempts < max_attempts:
            attempts += 1
            net = random.choice(secondary)
            ip_int = random.randint(
                int(net.network_address) + 1, int(net.broadcast_address) - 1
            )
            ip = str(ipaddress.ip_address(ip_int))
            generated.add(ip)

    return list(generated)[:count]


def fetch_cloudflare_ips() -> List[str]:
    """
    Retrieve the latest Cloudflare IP ranges.
    Uses cached version if fresh, otherwise downloads from official sources.
    """
    # Try cache first
    if CACHE_FILE.exists():
        try:
            data = json.loads(CACHE_FILE.read_text())
            cache_time = datetime.fromisoformat(data["timestamp"])
            if datetime.now() - cache_time < timedelta(hours=CACHE_TTL_HOURS):
                console.log("[green]Using cached IP ranges[/green]")
                return data["ranges"]
        except Exception:
            pass

    console.log("[yellow]Fetching fresh IP ranges from Cloudflare...[/yellow]")
    ranges = []
    # Fetch IPv4
    try:
        resp = httpx.get(CF_IPV4_URL, timeout=10)
        resp.raise_for_status()
        ipv4_ranges = [line.strip() for line in resp.text.splitlines() if line.strip()]
        ranges.extend(ipv4_ranges)
        console.log(f"  IPv4 ranges: {len(ipv4_ranges)}")
    except Exception as e:
        console.log(f"[red]Failed to fetch IPv4 ranges: {e}[/red]")
        ranges.extend(FALLBACK_IPV4_RANGES)
        console.log("[yellow]Using fallback IPv4 ranges[/yellow]")

    # Fetch IPv6
    try:
        resp = httpx.get(CF_IPV6_URL, timeout=10)
        resp.raise_for_status()
        ipv6_ranges = [line.strip() for line in resp.text.splitlines() if line.strip()]
        ranges.extend(ipv6_ranges)
        console.log(f"  IPv6 ranges: {len(ipv6_ranges)}")
    except Exception as e:
        console.log(f"[red]Failed to fetch IPv6 ranges: {e}[/red]")
        ranges.extend(FALLBACK_IPV6_RANGES)
        console.log("[yellow]Using fallback IPv6 ranges[/yellow]")

    # Validate ranges
    valid_ranges = []
    for cidr in ranges:
        try:
            ipaddress.ip_network(cidr, strict=False)
            valid_ranges.append(cidr)
        except ValueError:
            console.log(f"[red]Invalid CIDR skipped: {cidr}[/red]")

    # Cache them
    try:
        CACHE_FILE.write_text(
            json.dumps(
                {"timestamp": datetime.now().isoformat(), "ranges": valid_ranges}
            )
        )
    except Exception:
        pass

    return valid_ranges


# ------------------------------------------------------------------------------
# Ping Test (using system ping command for true ICMP)
# ------------------------------------------------------------------------------


@dataclass
class PingResult:
    ip: str
    success: bool
    avg_rtt_ms: Optional[float] = None
    packet_loss_percent: float = 100.0
    min_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    stddev_rtt_ms: Optional[float] = None


def ping_ip(
    ip: str, count: int = PING_COUNT, timeout: int = PING_TIMEOUT
) -> PingResult:
    """
    Execute a system ping command and parse the output.
    Works on Linux, macOS, and Windows.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip]

    try:
        output = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout * count + 5
        )
        output = output.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return PingResult(ip=ip, success=False, packet_loss_percent=100.0)
    except subprocess.CalledProcessError as e:
        output = e.output.decode(errors="replace") if e.output else ""

    # Parse packet loss
    loss_match = re.search(r"(\d+)% packet loss", output)
    if loss_match:
        loss = float(loss_match.group(1))
    else:
        loss = 100.0

    # Parse RTT statistics
    if system == "windows":
        rtt_match = re.search(
            r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", output
        )
        if rtt_match:
            min_rtt = float(rtt_match.group(1))
            max_rtt = float(rtt_match.group(2))
            avg_rtt = float(rtt_match.group(3))
            return PingResult(
                ip=ip,
                success=True,
                avg_rtt_ms=avg_rtt,
                packet_loss_percent=loss,
                min_rtt_ms=min_rtt,
                max_rtt_ms=max_rtt,
                stddev_rtt_ms=None,
            )
    else:
        # Linux/macOS style: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.789 ms
        rtt_match = re.search(
            r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", output
        )
        if rtt_match:
            min_rtt = float(rtt_match.group(1))
            avg_rtt = float(rtt_match.group(2))
            max_rtt = float(rtt_match.group(3))
            mdev = float(rtt_match.group(4))
            return PingResult(
                ip=ip,
                success=True,
                avg_rtt_ms=avg_rtt,
                packet_loss_percent=loss,
                min_rtt_ms=min_rtt,
                max_rtt_ms=max_rtt,
                stddev_rtt_ms=mdev,
            )

    # If we got some replies but couldn't parse RTT, still mark success if loss < 100
    if loss < 100.0:
        return PingResult(ip=ip, success=True, packet_loss_percent=loss)
    return PingResult(ip=ip, success=False, packet_loss_percent=100.0)


def batch_ping(ips: List[str]) -> Dict[str, PingResult]:
    """Ping a list of IPs concurrently using a thread pool."""
    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Pinging IPs...", total=len(ips))
        with ThreadPoolExecutor(max_workers=MAX_PING_WORKERS) as executor:
            future_to_ip = {executor.submit(ping_ip, ip): ip for ip in ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    res = future.result()
                    results[ip] = res
                except Exception as e:
                    results[ip] = PingResult(
                        ip=ip, success=False, packet_loss_percent=100.0
                    )
                progress.advance(task)
    return results


# ------------------------------------------------------------------------------
# TCP Connectivity Test
# ------------------------------------------------------------------------------


@dataclass
class TCPResult:
    ip: str
    success: bool
    latency_ms: Optional[float] = None  # connection establishment time


def test_tcp(ip: str, port: int = TCP_PORT, timeout: float = TCP_TIMEOUT) -> TCPResult:
    """Attempt a TCP connection to the given IP and port, measure latency."""
    sock = socket.socket(
        socket.AF_INET if is_ipv4(ip) else socket.AF_INET6, socket.SOCK_STREAM
    )
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        latency = (time.perf_counter() - start) * 1000
        return TCPResult(ip=ip, success=True, latency_ms=latency)
    except (socket.timeout, OSError):
        return TCPResult(ip=ip, success=False)
    finally:
        sock.close()


def batch_tcp(ips: List[str]) -> Dict[str, TCPResult]:
    """Test TCP connectivity for many IPs using a thread pool."""
    results = {}
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[magenta]TCP connectivity test...", total=len(ips))
        with ThreadPoolExecutor(max_workers=MAX_TCP_WORKERS) as executor:
            future_to_ip = {executor.submit(test_tcp, ip): ip for ip in ips}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    res = future.result()
                    results[ip] = res
                except Exception:
                    results[ip] = TCPResult(ip=ip, success=False)
                progress.advance(task)
    return results


# ------------------------------------------------------------------------------
# Download Speed Test (using HTTPS with SNI override)
# ------------------------------------------------------------------------------


@dataclass
class SpeedResult:
    ip: str
    success: bool
    download_speed_mbps: Optional[float] = None
    bytes_downloaded: int = 0
    error: Optional[str] = None


async def speed_test_async(
    ip: str,
    host: str = SPEED_TEST_HOST,
    path: str = SPEED_TEST_PATH,
    timeout: float = SPEED_TEST_TIMEOUT,
) -> SpeedResult:
    """
    Download a test file from Cloudflare's speed test endpoint,
    using the IP directly with a custom SNI/Host header.
    """
    url = f"https://{ip}{path}"
    headers = {"Host": host}
    # Create an httpx client that doesn't verify SSL (IP cert mismatch)
    limits = httpx.Limits(max_keepalive_connections=1, max_connections=1)
    async with httpx.AsyncClient(
        verify=False,
        timeout=timeout,
        limits=limits,
        headers=headers,
        http2=True,
    ) as client:
        try:
            start = time.perf_counter()
            response = await client.get(url)
            response.raise_for_status()
            # Read content in chunks to measure total bytes
            total_bytes = 0
            async for chunk in response.aiter_bytes(chunk_size=65536):
                total_bytes += len(chunk)
            elapsed = time.perf_counter() - start
            if elapsed > 0 and total_bytes > 0:
                speed_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
            else:
                speed_mbps = 0.0
            return SpeedResult(
                ip=ip,
                success=True,
                download_speed_mbps=speed_mbps,
                bytes_downloaded=total_bytes,
            )
        except Exception as e:
            return SpeedResult(ip=ip, success=False, error=str(e))


async def batch_speed_test(
    ips: List[str], concurrency: int = MAX_SPEED_WORKERS
) -> Dict[str, SpeedResult]:
    """Run speed tests concurrently with a semaphore."""
    semaphore = asyncio.Semaphore(concurrency)
    results = {}

    async def worker(ip: str):
        async with semaphore:
            return await speed_test_async(ip)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[blue]Download speed test...", total=len(ips))
        tasks = []
        for ip in ips:
            tasks.append(asyncio.ensure_future(worker(ip)))
        for coro in asyncio.as_completed(tasks):
            res = await coro
            results[res.ip] = res
            progress.advance(task)
    return results


# ------------------------------------------------------------------------------
# Scoring & Ranking
# ------------------------------------------------------------------------------


@dataclass
class IPMetrics:
    ip: str
    ping: Optional[PingResult] = None
    tcp: Optional[TCPResult] = None
    speed: Optional[SpeedResult] = None
    final_score: float = 1000.0  # lower is better

    def compute_score(self):
        """
        Compute a composite score (lower = better).
        Missing or failed tests incur high penalty.
        """
        score = 0.0
        total_weight = 0.0

        # 1. Ping score (latency normalized, loss penalty)
        if self.ping and self.ping.success and self.ping.avg_rtt_ms is not None:
            # Normalise latency: 0 ms -> score 0, 500 ms -> score 1, linear
            latency_score = min(self.ping.avg_rtt_ms / 500.0, 1.0)
            loss_score = self.ping.packet_loss_percent / 100.0
            ping_score = 0.7 * latency_score + 0.3 * loss_score
            score += WEIGHT_LATENCY * ping_score
            total_weight += WEIGHT_LATENCY
        else:
            # No successful ping => maximum penalty for this component
            score += WEIGHT_LATENCY * 1.0
            total_weight += WEIGHT_LATENCY

        # 2. TCP score (connection latency)
        if self.tcp and self.tcp.success and self.tcp.latency_ms is not None:
            tcp_latency = min(self.tcp.latency_ms / 500.0, 1.0)
            score += WEIGHT_TCP_SUCCESS * tcp_latency
            total_weight += WEIGHT_TCP_SUCCESS
        else:
            score += WEIGHT_TCP_SUCCESS * 1.0
            total_weight += WEIGHT_TCP_SUCCESS

        # 3. Download speed score (inverted: higher speed -> lower score)
        if (
            self.speed
            and self.speed.success
            and self.speed.download_speed_mbps is not None
        ):
            speed_mbps = self.speed.download_speed_mbps
            # Ideal speed 100 Mbps -> score 0, 0 Mbps -> score 1
            speed_score = max(0.0, 1.0 - speed_mbps / 100.0)
            score += WEIGHT_DOWNLOAD_SPEED * speed_score
            total_weight += WEIGHT_DOWNLOAD_SPEED
        else:
            score += WEIGHT_DOWNLOAD_SPEED * 1.0
            total_weight += WEIGHT_DOWNLOAD_SPEED

        # 4. Packet loss already included in ping; this weight is for overall connectivity
        # So we consider the combined weights normalised.
        if total_weight > 0:
            self.final_score = score / total_weight
        else:
            self.final_score = 1.0  # worst case

    def __str__(self):
        return (
            f"IP: {self.ip} | Score: {self.final_score:.3f} | "
            f"Ping: {self.ping.avg_rtt_ms if self.ping and self.ping.success else 'FAIL'} ms, "
            f"Loss: {self.ping.packet_loss_percent if self.ping else 'N/A'}%, "
            f"TCP: {self.tcp.latency_ms if self.tcp and self.tcp.success else 'FAIL'} ms, "
            f"Speed: {self.speed.download_speed_mbps if self.speed and self.speed.success else 'FAIL'} Mbps"
        )


# ------------------------------------------------------------------------------
# Main Scanner Class
# ------------------------------------------------------------------------------


class CloudflareScanner:
    """Orchestrates the entire scanning pipeline."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.ranges: List[str] = []
        self.generated_ips: List[str] = []
        self.ping_results: Dict[str, PingResult] = {}
        self.tcp_results: Dict[str, TCPResult] = {}
        self.speed_results: Dict[str, SpeedResult] = {}
        self.metrics: List[IPMetrics] = []

    def fetch_ranges(self):
        """Step 1: Obtain Cloudflare IP ranges."""
        console.rule("[bold green]Fetching Cloudflare IP Ranges")
        self.ranges = fetch_cloudflare_ips()
        if not self.ranges:
            console.print("[red]No IP ranges available. Exiting.[/red]")
            sys.exit(1)
        console.print(f"[green]Loaded {len(self.ranges)} CIDR ranges.[/green]")

    def generate_ips(self):
        """Step 2: Generate random IPs from ranges."""
        console.rule("[bold cyan]Generating Random IPs")
        target_count = self.args.count
        prefer_ipv4 = not self.args.prefer_ipv6
        self.generated_ips = generate_ips_from_ranges(
            self.ranges, target_count, prefer_ipv4
        )
        # Remove duplicates just in case
        self.generated_ips = list(set(self.generated_ips))
        console.print(f"[green]Generated {len(self.generated_ips)} unique IPs.[/green]")
        if len(self.generated_ips) < target_count:
            console.print(
                f"[yellow]Requested {target_count} but only {len(self.generated_ips)} could be generated.[/yellow]"
            )

    def run_ping_tests(self):
        """Step 3: Ping all IPs."""
        console.rule("[bold yellow]Ping Test")
        if not self.generated_ips:
            return
        self.ping_results = batch_ping(self.generated_ips)
        successful = sum(1 for r in self.ping_results.values() if r.success)
        console.print(
            f"[green]Ping success: {successful}/{len(self.generated_ips)}[/green]"
        )

    def run_tcp_tests(self):
        """Step 4: TCP connectivity test on all IPs."""
        console.rule("[bold magenta]TCP Connectivity Test")
        if not self.generated_ips:
            return
        self.tcp_results = batch_tcp(self.generated_ips)
        successful = sum(1 for r in self.tcp_results.values() if r.success)
        console.print(
            f"[green]TCP success: {successful}/{len(self.generated_ips)}[/green]"
        )

    def run_speed_tests(self):
        """Step 5: Speed test on IPs that passed TCP or ping (optional filter)."""
        console.rule("[bold blue]Download Speed Test")
        if not self.args.no_speed_test:
            # Select candidates: those that had successful TCP (or ping if TCP unavailable)
            candidates = [
                ip
                for ip in self.generated_ips
                if (ip in self.tcp_results and self.tcp_results[ip].success)
                or (ip in self.ping_results and self.ping_results[ip].success)
            ]
            if not candidates:
                console.print("[red]No candidates for speed test.[/red]")
                return
            console.print(f"[green]Testing speed on {len(candidates)} IPs...[/green]")
            # Run async speed test
            loop = asyncio.get_event_loop()
            self.speed_results = loop.run_until_complete(
                batch_speed_test(candidates, concurrency=MAX_SPEED_WORKERS)
            )
            successful = sum(1 for r in self.speed_results.values() if r.success)
            console.print(
                f"[green]Speed test success: {successful}/{len(candidates)}[/green]"
            )
        else:
            console.print("[yellow]Speed test disabled by --no-speed-test.[/yellow]")

    def compute_metrics(self):
        """Combine all results and compute scores."""
        console.rule("[bold cyan]Computing Scores")
        for ip in self.generated_ips:
            metric = IPMetrics(
                ip=ip,
                ping=self.ping_results.get(ip),
                tcp=self.tcp_results.get(ip),
                speed=self.speed_results.get(ip),
            )
            metric.compute_score()
            self.metrics.append(metric)
        console.print(f"[green]Scored {len(self.metrics)} IPs.[/green]")

    def select_top(self) -> List[str]:
        """Select top N IPs based on final score (lower is better)."""
        # Sort by score ascending
        self.metrics.sort(key=lambda m: m.final_score)
        # Take top N that have at least one successful test (score < 1.0 indicates some success)
        top_ips = []
        for m in self.metrics:
            if m.final_score < 1.0:  # completely dead IPs have score 1.0
                top_ips.append(m.ip)
                if len(top_ips) >= self.args.top:
                    break
        return top_ips

    def display_results(self, top_ips: List[str]):
        """Display a summary table and final list."""
        console.rule("[bold green]Results")
        if not top_ips:
            console.print("[red]No suitable IPs found.[/red]")
            return

        # Build a Rich table for the top IPs
        table = Table(title="Top Clean Cloudflare IPs", box=box.ROUNDED)
        table.add_column("Rank", style="cyan", no_wrap=True)
        table.add_column("IP", style="bold white")
        table.add_column("Score", style="magenta")
        table.add_column("Ping (ms)", style="green")
        table.add_column("Loss %", style="red")
        table.add_column("TCP (ms)", style="blue")
        table.add_column("Speed (Mbps)", style="yellow")

        for rank, ip in enumerate(top_ips, start=1):
            metric = next((m for m in self.metrics if m.ip == ip), None)
            if not metric:
                continue
            ping_ms = (
                f"{metric.ping.avg_rtt_ms:.1f}"
                if metric.ping and metric.ping.success
                else "N/A"
            )
            loss = f"{metric.ping.packet_loss_percent:.0f}" if metric.ping else "N/A"
            tcp_ms = (
                f"{metric.tcp.latency_ms:.1f}"
                if metric.tcp and metric.tcp.success
                else "N/A"
            )
            speed = (
                f"{metric.speed.download_speed_mbps:.2f}"
                if metric.speed and metric.speed.success
                else "N/A"
            )
            table.add_row(
                str(rank),
                ip,
                f"{metric.final_score:.4f}",
                ping_ms,
                loss,
                tcp_ms,
                speed,
            )
        console.print(table)

        # Output the comma-separated list
        ip_list_str = " ,".join(top_ips)
        console.print("\n[bold green]Best IPs (comma-separated):[/bold green]")
        console.print(Panel(ip_list_str, style="bold white on black"))

        # Save to file if requested
        if self.args.output:
            try:
                with open(self.args.output, "w") as f:
                    f.write(ip_list_str)
                console.print(f"[green]Saved to {self.args.output}[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save: {e}[/red]")

        # Also provide a JSON report if verbose
        if self.args.verbose:
            console.print("\n[bold]Detailed JSON:[/bold]")
            detail = []
            for ip in top_ips:
                metric = next((m for m in self.metrics if m.ip == ip), None)
                if metric:
                    detail.append(
                        {
                            "ip": metric.ip,
                            "score": metric.final_score,
                            "ping_avg_ms": metric.ping.avg_rtt_ms
                            if metric.ping
                            else None,
                            "packet_loss": metric.ping.packet_loss_percent
                            if metric.ping
                            else None,
                            "tcp_latency_ms": metric.tcp.latency_ms
                            if metric.tcp
                            else None,
                            "download_mbps": metric.speed.download_speed_mbps
                            if metric.speed
                            else None,
                        }
                    )
            console.print_json(json.dumps(detail, indent=2))

    def run(self):
        """Execute the full pipeline."""
        self.fetch_ranges()
        self.generate_ips()
        self.run_ping_tests()
        self.run_tcp_tests()
        self.run_speed_tests()
        self.compute_metrics()
        top_ips = self.select_top()
        self.display_results(top_ips)


# ------------------------------------------------------------------------------
# Command Line Interface
# ------------------------------------------------------------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cloudflare Edge IP Scanner - Find clean, low-latency IPs for VPN/CDN use.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --top 5 --count 1000
  %(prog)s --top 10 --count 500 --prefer-ipv6 --output best_ips.txt
  %(prog)s --top 3 --count 200 --no-speed-test
        """,
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of best IPs to output (default: 5).",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=500,
        help="Number of random IPs to generate for testing (default: 500).",
    )
    parser.add_argument(
        "--prefer-ipv6",
        action="store_true",
        help="Prefer IPv6 addresses over IPv4 when generating IPs.",
    )
    parser.add_argument(
        "--no-speed-test",
        action="store_true",
        help="Skip download speed test (faster but less accurate).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save the comma-separated IP list to a file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed JSON report.",
    )
    return parser


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------


def main():
    # Disable SSL warnings for self-signed certs when connecting via IP
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = build_argument_parser()
    args = parser.parse_args()

    # Print a fancy banner
    console.print(
        Panel.fit(
            Text("Cloudflare IP Cleaner & Performance Probe", style="bold cyan"),
            subtitle="v4.2.0 - Engineered for High Stability",
            border_style="bright_blue",
        )
    )

    scanner = CloudflareScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print_exception()
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
