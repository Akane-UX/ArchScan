
import os
import re
import argparse
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

# Definisi Rule / Pola Ancaman
RULES = [
    {
        "id": "R01",
        "name": "Destructive Command",
        "regex": re.compile(r"rm\s+-r[fF]?\s+(?:/|~|\$HOME|/\*)"),
        "severity": "CRITICAL",
        "description": "Menghapus direktori penting secara paksa."
    },
    {
        "id": "R02",
        "name": "Remote Execution (Pipe to shell)",
        "regex": re.compile(r"(curl|wget).+\|\s*(bash|sh|zsh)"),
        "severity": "CRITICAL",
        "description": "Mengunduh dan langsung mengeksekusi script eksternal."
    },
    {
        "id": "R03",
        "name": "Obfuscated Execution",
        "regex": re.compile(r"base64\s+-d\s+\|\s*(bash|sh)"),
        "severity": "HIGH",
        "description": "Mengeksekusi kode tersembunyi (base64 encoded)."
    },
    {
        "id": "R04",
        "name": "Suspicious Network Activity",
        "regex": re.compile(r"\b(nc|ncat|telnet|socat)\b"),
        "severity": "HIGH",
        "description": "Membuka koneksi jaringan mentah (potensi Reverse Shell/C2)."
    },
    {
        "id": "R05",
        "name": "Modifying System Files",
        "regex": re.compile(r"(>|>>)\s*(/etc/passwd|/etc/shadow|~/\.bashrc|~/\.zshrc)"),
        "severity": "CRITICAL",
        "description": "Mencoba memodifikasi file konfigurasi atau kredensial sistem."
    },
    {
        "id": "R06",
        "name": "Hidden File Execution",
        "regex": re.compile(r"\./\.[a-zA-Z0-9_-]+"),
        "severity": "MEDIUM",
        "description": "Mengeksekusi file tersembunyi."
    },
    {
        "id": "R07",
        "name": "Sudo Usage in PKGBUILD",
        "regex": re.compile(r"\bsudo\b"),
        "severity": "HIGH",
        "description": "Menggunakan sudo di dalam PKGBUILD (seharusnya tidak diperlukan dan dilarang makepkg)."
    },
    {
        "id": "R08",
        "name": "Wget/Curl outside source array",
        "regex": re.compile(r"^\s*(wget|curl)\s+"),
        "severity": "WARNING",
        "description": "Mengunduh file secara manual alih-alih menggunakan array source()."
    }
]

def scan_file(filepath: str) -> List[Dict]:
    """Memindai satu file berdasarkan rules yang ada."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
            
            # Skip comments unless the comment itself is suspicious (opsional, tapi biasanya malware bisa disembunyikan di string)
            # if line_clean.startswith('#'):
            #     continue
                
            for rule in RULES:
                if rule["regex"].search(line):
                    findings.append({
                        "line": line_num,
                        "content": line_clean,
                        "rule": rule
                    })
    except Exception as e:
        console.print(f"[bold red]Error membaca file {filepath}: {e}[/bold red]")
        
    return findings

def main():
    parser = argparse.ArgumentParser(description="ArchScan - PKGBUILD Antivirus")
    parser.add_argument("target", help="Path ke file PKGBUILD atau direktori")
    args = parser.parse_args()

    target_path = os.path.abspath(args.target)
    
    if not os.path.exists(target_path):
        console.print(f"[bold red]Target {target_path} tidak ditemukan![/bold red]")
        return
        
    files_to_scan = []
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file == "PKGBUILD" or file.endswith(".install"):
                    files_to_scan.append(os.path.join(root, file))
                    
    if not files_to_scan:
        console.print("[yellow]Tidak ada file PKGBUILD atau .install yang ditemukan untuk discan.[/yellow]")
        return

    console.print(Panel(f"Memulai pemindaian pada [bold cyan]{len(files_to_scan)}[/bold cyan] file...", title="ArchScan", style="blue"))
    
    total_findings = 0
    
    for file in files_to_scan:
        findings = scan_file(file)
        if findings:
            total_findings += len(findings)
            
            table = Table(title=f"Hasil Pindaian: {os.path.basename(file)}", show_lines=True)
            table.add_column("Line", style="cyan", justify="right", width=5)
            table.add_column("Severity", style="bold")
            table.add_column("Rule Name", style="magenta")
            table.add_column("Description", style="white")
            table.add_column("Code Snippet", style="dim")
            
            for f in findings:
                sev = f['rule']['severity']
                if sev == "CRITICAL":
                    sev_str = "[bold red blink]CRITICAL[/]"
                elif sev == "HIGH":
                    sev_str = "[bold red]HIGH[/]"
                elif sev == "MEDIUM":
                    sev_str = "[bold yellow]MEDIUM[/]"
                else:
                    sev_str = "[bold blue]WARNING[/]"
                    
                snippet = f['content']
                if len(snippet) > 50:
                    snippet = snippet[:47] + "..."
                    
                table.add_row(
                    str(f['line']),
                    sev_str,
                    f['rule']['name'],
                    f['rule']['description'],
                    snippet
                )
            
            console.print(table)
            console.print("\n")
        else:
            console.print(f"[green]✓ {os.path.basename(file)}: Aman. Tidak ada pola mencurigakan.[/green]")

    if total_findings > 0:
        console.print(f"[bold red]Peringatan: Ditemukan {total_findings} indikasi berbahaya![/bold red]")
    else:
        console.print("[bold green]Semua file terlihat aman![/bold green]")

if __name__ == "__main__":
    main()
