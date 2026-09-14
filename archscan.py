import os
import re
import argparse
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

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
        "name": "Sudo in Script",
        "regex": re.compile(r"\bsudo\b"),
        "severity": "WARNING",
        "description": "Menggunakan sudo di dalam skrip (bisa jadi normal, namun patut dicurigai jika tidak terduga)."
    },
    {
        "id": "R08",
        "name": "Suspicious Download",
        "regex": re.compile(r"^\s*(wget|curl)\s+"),
        "severity": "WARNING",
        "description": "Mengunduh file dari internet secara langsung di dalam script."
    }
]

# Direktori yang harus diabaikan untuk menghindari error dan mempercepat scan
IGNORE_DIRS = {'/proc', '/sys', '/dev', '/run', '/tmp', '/var/run', '/var/lock', '/snap', '/mnt'}
TARGET_EXTENSIONS = ('.sh', '.bash', '.zsh', '.install')

def is_target_file(filename: str) -> bool:
    if filename == "PKGBUILD":
        return True
    if filename.endswith(TARGET_EXTENSIONS):
        return True
    return False

def scan_file(filepath: str) -> Dict:
    """Memindai satu file berdasarkan rules yang ada."""
    findings = []
    try:
        # errors='ignore' mencegah program crash jika menemukan karakter aneh/binary
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, 1):
            line_clean = line.strip()
                
            for rule in RULES:
                if rule["regex"].search(line):
                    findings.append({
                        "line": line_num,
                        "content": line_clean,
                        "rule": rule
                    })
    except PermissionError:
        pass # Abaikan file yang tidak bisa diakses
    except Exception as e:
        pass # Abaikan error lain agar proses pemindaian lanjut
        
    return {"filepath": filepath, "findings": findings}

def get_files_to_scan(target_path: str) -> List[str]:
    files_to_scan = []
    
    if os.path.isfile(target_path):
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            # Abaikan direktori sistem yang sensitif
            # Filter in-place pada list dirs agar os.walk tidak memasukinya
            dirs[:] = [d for d in dirs if not any(os.path.join(root, d).startswith(ignore) for ignore in IGNORE_DIRS)]
                
            for file in files:
                if is_target_file(file):
                    files_to_scan.append(os.path.join(root, file))
    
    return files_to_scan

def main():
    parser = argparse.ArgumentParser(description="ArchScan - System Script Antivirus")
    parser.add_argument("target", help="Path ke file atau direktori target (misal: / atau /home/user)")
    args = parser.parse_args()

    target_path = os.path.abspath(args.target)
    
    if not os.path.exists(target_path):
        console.print(f"[bold red]Target {target_path} tidak ditemukan![/bold red]")
        return
        
    console.print(Panel(f"Mengumpulkan daftar file dari [bold cyan]{target_path}[/bold cyan]...\nProses ini mungkin memakan waktu jika target adalah root (/).", title="ArchScan Engine", style="blue"))
    
    files_to_scan = get_files_to_scan(target_path)
                    
    if not files_to_scan:
        console.print("[yellow]Tidak ada file skrip yang didukung untuk discan pada direktori tersebut.[/yellow]")
        return

    total_files = len(files_to_scan)
    console.print(f"Ditemukan [bold cyan]{total_files}[/bold cyan] file untuk dipindai.\n")
    
    all_results = []
    total_findings = 0
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Memindai ancaman...", total=total_files)
        
        # Multithreading scan
        workers = (os.cpu_count() or 1) * 2
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(scan_file, f): f for f in files_to_scan}
            for future in as_completed(futures):
                result = future.result()
                if result["findings"]:
                    all_results.append(result)
                    total_findings += len(result["findings"])
                progress.advance(task)

    # Cetak Hasil
    if all_results:
        console.print("\n[bold red]Hasil Pemindaian:[/bold red]")
        for res in all_results:
            filepath = res["filepath"]
            findings = res["findings"]
            
            table = Table(title=f"File: {filepath}", show_lines=True, title_style="bold magenta")
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
            
    if total_findings > 0:
        console.print(f"[bold red blink]PERINGATAN: Ditemukan total {total_findings} indikasi ancaman![/bold red blink]")
    else:
        console.print("[bold green]Semua file terlihat aman! Tidak ditemukan ancaman.[/bold green]")

if __name__ == "__main__":
    main()
