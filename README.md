# Vulneraptor

Vulneraptor is an authorized-use web security scanner that runs multiple checks
from one command and writes practical reports for later review.

Only scan systems you own or have explicit permission to test.

## What It Does

- Reconnaissance and service discovery
- Reflected XSS checks
- SQL injection checks
- Security header and cookie configuration checks
- Optional local AI analysis with Ollama
- JSON, CSV, and PDF report exports

## Requirements

- Python 3.10 or newer
- Nmap installed and available in `PATH`
- Python packages from `requirements.txt`
- Optional: Ollama for `--ai` reports

The Python dependency `python-nmap` talks to the Nmap application, so installing
the Python package alone is not enough. Confirm Nmap works with:

```bash
nmap --version
```

## Windows Setup

Install Python 3.10+ from the Microsoft Store or from python.org. During setup,
enable "Add Python to PATH" if the installer offers it.

Install Nmap using the official Windows installer, or with `winget`:

```powershell
winget install Insecure.Nmap
```

Open PowerShell in the project folder:

```powershell

```

Create and activate a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation for the current session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the tool:

```powershell
python main.py --help
```

Run a scan:

```powershell
python main.py Target --json --csv --pdf
```

Reports are written to:

```text
reports\Target_report.json
reports\Target_report.csv
reports\Target_report.pdf
```

## Kali Linux Setup From Source

Install system packages:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip python3-full nmap
```

Clone the project:

```bash
git clone https://github.com/sal-mah/Vulneraptor.git
cd Vulneraptor
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Check the tool:

```bash
python main.py --help
```

Run a scan:

```bash
python main.py Target --json --csv --pdf
```

## Kali Linux Setup With A Debian Package

If you have a built Debian package such as `Vulneraptor_2.0.0_all.deb`, install
required system packages first:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-full nmap
```

Install the package from the directory that contains the `.deb` file:

```bash
sudo apt install -y ./Vulneraptor_2.0.0_all.deb
```

The package installs Vulneraptor under `/opt/Vulneraptor` and creates the `Vulneraptor`
command in `/usr/local/bin`.

Check the installed command:

```bash
Vulneraptor --help
```

Run a scan:

```bash
Vulneraptor Target --json --csv --pdf
```

To move it to another Kali machine, copy `Vulneraptor_2.0.0_all.deb` to that
machine and repeat the package install commands.

## Usage

Single target:

```bash
python main.py Target
```

Save JSON, CSV, and PDF reports:

```bash
python main.py Target --json --csv --pdf
```

Legacy filename arguments are accepted, but Vulneraptor still writes reports using
the target name inside the `reports` folder:

```bash
python main.py Target --json scan.json --pdf scan.pdf
```

Output:

```text
reports/Target_report.json
reports/Target_report.pdf
```

Scan targets from a file:

```bash
python main.py --target-file targets.txt --json --csv --pdf
```

Example `targets.txt`:

```text
# One authorized target per line
https://lab.example
192.168.64.129
```

Batch reports use the target-file name:

```text
reports/targets_report.json
reports/targets_report.csv
reports/targets_report.pdf
```

## Local Ollama AI Reports

Vulneraptor can optionally analyze completed scan evidence with a local Ollama
model. The AI feature does not perform scanning; it only reviews the scanner
results.

Install and start Ollama, then make sure the model exists:

```bash
ollama list
ollama run qwen3.5:4b
```

Run with AI analysis:

```bash
python main.py https://Target.com/ --json --pdf --ai --ai-model qwen3.5:4b
```

Use a custom Ollama URL:

```bash
python main.py https://www.Target.com/ --ai --ai-url http://127.0.0.1:11434
```

Diagnostics:

```bash
python test_ollama.py
python test_ollama_generate.py
```

## Reports

Generated reports are saved in the `reports` directory.

For `https://www.Target.com/`, Vulneraptor creates:

```text
reports/Target_report.json
reports/Target_report.csv
reports/Target_report.pdf
```

For IP targets, Vulneraptor creates safe filenames such as:

```text
reports/192_168_64_129_report.json
```

## Tests

Install dependencies first, then run:

```bash
python -m pytest -q
```

## Project Layout

```text
main.py                  CLI entry point
core/scanner.py          Integrated scanner orchestration
core/reporter.py         Terminal and PDF text rendering
modules/recon.py         Reconnaissance module
modules/xss_scanner.py   Reflected XSS module
modules/sqli_scanner.py  SQL injection module
modules/security_config.py
                         Security headers and cookie checks
modules/ollama_analyzer.py
                         Local AI report analysis
reports/                 Generated report output
tests/                   Test suite
```

## Troubleshooting

If Python cannot import `nmap`, reinstall the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

If Nmap is not found, install the Nmap application and confirm:

```bash
nmap --version
```

If AI analysis fails, start Ollama and check that the selected model is
available:

```bash
ollama list
```
