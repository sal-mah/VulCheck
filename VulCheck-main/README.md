# VulnScope Lite

VulnScope Lite is an integrated authorized-use security scanner that combines:

1. Reconnaissance
2. Reflected XSS checks
3. SQL injection checks
4. Security configuration checks

Only scan systems you own or are explicitly authorized to assess.

## Setup

```bash
on windoes:
python -m pip install -r requirements.txt
-----------------------------------------------------
Install on Kali
git clone https://github.com/sal-mah/VulCheck.git
cd VulCheck 
sudo apt update
sudo apt install python3 python3-venv python3-full nmap
sudo apt install ./vulcheck_2.0.0_all.deb

Then test:
vulcheck "target"
vulcheck --help
vulcheck --target "target"

The package installs the application under /opt/VulCheck and creates the
vulcheck command in /usr/local/bin.

Transfer to another Kali machine

Copy vulcheck_1.0.0_all.deb to the other machine, then run:

sudo apt update
sudo apt install python3 python3-venv python3-full nmap
sudo apt install ./vulcheck_2.0.0_all.deb

Important

The package currently contains the integrated Recon + Security Configuration
version. XSS and SQLi are represented by the integration layer as skipped
until their scanner modules are added.

Only scan systems you own or are explicitly authorized to assess.

```

Recon uses `python-nmap`, which also requires the Nmap binary to be installed
and available in your system path.

## Usage

```bash
python main.py 192.168.64.129
python main.py http://lab.local --json reports/scan.json
python main.py --target-file targets.txt --json reports/batch.json
```

## Tests

```bash
python -m pytest -q
```
<<<<<<< HEAD


## Local Ollama AI

VulnScope can optionally analyze the completed scanner report using a local
Ollama model. The AI layer does not perform scanning; it analyzes evidence
already produced by Recon, XSS, SQLi, and Security Configuration.

Install/start Ollama and make sure the model exists:

```powershell
ollama list
ollama run qwen3.5:4b
```

Test the API:

```powershell
python test_ollama.py
```

Run a scan with local AI analysis:

```powershell
python main.py http://127.0.0.1:8080/WebGoat --ai
```

Select another local model:

```powershell
python main.py http://127.0.0.1:8080/WebGoat --ai --ai-model cyberuser42/DeepSeek-R1-Distill-Qwen-14B:latest
```

The default Ollama API is:

```text
http://127.0.0.1:11434
```

AI analysis is optional. VulnScope continues to produce its normal report if
Ollama is not enabled.


### Ollama diagnostic

If the AI section reports an empty response:

```powershell
python test_ollama_generate.py
```

The integration disables Qwen thinking for the report call and accepts
both Ollama generate and message-style response fields.
=======
>>>>>>> c687f5530f501fff24f4190a94787dd313e8f81f
