# PyPortScan — TCP Port Scanner

PyPortScan is a command-line TCP port scanner built with Python. It was created as a cybersecurity and networking portfolio project to practice TCP connections, socket programming, multithreading, banner grabbing, command-line interfaces, and basic reconnaissance concepts.

> Educational use only. Do not scan systems without explicit permission.

## Features

- TCP port scanning
- Custom target host or IP address
- Custom port ranges
- Support for comma-separated ports and ranges
- `top100` common ports option
- Multithreaded scanning
- Optional banner grabbing
- Known service identification for common ports
- Colored terminal output
- Export results to `.txt` or `.json`
- Configurable timeout and thread count

## Technologies Used

- Python 3
- `socket`
- `argparse`
- `threading`
- `concurrent.futures`
- `json`
- Command-line interface

## Usage

```bash
python PyPortScan.py <target> [options]
```

## Examples

Scan the default port range:

```bash
python PyPortScan.py 192.168.1.1
```

Scan a custom port range:

```bash
python PyPortScan.py scanme.nmap.org -p 1-1000
```

Scan specific ports:

```bash
python PyPortScan.py 10.0.0.1 -p 22,80,443,8080
```

Use the top 100 common ports:

```bash
python PyPortScan.py scanme.nmap.org -p top100
```

Use more threads:

```bash
python PyPortScan.py scanme.nmap.org -p top100 -t 300
```

Enable banner grabbing:

```bash
python PyPortScan.py 10.0.0.1 -p 22,80,443 --banner
```

Save output to a JSON file:

```bash
python PyPortScan.py scanme.nmap.org -p 1-1000 -o results.json
```

Save output to a text file:

```bash
python PyPortScan.py scanme.nmap.org -p 1-1000 -o results.txt
```

Disable colored output:

```bash
python PyPortScan.py scanme.nmap.org --sem-cor
```

## Command-Line Options

| Option | Description |
|---|---|
| `target` | IP address or hostname to scan |
| `-p`, `--portas` | Ports to scan. Accepts formats like `80`, `22,80,443`, `1-1024`, `top100`, or `all` |
| `-t`, `--threads` | Number of concurrent threads |
| `--timeout` | Timeout per port in seconds |
| `--banner` | Attempts to capture service banners |
| `-o`, `--output` | Saves results to `.txt` or `.json` |
| `--sem-cor` | Disables colored terminal output |

## Output

When an open port is found, PyPortScan displays:

- port number
- TCP protocol
- known service name, when available
- optional service banner, when banner grabbing is enabled

Example output:

```text
[ABERTA]     22/tcp  SSH
[ABERTA]     80/tcp  HTTP
[ABERTA]    443/tcp  HTTPS
```

## What I Learned

Through this project, I practiced:

- How TCP connections work
- How port scanning works at a basic level
- How to use Python sockets for network communication
- How to handle timeouts and connection errors
- How to improve scan speed with multithreading
- How to parse command-line arguments
- How to export structured scan results
- How service banners can provide useful information during reconnaissance

## Ethical Use

This tool is intended only for:

- personal learning
- local lab environments
- authorized testing
- systems you own or have explicit permission to scan

Do not use this tool to scan public or private systems without authorization.

## Status

Completed.
