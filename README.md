# Web Access Log Threat Analyzer

Simple Bash-based web log threat analyzer for Linux.

## Features

- Detect suspicious paths
- Detect failed requests
- Detect brute-force attempts
- Detect malformed log lines
- IP filtering

## Requirements

- Linux / WSL
- Bash
- grep
- awk
- sed

## Run

```bash
chmod +x analyzer.sh
./analyzer.sh access.log
or
./analyzer.sh access-nginx.log
