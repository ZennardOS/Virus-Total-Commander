# Virus Total Commander

A bash script that queries the VirusTotal API to scan file hashes and URLs for malware. Displays analysis statistics with configurable output limits.

<img src="img/virus.png">

## Features
* File Hash Scanning: Check SHA256/SHA1/MD5 hashes against VirusTotal database
* URL Scanning: Submit URLs for real-time analysis
* Configurable Output: Limit results with -h or show all
* Logging: Save output to file with -s

## Dependencies
* Bash shell
* curl, jq, awk 
* Your VirusTotal API key 

## Installation
1. Clone/download the script
2. Set your VirusTotal API key:

`APIKEY="your_actual_api_key_here"`

## Usage 
`./virustotal.sh [-U URL] [-H hash] [-s log_file] [-c algorithm] [-F file_path] [-h heading]`

## Options 

| Flag | Description | Example |
| :--- | :---: | ---: |
| -U | Scan URL | -U "https://example.com" |
| -H  | Check the hash | -H "abc123..." |
| -F | Scan the file | -F "/path/to/file.exe" |
| -s  | Log to file | -s "scan_results.log" |
| -c | Hash algorithm | -c "sha1sum" |
| -h  | Results limit | -h 5 or -h all |


## Examples 
`./virustotal.sh -U google.com`

`./virustotal.sh -h 3 -s scan.log -F ./malware.exe"`


