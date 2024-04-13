# VirusTotal API Tool

This script allows you to submit IPs, domains, URLs, or hashes to VirusTotal for security analysis and view the results.

## Requirements

- Python 3
- Requests Library
  - Install using: pip3 install requests
- VirusTotal API Key
  - Obtain from your VirusTotal account settings.

    
## Setup

- Clone/Download this script to your local machine.
- Install Requests Library:
  ```
  pip3 install requests

  ```

- API Key Configuration:
  - Open the script in a text editor.
  - Insert your VirusTotal API key in place of your_api_key_here.

## Usage

Run the script from the command line:
```
python3 virustotal.py
```
Input the IP, Domain, URL, or Hash when prompted and the results will be displayed in the terminal.

## Examples

- To Analyze an IP Address:

```
Enter an IP, Domain, URL, or Hash to analyze: 8.8.8.8
```

- To Analyze a URL:

``` 
Enter an IP, Domain, URL, or Hash to analyze: http://example.com
```

## Output

The results will be shown in JSON format, detailing the analysis findings from VirusTotal.


