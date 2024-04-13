import requests
import re

def identify_input_type(user_input):
    if re.match(r"https?://", user_input):
        return "url"
    elif re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", user_input):
        return "ip"
    elif re.match(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$", user_input):
        return "hash"
    elif re.match(r"^(?:[a-zA-Z0-9-]{1,63}\.?)+[a-zA-Z]{2,6}$", user_input):
        return "domain"
    else:
        return "invalid"

def submit_to_virustotal(input_data, input_type, api_key):
    base_url = "https://www.virustotal.com/api/v3/"
    headers = {"x-apikey": api_key}

    if input_type == "ip":
        url = f"{base_url}ip_addresses/{input_data}"
    elif input_type == "domain":
        url = f"{base_url}domains/{input_data}"
    elif input_type == "url":
        url = f"{base_url}urls"
        data = {"url": input_data}
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            url_id = response.json()['data']['id']
            url = f"{base_url}analyses/{url_id}"
            return requests.get(url, headers=headers).json()
        else:
            return response.json()
    elif input_type == "hash":
        url = f"{base_url}files/{input_data}"
    else:
        return {"error": "Invalid input type"}

    response = requests.get(url, headers=headers)
    return response.json()

def main():
    user_input = input("Enter an IP, Domain, URL, or Hash to analyze: ")
    api_key = "0cd5b5dce3550c49760399cc70882a611b1488547b1b107b97abc4a7c575a819"  # Replace with your actual VirusTotal API key
    input_type = identify_input_type(user_input)
    
    if input_type == "invalid":
        print("Invalid input. Please enter a valid IP, Domain, URL, or Hash.")
        return

    result = submit_to_virustotal(user_input, input_type, api_key)
    
    print("Analysis Result:")
    print(result)

if __name__ == "__main__":
    main()
