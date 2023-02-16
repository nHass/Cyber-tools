import pyshark
import requests

# Replace YOUR_API_KEY with your VirusTotal API key
API_KEY = 'YOUR_API_KEY'

# Open the pcap file
capture = pyshark.FileCapture('file.pcap')

# Initialize an empty list to store IP addresses
ip_addresses = []

# Loop through the packets in the pcap file
for packet in capture:
    # If the packet has an IP layer, extract the source and destination IP addresses
    if 'IP' in packet:
        ip_addresses.append(packet['IP'].src)
        ip_addresses.append(packet['IP'].dst)

# Remove duplicate IP addresses
ip_addresses = list(set(ip_addresses))

# Loop through the IP addresses and submit them to VirusTotal
for ip in ip_addresses:
    # Construct the URL for the VirusTotal API request
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'ip': ip, 'apikey': API_KEY}

    # Submit the API request and parse the response
    response = requests.get(url, params=params)
    response_json = response.json()

    # Check if the IP address is malicious or not
    if response_json['response_code'] == 1:
        if response_json['detected_urls']:
            print(ip, 'is malicious')
        else:
            print(ip, 'is not malicious')
    else:
        print('Error:', response_json['verbose_msg'])
