I. Africa-Centric Datasets

PaySim Synthetic Financial Dataset:

URL: https://www.kaggle.com/datasets/ealaxi/paysim1

Description: A synthetic dataset of ~6.3 million mobile money transactions based on real logs from an African country. Labeled for fraudulent activity, ideal for training models on financial fraud patterns.   

Fraudulent Email Corpus ("Nigerian 419"):

URL: https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus

Description: A collection of over 4,000 classic "Nigerian" advance-fee fraud emails, including full headers and body content. Excellent for NLP model training on social engineering narratives.   

Swahili SMS Detection Dataset:

URL: https://www.kaggle.com/datasets/henrydioniz/swahili-sms-detection-dataset

Description: A set of 1,508 SMS messages in Tanzanian Swahili, labeled as "scam" or "trust." A key resource for building detection capabilities for local African languages.   

419scam.org:

URL: https://419scam.org/

Description: A large, user-submitted archive of advance-fee fraud emails. Not available as a direct download but serves as a rich source for scraping and analysis of ongoing 419 scam campaigns.   

II. General-Purpose Phishing Datasets (for Filtering and Baseline Training)

Kaggle Phishing Email Dataset:

URL: https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset

Description: A composite dataset of ~82,500 labeled emails (spam/legitimate) from various sources, including headers, body, and URLs.   

Hugging Face ealvaradob/phishing-dataset:

URL: https://huggingface.co/datasets/ealvaradob/phishing-dataset

Description: A comprehensive, multi-modal dataset containing emails, SMS messages, URLs, and full website HTML content. An excellent resource for building a versatile detection engine.   

GitHub GregaVrbancic/Phishing-Dataset:

URL: https://github.com/GregaVrbancic/Phishing-Dataset

Description: Over 88,000 website instances with 111 pre-extracted URL and domain features, ideal for training URL classification models.   

III. Real-Time Threat Intelligence Feeds

OpenPhish:

URL: https://openphish.com/

Description: A commercial, AI-driven feed of zero-day phishing URLs. Data includes geographic and network metadata (country, IP, ASN), making it suitable for filtering. Requires a commercial license.   

PhishTank:

URL: https://phishtank.org/

Description: A free, community-driven database of verified phishing URLs. Data is available via API or hourly database download and includes network information like IP and RIR. Free for commercial use.   

IV. Regional Cybersecurity Institutions and Reports

Nigeria - ngCERT:

URL: https://www.cert.gov.ng/

Description: Publishes threat advisories on active campaigns and vulnerabilities relevant to Nigeria.   

Kenya - National KE-CIRT/CC:

URL: https://www.ke-cirt.go.ke/

Description: Issues detailed quarterly reports with statistics on cyber threat events in Kenya.   

South Africa - National Cybersecurity Hub:

URL: https://www.cybersecurityhub.gov.za/

Description: Provides public awareness materials and collaborates with industry partners on threat mitigation.   

Egypt - EG-CERT:

URL: https://egcert.eg/

Description: Issues security alerts and publications focused on protecting critical national infrastructure.   

INTERPOL (AFJOC):

URL: https://www.interpol.int/

Description: Publishes the annual Africa Cyberthreat Assessment Report with high-level statistics and trend analysis.   

Serianu:

URL: https://www.serianu.com/industry-reports.html

Description: An African cybersecurity firm that publishes detailed annual reports on the threat landscape across multiple African countries.   

AfricaCERT:

URL: https://portal.africacert.org/

Description: The coordinating body for CERTs in Africa, providing a directory of national teams and other resources.   

Sample Python Implementation for Geolocation Filtering
The following Python script provides a functional demonstration of the geolocation filtering methodology described in Section 4.2. This script takes a CSV file containing a list of URLs as input, resolves each URL's domain to an IP address, queries the ipinfo.io API to retrieve geolocation and ASN data, and filters for URLs whose infrastructure is located in an African country.

Prerequisites:

Python 3.6+ installed.

Required libraries: Install them using pip:

BASH

_pip install pandas ipinfo_

IPinfo API Token: Sign up for a free account at ipinfo.io to get an API access token. The free tier provides sufficient requests for testing and small-scale projects.

Input Data: A CSV file named urls_to_filter.csv with a header and a single column named url.

Sample Script (geo_filter_africa.py):

import pandas as pd
import ipinfo
import socket
from urllib.parse import urlparse
import time

# --- Configuration ---
IPINFO_ACCESS_TOKEN = 'YOUR_IPINFO_API_TOKEN'  # Replace with your actual token
INPUT_CSV_FILE = 'urls_to_filter.csv'
OUTPUT_CSV_FILE = 'africa_hosted_urls.csv'
REQUEST_DELAY_SECONDS = 0.1 # To respect API rate limits on free tiers

# List of African country codes (ISO 3166-1 alpha-2)
AFRICAN_COUNTRY_CODES = {
    'DZ', 'AO', 'BJ', 'BW', 'BF', 'BI', 'CV', 'CM', 'CF', 'TD', 'KM', 'CG', 'CD',
    'CI', 'DJ', 'EG', 'GQ', 'ER', 'SZ', 'ET', 'GA', 'GM', 'GH', 'GN', 'GW', 'KE',
    'LS', 'LR', 'LY', 'MG', 'MW', 'ML', 'MR', 'MU', 'YT', 'MA', 'MZ', 'NA', 'NE',
    'NG', 'RE', 'RW', 'ST', 'SN', 'SC', 'SL', 'SO', 'ZA', 'SS', 'SD', 'TZ', 'TG',
    'TN', 'UG', 'EH', 'ZM', 'ZW'
}

def get_domain_from_url(url):
    """Extracts the network location (domain) from a URL."""
    try:
        # Ensure URL has a scheme for proper parsing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed_url = urlparse(url)
        return parsed_url.netloc
    except Exception as e:
        print(f"Error parsing URL '{url}': {e}")
        return None

def get_ip_from_domain(domain):
    """Resolves a domain name to an IP address."""
    if not domain:
        return None
    try:
        # gethostbyname returns the first IPv4 address found
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        # This error occurs if the domain cannot be resolved
        print(f"Could not resolve domain: {domain}")
        return None
    except Exception as e:
        print(f"Error resolving domain '{domain}': {e}")
        return None

def main():
    """
    Main function to read URLs, filter them by African geolocation,
    and save the results.
    """
    print("Starting geolocation filtering process...")

    # Initialize the IPinfo handler
    try:
        handler = ipinfo.getHandler(IPINFO_ACCESS_TOKEN)
    except Exception as e:
        print(f"Failed to initialize IPinfo handler. Check your access token. Error: {e}")
        return

    # Read the input CSV file
    try:
        df = pd.read_csv(INPUT_CSV_FILE)
        if 'url' not in df.columns:
            print(f"Error: Input CSV '{INPUT_CSV_FILE}' must contain a column named 'url'.")
            return
    except FileNotFoundError:
        print(f"Error: Input file '{INPUT_CSV_FILE}' not found.")
        return

    print(f"Loaded {len(df)} URLs from '{INPUT_CSV_FILE}'.")

    results =
    
    # Iterate through each URL in the DataFrame
    for index, row in df.iterrows():
        url = row['url']
        print(f"\nProcessing URL ({index + 1}/{len(df)}): {url}")

        domain = get_domain_from_url(url)
        if not domain:
            continue

        ip_address = get_ip_from_domain(domain)
        if not ip_address:
            continue
        
        print(f" -> Resolved domain '{domain}' to IP: {ip_address}")

        try:
            # Get details from the IPinfo API
            details = handler.getDetails(ip_address)
            
            # Check if the 'country' attribute exists and is in our set
            if hasattr(details, 'country') and details.country in AFRICAN_COUNTRY_CODES:
                print(f"  [+] MATCH FOUND: IP is in {details.country_name} ({details.country}).")
                
                # Prepare data for the output DataFrame
                result_data = {
                    'original_url': url,
                    'domain': domain,
                    'ip_address': ip_address,
                    'country_code': details.country,
                    'country_name': details.country_name,
                    'region': getattr(details, 'region', 'N/A'),
                    'city': getattr(details, 'city', 'N/A'),
                    'asn': getattr(details, 'asn', {}).get('asn', 'N/A'),
                    'as_name': getattr(details, 'asn', {}).get('name', 'N/A'),
                    'as_domain': getattr(details, 'asn', {}).get('domain', 'N/A')
                }
                results.append(result_data)
            else:
                country_name = getattr(details, 'country_name', 'Unknown')
                print(f"  [-] No match: IP is in {country_name}. Skipping.")

        except Exception as e:
            print(f"  [!] Error querying IPinfo for '{ip_address}': {e}")

        # Add a small delay to avoid hitting API rate limits
        time.sleep(REQUEST_DELAY_SECONDS)

    # Create a DataFrame from the results and save to CSV
    if results:
        output_df = pd.DataFrame(results)
        output_df.to_csv(OUTPUT_CSV_FILE, index=False)
        print(f"\nProcess complete. Found {len(output_df)} Africa-hosted URLs.")
        print(f"Results saved to '{OUTPUT_CSV_FILE}'.")
    else:
        print("\nProcess complete. No Africa-hosted URLs were found in the input file.")
if __name__ == "__main__":
    main()
