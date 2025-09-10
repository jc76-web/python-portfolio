import requests                      # Used to fetch web pages
from bs4 import BeautifulSoup        # Used to parse HTML content
from urllib.parse import urlparse    # Used to extract parts of a URL (like domain name)
import csv                           # Used to save results into a CSV file
from colorama import Fore, Style     # Used to add colors in the console output

# Ask the user for multiple websites (separated by commas)
sites = input("Enter websites separated by commas (e.g. example.com, python.org): ").split(",")

# Prepare a CSV file to store results
filename = "multi_site_scan_results.csv"
with open(filename, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    # Write the column headers
    writer.writerow(["Website", "Title", "Status", "Suspicious Links", "Suspicious Scripts"])

    # Go through each site entered by the user
    for site in sites:
        site = site.strip()   # Remove extra spaces from input
        if not site.startswith(("http://", "https://")):  
            site = "https://" + site  # Default to https if user didn’t type it

        print(f"\n🔍 Scanning: {site}")

        try:
            # Send an HTTP GET request to fetch the page
            response = requests.get(site, timeout=10)

            # Parse the page with BeautifulSoup
            soup = BeautifulSoup(response.text, "html.parser")

            # Extract the <title> tag text (or N/A if missing)
            title = soup.title.string if soup.title else "N/A"

            # Default status: safe (green check mark)
            status = Fore.GREEN + "✅ Safe"

            suspicious_links = []   # Store links with suspicious patterns
            suspicious_scripts = [] # Store scripts with suspicious patterns

            # List of keywords we consider "suspicious"
            suspicious_keywords = ["javascript:", "onerror", "onload", "<script>", "base64", "eval"]

            # 🔗 Check all <a> tags (links) for suspicious keywords
            for link in soup.find_all("a", href=True):
                href = link["href"]
                for keyword in suspicious_keywords:
                    if keyword in href:
                        suspicious_links.append(href)

            # 📜 Check all <script> tags for suspicious keywords
            for script in soup.find_all("script"):
                script_code = str(script)
                for keyword in suspicious_keywords:
                    if keyword in script_code:
                        suspicious_scripts.append(script_code[:50] + "...")  # Save only first 50 chars

            # If any suspicious content was found, mark site as risky
            if suspicious_links or suspicious_scripts:
                status = Fore.RED + "⚠️ Suspicious"

            # Print results to console
            print(f"Title: {title}")
            print(f"Status: {status}{Style.RESET_ALL}")
            print(f"Suspicious Links: {suspicious_links}")
            print(f"Suspicious Scripts: {suspicious_scripts}")

            # Save results into CSV file
            writer.writerow([site, title, status, suspicious_links, suspicious_scripts])

        except Exception as e:
            # If something goes wrong (timeout, invalid URL, etc.), log error
            print(Fore.YELLOW + f"Error scanning {site}: {e}" + Style.RESET_ALL)
            writer.writerow([site, "N/A", "Error", "N/A", "N/A"])

print(f"\n📁 Results saved to {filename}")
