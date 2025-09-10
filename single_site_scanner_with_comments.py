# A simple single-site scanner to check for suspicious content on a webpage
# This script fetches the webpage, parses its content, and looks for potentially malicious links or
# keywords. It also saves the scan results to a text file.



import requests # Import the requests library to handle HTTP requests
from bs4 import BeautifulSoup # Import BeautifulSoup for HTML parsing

site = input("Enter the website URL: ").strip() # Get the website URL from the user
if not site.startswith("http"): # Ensure the URL starts with http or https
   site = "http://" + site # Default to http if no scheme is provided

response = requests.get(site, timeout=10) # Send a GET request to the website with a timeout of 10 seconds
soup = BeautifulSoup(response.text, 'html.parser') # Parse the HTML content of the page

print("Title of the webpage:", soup.title.string) # Print the title of the webpage

suspicious_keywords = ["javascript", "eval", "document.cookie", "innerHTML", "onerror", "onload", "<script>", "<iframe>", "base64"] # Define keywords that may indicate suspicious content
suspicious_links = [] # List to store suspicious links
for link in soup.find_all('a', href=True): # Find all anchor tags with href attributes
    href = link['href'] # Get the href attribute
    if any(keyword in href for keyword in suspicious_keywords): # Check if any suspicious keyword is in the href
        suspicious_links.append(href)   # Add the suspicious link to the list

print("Suspicious links found on the page:") # Print the suspicious links found
for suspicious_link in suspicious_links: # Iterate over the suspicious links
    print(suspicious_link) # Print each suspicious link


status = "SAFE SITE" # Default status of the site
if any(keyword in response.text for keyword in suspicious_keywords): # Check if any suspicious keyword is in the page content
    status = "POTENTIALLY MALICIOUS SITE" # Update status if suspicious content is found
print("Site status:", status) # Print the status of the site

try: # Handle potential request exceptions
    response.raise_for_status() # Raise an error for bad responses
except requests.exceptions.RequestException as e: # Catch any request-related exceptions
    print(f"Error scanning {site}: {e}") # Print the error message

with open("scan_results.txt", "w") as f: # Open a file to write the scan results
    f.write(f"Site: {site}\n") # Write the site URL to the file
    f.write(f"Title: {soup.title.string}\n") # Write the title of the webpage to the file
    f.write(f"Status: {status}\n") # Write the status of the site to the file
    f.write("Suspicious links:\n") # Write the header for suspicious links
    for suspicious_link in suspicious_links: # Iterate over the suspicious links
        f.write(f"{suspicious_link}\n") # Write each suspicious link to the file
    f.write("\n") # Add a newline for better readability
print("Scan results saved to scan_results.txt") # Notify the user that the results have been saved

print("Scan complete.") # Indicate that the scan is complete 

# End of the script
