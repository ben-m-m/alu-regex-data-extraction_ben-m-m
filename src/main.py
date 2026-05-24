#!/usr/bin/env python3

"""
ALU Regex Data Extraction Assignment

This program extracts and validates sensitive structured data
from raw API-style text input using regular expressions.

Extracted data types:
- ALU email addresses
- URLs
- Phone numbers
- Credit card numbers

Security considerations:
- External input is treated as untrusted
- Suspicious patterns are filtered
- Credit card numbers are masked before output
- Invalid or malicious content is ignored
"""

import re
import json

# Regular expressions for matching email addresses, URLs, phone numbers, and credit card numbers
email_address_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@(?:alueducation\.com|alumni\.alueducation\.com|si\.alueducation\.com)\b')
url_pattern = re.compile(r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b')
phone_no_pattern = re.compile(r'(?:\+\d{1,3}[- ]?)?(?:\(?\d{2,4}\)?[- ]?)?\d{3}[- ]?\d{3,4}[- ]?\d{3,4}')
credit_card_pattern = re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')

# Function to mask credit card numbers, showing only the last 4 digits
def hidden_credit_card_numbers(credit_cards):
    """
    Masks credit card numbers to avoid exposing sensitive data.

    Example:
    4532 1234 5678 9012
    becomes:
    **** **** **** 9012
    """

    digits = re.sub(r'\D', '', credit_cards)
    if len(digits) == 16:
        return '**** **** **** ' + digits[-4:]
    return ""

# Functions to clean URLs
def clean_url(urls):
    """
    Removes suspicious or potentially malicious URLs.

    Filters patterns associated with:
    - SQL injection
    - JavaScript injection
    - Script tags
    """
    avoid_texts = ["drop_table", "javascript", "<script>", "select * from", "insert into", "delete from", "update", "alter table"]
    valid_urls = []
    for url in urls:
        lower_url = url.lower()
        if not any (avoid_text.lower() in lower_url for avoid_text in avoid_texts):
            valid_urls.append(url)
    return valid_urls

#
def clean_emails(emails):
    """Removes suspicious or potentially malicious email addresses."""
    avoid_texts = ["drop_table", "javascript", "<script>", "select * from", "insert into", "delete from", "update", "alter table"]
    valid_emails = []
    for email in emails:
        lower_email = email.lower()
        if not any (avoid_text.lower() in lower_email for avoid_text in avoid_texts):
            valid_emails.append(email)
    return valid_emails

def clean_phone_numbers(phone_numbers):
    """Validates extracted phone numbers based on digit length and format."""
    valid_phone_numbers = []
    for number in phone_numbers:
        digits = re.sub(r'\D', '', number)
        if 10 <= len(digits) <= 15:
            valid_phone_numbers.append(number)
    return valid_phone_numbers

def extract_sensitive_info(text):
    """Extracts sensitive information from the input text using regular expressions.
    Returns a dictionary containing lists of emails, URLs, phone numbers, and masked credit card numbers"""
    emails = list(set(clean_emails(email_address_pattern.findall(text))))
    urls = list(set(clean_url(url_pattern.findall(text))))
    phone_numbers = list(set(clean_phone_numbers(phone_no_pattern.findall(text))))
    credit_cards_lst = list(set(credit_card_pattern.findall(text)))

    return {
        'emails': emails,
        'urls': urls,
        'phone_numbers': phone_numbers,
        'credit_cards': [hidden_credit_card_numbers(card) for card in credit_cards_lst]
    }

if __name__ == "__main__":
    with open('../input/raw-text.txt', 'r') as file:
        text = file.read()

    sensitive_info = extract_sensitive_info(text)

    with open('../output/sample-output.json', 'w') as json_file:
        json.dump(sensitive_info, json_file, indent=4)
    
    print("Sensitive information extracted and saved to sample-output.json")
