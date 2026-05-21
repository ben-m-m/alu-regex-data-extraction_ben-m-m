#!/usr/bin/env python3

import re
import json

email_address = re.compile(r'\b[a-zA-Z0-9._%+-]+@(?:alueducation\.com|alumni\.alueducation\.com|si\.alueducation\.com)\b')
url_pattern = re.compile(r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b')
phone_no_pattern = re.compile(r'(?:\+\d{1,3}[- ]?)?(?:\(?\d{2,4}\)?[- ]?)?\d{3}[- ]?\d{3,4}')
credit_card_pattern = re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')

def extract_sensitive_info(text):
    emails = email_address.findall(text)
    urls = url_pattern.findall(text)
    phone_numbers = phone_no_pattern.findall(text)
    credit_cards = credit_card_pattern.findall(text)

    return {
        'emails': emails,
        'urls': urls,
        'phone_numbers': phone_numbers,
        'credit_cards': credit_cards
    }

if __name__ == "__main__":
    with open('../input/raw-text.txt', 'r') as file:
        text = file.read()

    sensitive_info = extract_sensitive_info(text)

    with open('../output/sample-output.json', 'w') as json_file:
        json.dump(sensitive_info, json_file, indent=4)
