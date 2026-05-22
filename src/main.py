#!/usr/bin/env python3

import re
import json

email_address_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@(?:alueducation\.com|alumni\.alueducation\.com|si\.alueducation\.com)\b')
url_pattern = re.compile(r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b')
phone_no_pattern = re.compile(r'(?:\+\d{1,3}[- ]?)?(?:\(?\d{2,4}\)?[- ]?)?\d{3}[- ]?\d{3,4}')
credit_card_pattern = re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b')

def hidden_credit_card_numbers(credit_cards):
    hidden_cards = []
    digits = re.sub(r'\D', '', credit_cards)
    if len(digits) == 16:
        hidden_card = '**** **** **** ' + digits[-4:]
        hidden_cards.append(hidden_card)
    return hidden_cards[0] if hidden_cards else ""


def extract_sensitive_info(text):
    emails = list(set(email_address_pattern.findall(text)))
    urls = list(set(url_pattern.findall(text)))
    phone_numbers = list(set(phone_no_pattern.findall(text)))
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
