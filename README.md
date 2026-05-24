# ALU Regex Data Extraction & Secure Validation

## Overview

This project is a regex-based data extraction tool built in Python.  
It processes raw, untrusted text (similar to API responses or system logs) and extracts structured information while applying validation and basic security filtering.

The goal is to demonstrate:
- Accurate regex extraction
- Data validation and sanitization
- Awareness of unsafe or malicious input
- Structured JSON output generation

---

## Extracted Data Types

The program extracts the following four required data types:

1. Email addresses (ALU domains only)
2. URLs (HTTP/HTTPS links)
3. Phone numbers (international and local formats)
4. Credit card numbers (masked for security)

---

## Project Structure

alu-regex-data-extraction/
├── input/
│   └── raw-text.txt
├── src/
│   └── main.py
├── output/
│   └── sample-output.json
└── README.md


---

## How It Works

### 1. Input Processing
The program reads raw text from:
input/raw-text.txt


This text simulates real-world unstructured data such as:
- API responses
- logs
- user-generated content

---

### 2. Regex Extraction
Regular expressions are used to extract:

- Emails restricted to ALU domains
- URLs starting with http/https
- Phone numbers in multiple formats
- Credit card numbers (16-digit format)

---

### 3. Data Validation & Security Filtering

To ensure safe processing of untrusted input:

- Suspicious patterns (e.g., SQL injection, script tags) are filtered
- Invalid or malformed data is ignored
- Credit card numbers are masked before output
- Duplicate values are removed

Example security checks:
- `javascript:` URLs are rejected
- `<script>` tags are ignored
- SQL keywords like `SELECT`, `DROP`, `INSERT` are filtered

---

### 4. Output

The extracted data is saved in structured JSON format:

Example structure:

```json
{
  "emails": [],
  "urls": [],
  "phone_numbers": [],
  "credit_cards": []
}
```

### 5. How to Run
From the project root:
python3 src/main.py
and press enter. 

## Notes

- All input is treated as untrusted data
- Regex patterns are designed for realistic messy input
- Output is sanitized before being saved

