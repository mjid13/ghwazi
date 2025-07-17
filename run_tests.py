import re

import pandas as pd
import pdfplumber
import tabula
from pathlib import Path
import os


def is_transaction_line(line):
    # Match lines that start with two dates (dd/mm/yyyy)
    return re.match(r"\d{2}/\d{2}/\d{4} +\d{2}/\d{2}/\d{4}", line)

def parse_transaction_line(line):
    # Attempt to extract using regex
    match = re.match(
        r"(\d{2}/\d{2}/\d{4}) +(\d{2}/\d{2}/\d{4}) +(.+?) +([\d,]+\.\d{3}|\d+\.\d{3}|\d+\.\d+|) *([\d,]+\.\d{3}|\d+\.\d{3}|\d+\.\d+|) +([\d,]+\.\d{3}|\d+\.\d{3}|\d+\.\d+)",
        line)
    if match:
        return {
            "post_date": match.group(1),
            "value_date": match.group(2),
            "narration": match.group(3).strip(),
            "debit": match.group(4),
            "credit": match.group(5),
            "balance": match.group(6),
        }
    return None
import re
import re

def _get_transaction_id(narration: str) -> str:
    # POS Transaction ID: usually the last POSXXXX string
    pos_match = re.findall(r"POS\d+[A-Z0-9]*", narration)
    if pos_match:
        return pos_match[-1]  # Return the last POS match

    # Wallet Trx: FTxxxxxxx code
    ft_match = re.search(r"FT\d{10,}", narration)
    if ft_match:
        return ft_match.group()

    # Easy Deposit: CDMxxxx code
    cdm_match = re.search(r"CDM\d+[A-Z0-9]*", narration)
    if cdm_match:
        return cdm_match.group()

    # Salary or Transfers: fallback to last numeric string (long enough)
    generic_match = re.findall(r"\d{12,}", narration)
    if generic_match:
        return generic_match[-1]

    # Last line fallback (e.g. LF, if nothing else works)
    lines = narration.strip().split("\n")
    if lines:
        last = lines[-1].strip()
        if len(last) < 20:
            return last

    return ""  # Nothing found

def _get_name(narration: str) -> str:
    narration = narration.strip()

    # POS transactions
    if narration.startswith("POS"):
        # POS transactions
        if narration.startswith("POS"):
            # Match pattern: POS <digits>-<name>
            parts = narration.split("\n")
            if len(parts) >= 1 and "-" in parts[0]:
                name = parts[0].split("-", 1)[1].strip()
                # Remove any POS codes from the name
                pos_code_match = re.search(r'POS\d+[A-Z0-9]*', name)
                if pos_code_match:
                    name = name[:pos_code_match.start()].strip()
                return name

    # Wallet Trx
    if narration.startswith("Wallet Trx"):
        parts = narration.split()
        try:
            # Look for any proper names between transaction code and trailing FT code
            name_parts = []
            for word in parts[2:]:
                if word.startswith("FT"):
                    break
                name_parts.append(word)
            return " ".join(name_parts).strip()
        except:
            return ""

    # Easy Deposit
    if narration.startswith("Easy Deposit"):
        lines = narration.split("\n")
        if len(lines) >= 2:
            return lines[1].split()[0].strip()

    # SALARY
    if narration.startswith("SALARY"):
        lines = narration.split("\n")
        for line in lines:
            if "salary" not in line.lower():
                return line.strip()

    # Transfer
    if narration.startswith("Transfer"):
        lines = narration.split("\n")
        if len(lines) >= 2:
            return " ".join(lines[0].replace("Transfer", "").strip().split() + lines[1].strip().split())

    # Fallback — return original narration
    return narration

import pdfplumber
import re
import csv

def is_transaction_line(line):
    return re.match(r"\d{2}/\d{2}/\d{4} +\d{2}/\d{2}/\d{4}", line)

def parse_transaction_line(line):
    match = re.match(
        r"(\d{2}/\d{2}/\d{4}) +(\d{2}/\d{2}/\d{4}) +(.+?) +([\d,]+\.\d{3}|\d+\.\d+|) *([\d,]+\.\d{3}|\d+\.\d+|) +([\d,]+\.\d{3}|\d+\.\d+)",
        line)
    if match:
        return {
            "post_date": match.group(1),
            "value_date": match.group(2),
            "narration": match.group(3).strip(),
            "debit": match.group(4),
            "credit": match.group(5),
            "balance": match.group(6),
        }
    return None

def extract_account_metadata(text):
    account_number = currency = branch = ""
    match = re.search(r"(\d{16})\s+\d+\.\d+\s+([A-Z]+)\s+([A-Z0-9\-]+.*?)\n", text)
    if match:
        account_number = match.group(1)
        currency = match.group(2)
        branch = match.group(3).strip()
    return account_number, currency, branch

# Final collection of all records
all_records = []



def parse_data(pdf_file):
    transactions = []

    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            acc_num, currency, branch = extract_account_metadata(text)

            lines = text.split("\n")

            for line in lines:
                data = {
                    "account_number": acc_num,
                    "branch": branch,
                    "transaction_type": None,
                    "amount": None,
                    "date": None,
                    "transaction_details": None,
                    "counterparty_name": None,
                    "transaction_id": None,
                    "description": None,
                    "type": None,
                    "from": None,
                    "to": None,
                    "currency": currency,
                }
                if is_transaction_line(line):
                    parsed = parse_transaction_line(line)
                    if parsed:
                        data["post_date"] = parsed["post_date"]
                        data["value_date"] = parsed["value_date"]
                        data["counterparty_name"] = _get_name(parsed["narration"])
                        data["transaction_id"] = _get_transaction_id(parsed["narration"])
                        data["transaction_type"] = "Debit" if parsed["debit"] else "Credit"
                        data["amount"] = parsed["debit"] if parsed["debit"] else parsed["credit"]
                        data["description"] = parsed["narration"]
                        if data['transaction_type'] == "Debit":
                            data["type"] = "debit"
                            data["from"] = data["counterparty_name"]
                            data["to"] = "me"
                        else:
                            data["type"] = "credit"
                            data["from"] = "me"
                            data["to"] = data["counterparty_name"]

                        transactions.append(data)
    return transactions


# Example usage
if __name__ == "__main__":
    # Example 1: Basic extraction
    pdf_file = "bmcT.pdf"  # Replace with your PDF file path

    # Extract all tables
    # tables = extract_tables_from_pdf(pdf_file)

    # Example 2: Extract from specific pages
    # tables = extract_tables_advanced(pdf_file, specific_pages=[1, 3, 5])

    # Example 3: Extract from specific area (coordinates in points)
    # tables = extract_tables_advanced(pdf_file, area=[100, 50, 400, 300])

    # Example 4: Alternative method using pdfplumber
    tables = parse_data(pdf_file)
    for table in tables:
        print(table)
    # print(tables)
    # print(f"Total tables extracted: {len(tables)}")