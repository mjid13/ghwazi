"""
PDF parser service for extracting transaction data from PDF bank statements.
"""

import os
import re
import logging
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd
import fitz  # PyMuPDF
from datetime import datetime

from pdfminer.pdfparser import PDFParser

logger = logging.getLogger(__name__)


def get_table_bounds(table_structure: List[Dict[str, Any]]) -> Optional[Tuple[float, float, float, float]]:
    """Return (x1,y1,x2,y2) of the first rectangle, or None."""
    for el in table_structure:
        if el['type'] == 'rectangle':
            return el['x1'], el['y1'], el['x2'], el['y2']
    return None


class PDFTableExtractor:
    """Class for extracting tables from PDF bank statements."""
    
    def __init__(self, pdf_path: str):
        """
        Initialize the PDF table extractor.
        
        Args:
            pdf_path (str): Path to the PDF file.
        """
        self.pdf_path = pdf_path
        self.doc = fitz.open(pdf_path)

    def get_table_structures(self) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """
        Returns the predefined table structures for both tables on page one and other pages
        """
        # Page one table structures
        page_one_table_one = [
            {'type': 'rectangle', 'x1': 60.69945526123047, 'y1': 428.2039489746094, 'x2': 868.6990356445312, 'y2': 496.1959533691406},
            {'type': 'line', 'x1': 212.370361328125, 'y1': 426.8129577636719, 'x2': 212.370361328125, 'y2': 495.5869445800781},
            {'type': 'line', 'x1': 372.9596252441406, 'y1': 426.1130065917969, 'x2': 372.9596252441406, 'y2': 495.8869934082031},
            {'type': 'line', 'x1': 584.129638671875, 'y1': 429.2129821777344, 'x2': 584.129638671875, 'y2': 498.9869689941406},
            {'type': 'line', 'x1': 680.2296142578125, 'y1': 428.5130310058594, 'x2': 680.2296142578125, 'y2': 498.2870178222656},
            {'type': 'line', 'x1': 59.73999786376953, 'y1': 451.2002868652344, 'x2': 871.498046875, 'y2': 455.19964599609375}
        ]

        page_one_table_two = [
            {'type': 'rectangle', 'x1': 58.719913482666016, 'y1': 571.8800048828125, 'x2': 862.719482421875, 'y2': 1460.8800048828125},
            {'type': 'line', 'x1': 146.62001037597656, 'y1': 569.8489990234375, 'x2': 147.61990356445312, 'y2': 1460.6309814453125},
            {'type': 'line', 'x1': 225.010009765625, 'y1': 570.489013671875, 'x2': 226.00990295410156, 'y2': 1461.27099609375},
            {'type': 'line', 'x1': 547.4600219726562, 'y1': 569.0889892578125, 'x2': 548.4599609375, 'y2': 1459.8709716796875},
            {'type': 'line', 'x1': 646.0900268554688, 'y1': 571.3289794921875, 'x2': 647.0899658203125, 'y2': 1462.1109619140625},
            {'type': 'line', 'x1': 761.1599731445312, 'y1': 572.1290283203125, 'x2': 762.159912109375, 'y2': 1462.9110107421875},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 603.1996459960938, 'x2': 863.2449951171875, 'y2': 604.1996459960938},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 646.9996948242188, 'x2': 863.2449951171875, 'y2': 647.9996948242188},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 690.7296752929688, 'x2': 863.2449951171875, 'y2': 691.7296752929688},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 737.0197143554688, 'x2': 864.510009765625, 'y2': 738.0197143554688},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 780.7896728515625, 'x2': 863.2449951171875, 'y2': 781.7896728515625},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 827.3297119140625, 'x2': 863.2449951171875, 'y2': 828.3297119140625},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 872.5897216796875, 'x2': 863.2449951171875, 'y2': 873.5897216796875},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 917.8596801757812, 'x2': 864.510009765625, 'y2': 918.8596801757812},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 964.2597045898438, 'x2': 863.2449951171875, 'y2': 965.2597045898438},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1005.8496704101562, 'x2': 864.510009765625, 'y2': 1006.8496704101562},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1051.23974609375, 'x2': 864.510009765625, 'y2': 1052.2396240234375},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1096.6297607421875, 'x2': 864.510009765625, 'y2': 1097.629638671875},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1139.48974609375, 'x2': 864.510009765625, 'y2': 1140.4896240234375},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1187.5897216796875, 'x2': 864.510009765625, 'y2': 1188.589599609375},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 1231.8997802734375, 'x2': 863.2449951171875, 'y2': 1232.899658203125},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 1319.19970703125, 'x2': 863.2449951171875, 'y2': 1320.1995849609375},
            {'type': 'line', 'x1': 58.4630012512207, 'y1': 1368.559814453125, 'x2': 863.2449951171875, 'y2': 1369.5596923828125},
            {'type': 'line', 'x1': 59.72800064086914, 'y1': 1409.0797119140625, 'x2': 864.510009765625, 'y2': 1410.07958984375}
        ]

        # Other pages table structures
        other_pages_table_one = [
            {'type': 'line', 'x1': 58.715999603271484, 'y1': 222.49957275390625, 'x2': 862.4979858398438, 'y2': 222.49957275390625},
            {'type': 'line', 'x1': 365.1098937988281, 'y1': 175.49002075195312, 'x2': 364.1098937988281, 'y2': 267.3100280761719},
            {'type': 'line', 'x1': 591.4498901367188, 'y1': 176.78994750976562, 'x2': 590.4498901367188, 'y2': 268.6099548339844},
            {'type': 'line', 'x1': 685.0299072265625, 'y1': 176.89004516601562, 'x2': 684.0299072265625, 'y2': 268.7100524902344},
            {'type': 'line', 'x1': 215.89988708496094, 'y1': 175.58999633789062, 'x2': 214.89990234375, 'y2': 267.4100036621094},
            {'type': 'rectangle', 'x1': 58.16999816894531, 'y1': 174.80038452148438, 'x2': 859.1699829101562, 'y2': 264.80023193359375}
        ]

        other_pages_table_two = [
            {'type': 'line', 'x1': 224.25967407226562, 'y1': 377.60699462890625, 'x2': 226.26019287109375, 'y2': 1478.373046875},
            {'type': 'line', 'x1': 553.0197143554688, 'y1': 376.34698486328125, 'x2': 555.0202026367188, 'y2': 1477.113037109375},
            {'type': 'line', 'x1': 651.6497192382812, 'y1': 377.25701904296875, 'x2': 653.6502075195312, 'y2': 1478.0230712890625},
            {'type': 'line', 'x1': 765.459716796875, 'y1': 376.90704345703125, 'x2': 767.460205078125, 'y2': 1477.673095703125},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 445.19952392578125, 'x2': 861.2340087890625, 'y2': 445.19952392578125},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 491.19952392578125, 'x2': 861.2340087890625, 'y2': 491.19952392578125},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 534.6995239257812, 'x2': 859.968994140625, 'y2': 534.6995239257812},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 579.4995727539062, 'x2': 861.2340087890625, 'y2': 579.4995727539062},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 622.9995727539062, 'x2': 861.2340087890625, 'y2': 622.9995727539062},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 672.799560546875, 'x2': 861.2340087890625, 'y2': 672.799560546875},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 715.5995483398438, 'x2': 859.968994140625, 'y2': 715.5995483398438},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 758.3895874023438, 'x2': 859.968994140625, 'y2': 758.3895874023438},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 802.4495849609375, 'x2': 859.968994140625, 'y2': 802.4495849609375},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 1252.7095947265625, 'x2': 861.2340087890625, 'y2': 1252.7095947265625},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 850.28955078125, 'x2': 861.2340087890625, 'y2': 850.28955078125},
            {'type': 'line', 'x1': 54.92300033569336, 'y1': 894.3495483398438, 'x2': 858.7050170898438, 'y2': 894.3495483398438},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 942.1995849609375, 'x2': 859.968994140625, 'y2': 942.1995849609375},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 986.2495727539062, 'x2': 861.2340087890625, 'y2': 986.2495727539062},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 1026.5096435546875, 'x2': 861.2340087890625, 'y2': 1026.5096435546875},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1071.629638671875, 'x2': 859.968994140625, 'y2': 1071.629638671875},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1123.2696533203125, 'x2': 859.968994140625, 'y2': 1123.2696533203125},
            {'type': 'line', 'x1': 57.45199966430664, 'y1': 1167.11962890625, 'x2': 861.2340087890625, 'y2': 1167.11962890625},
            {'type': 'rectangle', 'x1': 57.13800048828125, 'y1': 377.1295471191406, 'x2': 860.1380004882812, 'y2': 1478.129150390625},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1210.11962890625, 'x2': 859.968994140625, 'y2': 1210.11962890625},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1299.089599609375, 'x2': 859.968994140625, 'y2': 1299.089599609375},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1343.1396484375, 'x2': 859.968994140625, 'y2': 1343.1396484375},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1389.7296142578125, 'x2': 859.968994140625, 'y2': 1389.7296142578125},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 1434.0196533203125, 'x2': 859.968994140625, 'y2': 1434.0196533203125},
            {'type': 'line', 'x1': 147.1196746826172, 'y1': 378.36700439453125, 'x2': 149.1201934814453, 'y2': 1479.133056640625},
            {'type': 'line', 'x1': 56.1870002746582, 'y1': 405.69952392578125, 'x2': 859.968994140625, 'y2': 405.69952392578125}
        ]

        return {
            'page_one': {
                'table_one': page_one_table_one,
                'table_two': page_one_table_two
            },
            'other_pages': {
                'table_one': other_pages_table_one,
                'table_two': other_pages_table_two
            }
        }

    def get_column_boundaries(self, table_structure):
        table_bounds = get_table_bounds(table_structure)
        if table_bounds is None:
            return []

        x1, y1, x2, y2 = table_bounds
        verts = set()
        for el in table_structure:
            if el['type'] == 'line' and abs(el['x1'] - el['x2']) < 5 and abs(el['y1'] - el['y2']) > 20:
                x = el['x1']
                if x1 <= x <= x2 and min(el['y1'], el['y2']) <= y2 and max(el['y1'], el['y2']) >= y1:
                    verts.add(x)
        cols = sorted(verts)
        if cols and x1 not in cols:
            cols.insert(0, x1)
        if cols and x2 not in cols:
            cols.append(x2)
        return cols

    def get_row_boundaries(self, table_structure):
        table_bounds = get_table_bounds(table_structure)
        if table_bounds is None:
            return []

        x1, y1, x2, y2 = table_bounds
        hors = set()
        for el in table_structure:
            if el['type'] == 'line' and abs(el['y1'] - el['y2']) < 5 and abs(el['x1'] - el['x2']) > 20:
                y = el['y1']
                if y1 <= y <= y2 and min(el['x1'], el['x2']) <= x2 and max(el['x1'], el['x2']) >= x1:
                    hors.add(y)
        rows = sorted(hors)
        if rows and y1 not in rows:
            rows.insert(0, y1)
        if rows and y2 not in rows:
            rows.append(y2)
        return rows

    def extract_text_from_table_cells(self, page, structure):
        cols = self.get_column_boundaries(structure)
        rows = self.get_row_boundaries(structure)
        if not cols or not rows:
            return []

        data = []
        for i in range(len(rows) - 1):
            y_top, y_bot = rows[i], rows[i + 1]
            row = []
            for j in range(len(cols) - 1):
                x_left, x_right = cols[j], cols[j + 1]
                clip = fitz.Rect(x_left, y_top, x_right, y_bot)
                txt = page.get_text("text", clip=clip).strip()
                row.append(txt)
            data.append(row)
        return data

    def organize_table_data(self, table_data) -> pd.DataFrame:
        if not table_data:
            return pd.DataFrame()

        # Keep only non-empty rows
        nonempty = [r for r in table_data if any(cell for cell in r)]
        if not nonempty:
            return pd.DataFrame()

        maxc = max(len(r) for r in nonempty)

        # Use the first row as header if available
        if len(nonempty) > 1:
            # First row becomes column names
            header_row = nonempty[0]
            # Pad header row to maxc length and clean up column names
            cols = [str(header_row[i]).strip() if i < len(header_row) and header_row[i].strip()
                    else f"Column_{i + 1}" for i in range(maxc)]

            # Remaining rows become data
            data_rows = nonempty[1:]
            rows = [r + [''] * (maxc - len(r)) for r in data_rows]
        else:
            # If only one row, use generic column names
            cols = [f"Column_{i + 1}" for i in range(maxc)]
            rows = [r + [''] * (maxc - len(r)) for r in nonempty]

        return pd.DataFrame(rows, columns=cols)

    def extract_tables_from_pdf(self) -> Dict[str, pd.DataFrame]:
        """
        Extract tables from PDF and return:
        - first_table: DataFrame with first table data (same across all pages, so only one instance)
        - second_table: DataFrame with all second table data from all pages combined
        """
        structs = self.get_table_structures()

        # For first table - we only need it once since it's the same across all pages
        first_table_df = None

        # For second table - collect all data from all pages
        second_table_data = []
        second_table_columns = None

        for page_num in range(len(self.doc)):
            page = self.doc[page_num]

            # Determine which structure to use
            if page_num == 0:
                table_one_struct = structs['page_one']['table_one']
                table_two_struct = structs['page_one']['table_two']
            else:
                table_one_struct = structs['other_pages']['table_one']
                table_two_struct = structs['other_pages']['table_two']

            # Extract first table only once (from first page)
            if first_table_df is None:
                table_one_cells = self.extract_text_from_table_cells(page, table_one_struct)
                first_table_df = self.organize_table_data(table_one_cells)
                logger.info(f"First table extracted from page {page_num + 1}")

            # Extract second table from all pages
            table_two_cells = self.extract_text_from_table_cells(page, table_two_struct)
            table_two_df = self.organize_table_data(table_two_cells)

            if not table_two_df.empty:
                # Add page number for reference
                table_two_df['Page_Number'] = page_num + 1

                # Store column names from first occurrence
                if second_table_columns is None:
                    second_table_columns = table_two_df.columns.tolist()

                # Skip header row for subsequent pages (assuming first row is always header)
                if page_num > 0 and len(table_two_df) > 0:
                    # Skip the first row (header) for pages after the first
                    table_two_df = table_two_df.iloc[1:].reset_index(drop=True)

                second_table_data.append(table_two_df)
                logger.info(f"Second table extracted from page {page_num + 1}")

        # Combine all second table data
        if second_table_data:
            combined_second_table = pd.concat(second_table_data, ignore_index=True)
        else:
            combined_second_table = pd.DataFrame()

        return {
            'first_table': first_table_df if first_table_df is not None else pd.DataFrame(),
            'second_table': combined_second_table
        }

    def save_tables_to_excel(self, output_path: str):
        """Save extracted tables to Excel file with separate sheets"""
        tables = self.extract_tables_from_pdf()

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            if not tables['first_table'].empty:
                tables['first_table'].to_excel(writer, sheet_name='First_Table', index=False)
                logger.info(f"First table saved with {len(tables['first_table'])} rows")

            if not tables['second_table'].empty:
                tables['second_table'].to_excel(writer, sheet_name='Second_Table', index=False)
                logger.info(f"Second table saved with {len(tables['second_table'])} rows")

        logger.info(f"Tables saved to {output_path}")

    def get_dataframes(self) -> Dict[str, pd.DataFrame]:
        """Return the extracted DataFrames directly"""
        return self.extract_tables_from_pdf()

    def close(self):
        """Close the PDF document"""
        self.doc.close()


class PDFParser:
    """Class for parsing transaction data from PDF bank statements."""
    
    def __init__(self):
        """Initialize the PDF parser."""
        self.extractor = None
    
    def parse_pdf(self, pdf_path: str) -> List[Dict[str, Any]]:
        """
        Parse transaction data from a PDF bank statement.
        
        Args:
            pdf_path (str): Path to the PDF file.
            
        Returns:
            List[Dict[str, Any]]: List of transaction data dictionaries.
        """
        try:
            self.extractor = PDFTableExtractor(pdf_path)
            tables = self.extractor.get_dataframes()
            
            # Process account information from first table
            account_info = self._process_account_info(tables['first_table'])
            
            # Process transactions from second table
            transactions = self._process_transactions(tables['second_table'], account_info)
            
            self.extractor.close()
            return transactions
        except Exception as e:
            logger.error(f"Error parsing PDF: {str(e)}")
            if self.extractor:
                self.extractor.close()
            return []
    
    def _process_account_info(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Process account information from the first table.
        
        Args:
            df (pd.DataFrame): DataFrame containing account information.
            
        Returns:
            Dict[str, Any]: Dictionary containing account information.
        """
        account_info = {
            'account_number': '',
            'currency': '',
            'branch': ''
        }
        
        if not df.empty and 'Account Number' in df.columns and 'Currency' in df.columns and 'Branch' in df.columns:
            # Get the first row
            row = df.iloc[0]
            account_info['account_number'] = row['Account Number']
            account_info['currency'] = row['Currency']
            account_info['branch'] = row['Branch']
        
        return account_info
    
    def _process_transactions(self, df: pd.DataFrame, account_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process transactions from the second table.
        
        Args:
            df (pd.DataFrame): DataFrame containing transaction data.
            account_info (Dict[str, Any]): Dictionary containing account information.
            
        Returns:
            List[Dict[str, Any]]: List of transaction data dictionaries.
        """
        transactions = []
        
        if df.empty or 'Post Date' not in df.columns or 'Narration' not in df.columns:
            return transactions
        
        expected_columns = ['Post Date', 'Value Date', 'Narration', 'Debit', 'Credit', 'Balance', 'Page_Number']
        
        # Check if all expected columns exist
        for col in expected_columns:
            if col not in df.columns:
                logger.warning(f"Column {col} not found in transaction table")
                return transactions
        
        # Process each row
        for _, row in df.iterrows():
            # Skip rows with empty narration
            if pd.isna(row['Narration']) or row['Narration'] == '':
                continue
            
            # Parse counterparty name and transaction ID from narration
            parsed_narration = self._parse_narration(row['Narration'])
            
            # Determine transaction type and amount
            transaction_type, amount = self._determine_transaction_type_and_amount(row)

            transaction_sender = parsed_narration["counterparty_name"] if transaction_type == 'EXPENSE' else "me"
            transaction_receiver = parsed_narration["counterparty_name"] if transaction_type == 'INCOME' else "me"
            
            # Skip transactions with no amount
            if amount is None:
                continue

            # Parse dates to datetime objects
            post_date = self._parse_date_string(row['Post Date']) if not pd.isna(row['Post Date']) else None
            value_date = self._parse_date_string(row['Value Date']) if not pd.isna(row['Value Date']) else None

            # Create transaction data dictionary
            transaction_data = {
                'account_number': account_info['account_number'],
                'post_date': post_date,
                'value_date': value_date,
                'transaction_content': row['Narration'],
                'amount': amount,
                'transaction_type': transaction_type,
                'balance': row['Balance'] if not pd.isna(row['Balance']) else None,
                'counterparty_name': parsed_narration["counterparty_name"],
                'transaction_id': parsed_narration["transaction_id"],
                'transaction_details': parsed_narration["details"],
                "transaction_sender": transaction_sender,
                "transaction_receiver": transaction_receiver,
                'source': 'PDF',
                'currency': account_info['currency']
            }
            
            transactions.append(transaction_data)
        
        return transactions

    @staticmethod
    def _parse_narration(narration: str) -> Dict[str, Any]:
        """
        Parse counterparty name and transaction ID from narration.
        
        Args:
            narration (str): Narration text.
            
        Returns:
            Tuple[str, Optional[str]]: Counterparty name and transaction ID.
        """
        text = ' '.join(narration.strip().split())

        # Special handling for Transfer cases
        if text.startswith('Transfer'):
            # Find the first occurrence of consecutive uppercase words (person name)
            # Match everything after "Transfer" until the last word that looks like a transaction ID
            match = re.search(r'Transfer\s+(.*?)(?:\s+([A-Z0-9]{10,}))?\s*$', text)
            if match:
                full_name = match.group(1).strip()
                transaction_id = match.group(2) if match.group(2) else None
                return {
                    'details': text,
                    'counterparty_name': full_name,
                    'transaction_id': transaction_id
                }

        # Pattern to match other transaction formats
        patterns = [
            # POS transactions: POS number-description code
            r'(POS\s+\d+)-([A-Z0-9\s\-]+?)\s+(POS\d+[A-Z0-9]+)$',
            # POS transactions without separate transaction ID: POS number-description
            r'(POS\s+\d+)-([A-Z0-9\s\-.,@]+)$',
            # Generic POS: POS description code
            r'(POS)\s+([A-Z\s]+?)\s+([A-Z0-9]+)$',
            # Wallet transactions: Wallet details name FT/LFT code
            r'(Wallet\s+Trx(?:\s+(?:Cr|Dr))?\s+[A-Z0-9]+)\s+([A-Z][A-Z0-9\s\-]*?)\s+([FL]T\d+)',
            # Easy Deposit: Easy Deposit details name code
            r'(Easy\s+Deposit\s+[A-Z0-9]+\s+\d{2}:\d{2}:\d{2})\s+([A-Z][A-Z\s]+[A-Z])\s+([A-Z0-9]+)$',
            # SALARY: SALARY details description code
            r'(SALARY\s+.*?)\s+(SALARY)\s+([\d.]+)$'
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                groups = match.groups()
                return {
                    'details': groups[0].strip(),
                    'counterparty_name': groups[1].strip(),
                    'transaction_id': groups[2].strip() if len(groups) > 2 else None
                }

        return {'details': text, 'counterparty_name': '', 'transaction_id': None}
    
    def _determine_transaction_type_and_amount(self, row: pd.Series) -> Tuple[str, Optional[float]]:
        """
        Determine transaction type and amount from row data.
        
        Args:
            row (pd.Series): Row data.
            
        Returns:
            Tuple[str, Optional[float]]: Transaction type and amount.
        """
        # Check if Debit or Credit is not null
        if not pd.isna(row['Debit']) and row['Debit'] != '':
            try:
                amount = float(row['Debit'])
                return 'EXPENSE', amount
            except (ValueError, TypeError):
                pass
        
        if not pd.isna(row['Credit']) and row['Credit'] != '':
            try:
                amount = float(row['Credit'])
                return 'INCOME', amount
            except (ValueError, TypeError):
                pass
        
        return 'unknown', None

    def _parse_date_string(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime object.

        Args:
            date_str (str): Date string to parse (e.g., '10/07/2025')

        Returns:
            Optional[datetime]: Parsed datetime or None if parsing fails.
        """
        if not date_str or pd.isna(date_str):
            return None

        try:
            # Try different date formats that might be in the PDF
            date_formats = [
                '%d/%m/%Y',    # DD/MM/YYYY
                '%d/%m/%y',    # DD/MM/YY
                '%Y-%m-%d',    # YYYY-MM-DD
                '%m/%d/%Y',    # MM/DD/YYYY
                '%m/%d/%y',    # MM/DD/YY
            ]

            for fmt in date_formats:
                try:
                    return datetime.strptime(str(date_str).strip(), fmt)
                except ValueError:
                    continue

            # If none of the formats work, try using dateutil parser
            from dateutil import parser
            return parser.parse(str(date_str).strip(), dayfirst=True)

        except Exception as e:
            logger.warning(f"Failed to parse date string '{date_str}': {str(e)}")
            return None
