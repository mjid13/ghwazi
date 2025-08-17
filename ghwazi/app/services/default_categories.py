import re
import unicodedata
from typing import Dict, List, Optional, Tuple

# Default categories and patterns for smart suggestions. Only used on-demand.
# Notes:
# - Patterns are kept in lowercase; matching uses normalized, case-insensitive comparison
# - Counterparty patterns are preferred over description patterns
# - We do NOT seed these into the DB up-front; we only create user categories/mappings when matched

CATEGORIES: List[Dict] = [
    {
        "name": "Transportation",
        "description": "Fuel, taxis, public transport, parking, tolls, vehicle upkeep (non-repair).",
        "patterns": {
            "counterparty": [
                # Fuel brands & stations
                "oomco", "oman oil marketing", "oq station", "oq", "shell oman", "shell station",
                "al maha", "almaha", "maha petroleum",
                # Taxis & ride-hailing & buses
                "otaxi", "o taxi", "oman taxi", "mwasalat", "mwasalat taxi", "mwasalat bus", "tasleem",
                # Generic
                "petrol", "gas station", "fuel station",
            ],
            "description": [
                "fuel", "petrol", "diesel", "gasoline", "parking", "toll", "transport", "bus", "taxi", "ride"
            ],
        },
    },
    {
        "name": "Groceries",
        "description": "Supermarkets and grocery delivery.",
        "patterns": {
            "counterparty": [
                "lulu", "lulu hypermarket", "luluhypermarket", "carrefour", "hypermax", "spar oman", "spar", "mart", "HYPERMARKET"
                "al fair", "alfair", "nesto", "km trading", "k.m. trading", "ramez", "talabat mart", "talabat market",
            ],
            "description": ["groceries", "supermarket", "food shopping", "household"],
        },
    },
    {
        "name": "Dining & Delivery",
        "description": "Quick service restaurants and food delivery apps.",
        "patterns": {
            "counterparty": [
                # Delivery platforms in Oman
                "talabat", "akeed",
                # Common chains present in Oman
                "mcdonald", "kfc", "burger king", "subway", "pizza hut", "domino", "hardees", "papa john",
                "shaway", "shawarma", "doner", "karak", "café", "cafe", "starbucks", "costa", "gloria jean",
                "dunkin", "55 cafe", "restaurant", "rest.", "coffee", "kuku", "burger", "pizza", "FOOD"
            ],
            "description": ["fast food", "delivery", "takeaway", "pizza", "dining", "burger", "snack"],
        },
    },
    {
        "name": "Bills & Utilities",
        "description": "Electricity, water, telecom, and bill aggregators.",
        "patterns": {
            "counterparty": [
                # Electricity & water
                "nama services", "nama electricity", "nama distribution", "nama supply",
                "nama water services", "owwsc", "diam",
                # Bill pay aggregators
                "oifc", "khedmah", "oneic", "bill & pay", "Oman Investment and fin"
                # Telecoms (postpaid/prepaid bills)
                "omantel", "ooredoo oman", "ooredoo", "vodafone oman", "renna", "friendi",
            ],
            "description": [
                "electricity", "water", "sewage", "internet", "fiber", "broadband", "postpaid", "prepaid",
                "bill", "recharge", "topup", "top-up",
            ],
        },
    },
    {
        "name": "Phone transfer",
        "description": "Transfers between phone numbers, typically for mobile top-ups or P2P payments.",
        "patterns": {
            "counterparty": [
                # Electricity & water
                "mobile payment",
            ],
            "description": [
                "mobile Payment", "mobile"
            ],
        },
    },
    {
        "name": "Healthcare",
        "description": "Hospitals, clinics, pharmacies, insurance copays.",
        "patterns": {
            "counterparty": [
                "badr al samaa", "badr alsamaa", "starcare", "aster al raffah", "kims", "muscat private hospital",
                "nmc", "sultan qaboos university hospital", "sqm hospital",
                "life pharmacy", "lifepharmacy", "muscat pharmacy", "aster pharmacy", "bin sina",
            ],
            "description": ["clinic", "hospital", "pharmacy", "doctor", "dentist", "medical", "medicine"],
        },
    },
    {
        "name": "Entertainment",
        "description": "Cinemas, restaurants, cafés, leisure.",
        "patterns": {
            "counterparty": [
                "vox cinemas", "vox", "cinepolis", "wow cinemas", "tea"
            ],
            "description": ["cinema", "movie", "tickets", "leisure", "entertainment"],
        },
    },
    {
        "name": "Shopping & Electronics",
        "description": "Retail, fashion, electronics, general shopping.",
        "patterns": {
            "counterparty": [
                "mall of oman", "oman avenues mall", "city centre muscat",
                "sharaf dg", "jumbo electronics", "emax", "extra", "noon", "amazon", "namshi", "max fashion", "centrepoint",
                "khimji", "khimji's", "al fair dept", "decathlon", "GADGETS"
            ],
            "description": [
                "shopping", "retail", "clothing", "apparel", "electronics", "online shopping", "fashion", "accessories",
            ],
        },
    },
    {
        "name": "Education",
        "description": "Schools, universities, training centers, books.",
        "patterns": {
            "counterparty": [
                "sultan qaboos university", "squ", "utas", "gutech", "modern college of business and science",
                "aba oman", "a'soud global school", "indian school muscat",
                "skill training", "language institute", "bookstore", "coursera", "udeamy",
            ],
            "description": ["school fee", "tuition", "course", "training", "books", "exam", "subscription"],
        },
    },
    {
        "name": "Insurance",
        "description": "General, health, motor, and takaful premiums.",
        "patterns": {
            "counterparty": [
                "nlgic", "national life & general", "dhofar insurance", "oqic", "oman qatar insurance", "bima",
                "al ahlia insurance", "gig gulf", "takaful oman", "al madina takaful", "oman united insurance",
            ],
            "description": ["insurance", "premium", "policy", "takaful", "coverage", "renewal"],
        },
    },
    {
        "name": "Government & Fines",
        "description": "Government fees, traffic fines, visas.",
        "patterns": {
            "counterparty": [
                "royal oman police", "rop", "ministry", "moh", "mohe", "municipality", "evisa", "mwasalat fine",
            ],
            "description": ["fine", "traffic", "visa", "renewal", "residency", "license fee", "mulkiya"],
        },
    },
    {
        "name": "Charity & Zakat",
        "description": "Donations, zakat, waqf.",
        "patterns": {
            "counterparty": [
                "social protection fund", "spf", "oman charitable organization", "taawon", "donation", "zakat", "waqf",
            ],
            "description": ["charity", "donation", "zakat", "waqf", "sadaqah"],
        },
    },
    {
        "name": "Remittances & Exchange",
        "description": "International transfers and currency exchange.",
        "patterns": {
            "counterparty": [
                "lulu exchange", "lulu money", "unimoni", "uae exchange", "western union", "moneygram", "oman united exchange",
            ],
            "description": ["remittance", "money transfer", "exchange", "fx", "forex"],
        },
    },
    {
        "name": "Subscriptions & Digital",
        "description": "Streaming, SaaS, app stores, cloud.",
        "patterns": {
            "counterparty": [
                "netflix", "shahid", "starzplay", "tod", "spotify", "apple", "app store", "google", "play store",
                "microsoft", "office 365", "github", "openai", "adobe", "dropbox",
            ],
            "description": ["subscription", "monthly", "yearly", "auto-renew", "cloud", "saas"],
        },
    },
    # --------- INCOME CATEGORIES ----------
    {
        "name": "Salary",
        "type": "income",
        "description": "Payroll/WPS salary deposits from employers.",
        "patterns": {
            "counterparty": ["company", "employer", "hr payroll"],
            "description": ["salary", "wps salary", "allowance"],
        },
    },
    {
        "name": "Business Income",
        "type": "income",
        "description": "POS settlements and transfers from customers.",
        "patterns": {
            "counterparty": ["omannet settlement", "pos settlement", "invoice payment", "customer transfer"],
            "description": ["settlement", "sale revenue", "invoice paid", "transfer in"],
        },
    },
    {
        "name": "Freelance/Contract Income",
        "type": "income",
        "description": "Project-based payments (local or international).",
        "patterns": {
            "counterparty": ["upwork", "freelancer", "fiverr", "client transfer", "wise", "payoneer"],
            "description": ["freelance", "contract", "project payment", "service fee", "consulting"],
        },
    },
    {
        "name": "Investment Income",
        "type": "income",
        "description": "Dividends, interest, returns.",
        "patterns": {
            "counterparty": ["muscat stock exchange", "mse", "brokerage", "bank interest"],
            "description": ["dividend", "interest", "profit distribution", "coupon", "return"],
        },
    },
]


def normalize_text(text: Optional[str]) -> str:
    """Lowercase, strip, and fold accents for robust matching."""
    if not text:
        return ""
    # Normalize unicode accents
    text = unicodedata.normalize("NFKD", text)
    text = "".join([c for c in text if not unicodedata.combining(c)])
    # Lowercase
    text = text.casefold()
    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _compile_boundary_regex(pattern: str) -> re.Pattern:
    """Compile a case-insensitive regex for the pattern with word boundaries at both ends."""
    escaped = re.escape(normalize_text(pattern))
    # Use custom boundaries to avoid matching inside longer words
    return re.compile(rf"(?<!\w){escaped}(?!\w)", re.IGNORECASE)


def find_first_match(text: str, patterns: List[str]) -> Optional[Tuple[str, str]]:
    """
    Find the first matching pattern in text, preferring longer patterns first.
    Returns a tuple of (canonical_pattern, matched_substring_from_text).
    """
    if not text or not patterns:
        return None
    ntext = normalize_text(text)
    # Sort patterns by length desc to match the most specific first
    for pat in sorted(patterns, key=lambda p: len(p), reverse=True):
        regex = _compile_boundary_regex(pat)
        m = regex.search(ntext)
        if m:
            # Extract original substring from original text by mapping indices
            # This is approximate due to normalization, so fallback to pattern itself if indices mismatch
            # We will try to find a case-insensitive occurrence in the original text
            orig_regex = re.compile(re.escape(pat), re.IGNORECASE)
            m2 = orig_regex.search(text)
            matched_substring = m2.group(0) if m2 else pat
            return pat, matched_substring
    return None


def suggest_category(counterparty: Optional[str], description: Optional[str]) -> Optional[Dict]:
    """
    Suggest a category based on default patterns.
    Tries counterparty patterns first, then description patterns.
    Returns a dict with keys: name, description, mapping_type ('COUNTERPARTY' or 'DESCRIPTION'), matched_pattern, matched_substring
    or None if no suggestion.
    """
    # Try counterparty first
    if counterparty:
        for cat in CATEGORIES:
            patterns = cat.get("patterns", {}).get("counterparty", [])
            match = find_first_match(counterparty, patterns)
            if match:
                pat, matched_sub = match
                return {
                    "name": cat["name"],
                    "description": cat.get("description"),
                    "mapping_type": "COUNTERPARTY",
                    "matched_pattern": pat,
                    "matched_substring": matched_sub,
                }
    # Then description
    if description:
        for cat in CATEGORIES:
            patterns = cat.get("patterns", {}).get("description", [])
            match = find_first_match(description, patterns)
            if match:
                pat, matched_sub = match
                return {
                    "name": cat["name"],
                    "description": cat.get("description"),
                    "mapping_type": "DESCRIPTION",
                    "matched_pattern": pat,
                    "matched_substring": matched_sub,
                }
    return None
