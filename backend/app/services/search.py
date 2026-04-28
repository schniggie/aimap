"""Shodan-style search query parser for AIMap.

Parses structured search strings into MongoDB filter dicts.

Supported syntax:
  protocol:mcp          -> {"protocol": "mcp"}
  auth:none             -> {"auth_status": "none"}
  risk:critical         -> risk_score >= 9.0
  risk:high             -> risk_score 7.0-8.9
  risk:medium           -> risk_score 4.0-6.9
  risk:low              -> risk_score 1.0-3.9
  risk:info             -> risk_score < 1.0
  tool:query_db         -> {"tools.name": "query_db"}
  country:US            -> {"geo.country_code": "US"}
  port:8080             -> {"port": 8080}
  org:"Amazon AWS"      -> {"geo.org": "Amazon AWS"}
  has:system_prompt     -> {"system_prompt_extracted": true}
  Free text             -> $text search
"""

import re
from typing import Any


# Risk level to score ranges
RISK_RANGES: dict[str, dict[str, Any]] = {
    "critical": {"$gte": 9.0},
    "high": {"$gte": 7.0, "$lt": 9.0},
    "medium": {"$gte": 4.0, "$lt": 7.0},
    "low": {"$gte": 1.0, "$lt": 4.0},
    "info": {"$lt": 1.0},
}

# Pattern to match key:value or key:"quoted value"
TOKEN_RE = re.compile(
    r'(\w+):"([^"]+)"|(\w+):(\S+)'
)


def parse_search_query(query: str) -> dict[str, Any]:
    """Parse a Shodan-style search query into a MongoDB filter dict.

    Args:
        query: Raw query string like 'protocol:mcp auth:none tool:query_db free text'

    Returns:
        MongoDB filter dict suitable for collection.find()
    """
    if not query or not query.strip():
        return {}

    filters: list[dict[str, Any]] = []
    remaining = query

    # Extract all structured key:value tokens
    for match in TOKEN_RE.finditer(query):
        if match.group(1):
            key = match.group(1)
            value = match.group(2)
        else:
            key = match.group(3)
            value = match.group(4)

        # Remove matched token from remaining text
        remaining = remaining.replace(match.group(0), "", 1)

        filt = _key_value_to_filter(key, value)
        if filt:
            filters.append(filt)

    # Remaining text (after removing structured tokens) goes to $text search
    free_text = remaining.strip()
    if free_text:
        filters.append({"$text": {"$search": free_text}})

    if not filters:
        return {}
    if len(filters) == 1:
        return filters[0]
    return {"$and": filters}


def _key_value_to_filter(key: str, value: str) -> dict[str, Any] | None:
    """Convert a single key:value pair to a MongoDB filter."""
    key = key.lower()

    if key == "protocol":
        return {"protocol": value.lower()}

    if key == "auth":
        return {"auth_status": value.lower()}

    if key == "risk":
        risk_range = RISK_RANGES.get(value.lower())
        if risk_range:
            return {"risk_score": risk_range}
        # Try numeric
        try:
            score = float(value)
            return {"risk_score": {"$gte": score}}
        except ValueError:
            return None

    if key == "tool":
        return {"tools.name": value}

    if key == "country":
        return {"geo.country_code": value.upper()}

    if key == "port":
        try:
            return {"port": int(value)}
        except ValueError:
            return None

    if key == "org":
        return {"geo.org": value}

    if key == "has":
        if value.lower() == "system_prompt":
            return {"system_prompt_extracted": True}
        return None

    # Unknown key — ignore
    return None
