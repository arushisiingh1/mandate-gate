"""The closed set of purchase categories.

A closed set matters for security: a category is matched by exact string
equality against a mandate's allowlist, so there is no normalisation step that
a look-alike string ("Books", "books​", Cyrillic "ѵ") could slip through.
"""

CATEGORIES = (
    "groceries",
    "books",
    "software",
    "home",
    "clothing",
    "electronics",
    "travel",
    "gift_cards",
    "crypto",
)

CATEGORY_IDS = {name: i for i, name in enumerate(CATEGORIES)}
