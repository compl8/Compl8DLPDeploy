import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

def make_row(width, **cells):
    """Build a 0-indexed sheet row of `width` cells, setting named columns."""
    import catalog_refresh as cr
    r = [""] * width
    mapping = {"name": cr.COL_NAME, "slug": cr.COL_SLUG, "source": cr.COL_SOURCE,
               "category": cr.COL_CATEGORY, "jurisdictions": cr.COL_JURISDICTIONS,
               "risk_rating": cr.COL_RISK_RATING, "version": cr.COL_VERSION,
               "created": cr.COL_CREATED, "updated": cr.COL_UPDATED}
    for k, v in cells.items():
        r[mapping[k]] = v
    return r
