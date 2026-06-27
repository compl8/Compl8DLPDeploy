import pytest
import catalog_refresh as cr
from conftest import make_row

def test_is_microsoft():
    assert cr.is_microsoft({"source": "microsoft"})
    assert cr.is_microsoft({"source": "Microsoft"})
    assert not cr.is_microsoft({"source": "qld-custom"})
    assert not cr.is_microsoft({"source": None})

def test_derive_source():
    assert cr.derive_source("qld-custom") == "QLD-Custom"
    assert cr.derive_source(None) == "TestPattern"
    assert cr.derive_source("testpattern-community") == "TestPattern"

def test_index_catalog_drops_microsoft_and_slugless():
    pats = [{"slug": "a", "source": None},
            {"slug": "b", "source": "microsoft"},
            {"source": "x"}]
    assert set(cr.index_catalog(pats)) == {"a"}

def test_index_sheet_rows_only_testpattern_and_qld():
    rows = [make_row(cr.SHEET_WIDTH, name="A", slug="a", source="TestPattern"),
            make_row(cr.SHEET_WIDTH, name="B", slug="b", source="QLD-Custom"),
            make_row(cr.SHEET_WIDTH, name="C", slug="uuid-c", source="Microsoft Built-in")]
    assert set(cr.index_sheet_rows(rows)) == {"a", "b"}

def test_reconcile_partitions():
    cat = {"a": {}, "c": {}}
    sheet = {"a": make_row(cr.SHEET_WIDTH), "b": make_row(cr.SHEET_WIDTH)}
    added, removed, common = cr.reconcile(cat, sheet)
    assert (added, removed, common) == (["c"], ["b"], ["a"])

def test_assert_catalog_sane():
    with pytest.raises(ValueError):
        cr.assert_catalog_sane([{}] * 10)
    cr.assert_catalog_sane([{}] * 600)  # no raise

def test_join():
    assert cr._join(["a", "b"]) == "a; b"
    assert cr._join(["a", None, ""]) == "a"
    assert cr._join("x") == "x"
    assert cr._join(None) == ""

def test_row_from_catalog_maps_fields():
    p = {"slug": "global-aws-key", "name": "AWS Key",
         "data_categories": ["credentials", "secrets"], "risk_description": "leak",
         "risk_rating": 9, "references": ["https://x"], "source": None,
         "jurisdictions": ["global"], "scope": "wide", "confidence": "high",
         "regulations": ["ISO 27001"], "created": "2026-01-01", "updated": "2026-02-01",
         "version": "1.2.0"}
    r = cr.row_from_catalog(p)
    assert len(r) == cr.SHEET_WIDTH
    assert r[cr.COL_NAME] == "AWS Key"
    assert r[cr.COL_SLUG] == "global-aws-key"
    assert r[cr.COL_CATEGORY] == "credentials; secrets"
    assert r[cr.COL_RISK_RATING] == 9
    assert r[cr.COL_REF_URL] == "https://x"
    assert r[cr.COL_CLASSIFIER_TYPE] == "SIT"
    assert r[cr.COL_SOURCE] == "TestPattern"
    assert r[cr.COL_JURISDICTIONS] == "global"
    assert r[cr.COL_REGULATIONS] == "ISO 27001"
    assert r[cr.COL_VERSION] == "1.2.0"
    assert r[cr.COL_UPDATED] == "2026-02-01"
    # curated columns left blank
    assert r[6] == "" and r[9] == "" and r[12] == "" and r[20] == ""

def test_row_from_catalog_qld_source_and_missing_fields():
    r = cr.row_from_catalog({"slug": "qld-x", "name": "Q", "source": "qld-custom"})
    assert r[cr.COL_SOURCE] == "QLD-Custom"
    assert r[cr.COL_CATEGORY] == "" and r[cr.COL_REF_URL] == "" and r[cr.COL_RISK_RATING] == ""
    assert r[cr.COL_CLASSIFIER_TYPE] == "SIT"

def test_version_bumped():
    assert cr.version_bumped({"version": "1.2.0"}, make_row(cr.SHEET_WIDTH, version="1.0.0"))
    assert not cr.version_bumped({"version": "1.0.0"}, make_row(cr.SHEET_WIDTH, version="1.0.0"))
    # new freshness on a row that never had it = tuned/updated signal
    assert cr.version_bumped({"version": "1.0.0"}, make_row(cr.SHEET_WIDTH, version=""))

def test_detect_changes_drift_and_tuned():
    p = {"name": "New Name", "data_categories": ["pii"], "jurisdictions": ["au"], "version": "2.0.0"}
    row = make_row(cr.SHEET_WIDTH, name="Old Name", category="pii", jurisdictions="au", version="1.0.0")
    ch = cr.detect_changes(p, row)
    assert ch["drift"] == ["name"]   # category/jurisdictions match
    assert ch["tuned"] is True

def test_detect_changes_no_change():
    p = {"name": "Same", "data_categories": ["pii"], "jurisdictions": ["au"], "version": "1.0.0"}
    row = make_row(cr.SHEET_WIDTH, name="Same", category="pii", jurisdictions="au", version="1.0.0")
    assert cr.detect_changes(p, row) == {"drift": [], "tuned": False}

def test_row_from_catalog_dict_references():
    p = {"slug": "s", "name": "N", "references": [{"url": "https://x", "title": "t"}]}
    assert cr.row_from_catalog(p)[cr.COL_REF_URL] == "https://x"

def test_row_from_catalog_string_references_still_work():
    p = {"slug": "s", "name": "N", "references": ["https://y"]}
    assert cr.row_from_catalog(p)[cr.COL_REF_URL] == "https://y"

def test_join_handles_dict_elements():
    assert cr._join([{"name": "a"}, "b"]) == "a; b"
