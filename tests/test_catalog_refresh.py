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
