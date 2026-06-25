import importlib.util, pathlib
def _load(name):
    p = pathlib.Path(__file__).parents[2] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
bfx = _load("_bfx_analysis")

def _norm(n): return "".join(c for c in n.lower() if c.isalnum())

def test_builtin_map_resolves_by_guid_regardless_of_xml():
    entry = {"name": "Australian Passport Number", "guid_slug": "au-passport", "label_code": "SENS_Pvc",
             "classifier_type": "Regex", "source": "TestPattern"}
    bm = {_norm("Australian Passport Number"): "29869db6-602d-4853-ab93-3484f905df50"}
    guid, source = bfx.resolve_guid(entry, xml_lookup={}, classifier_lookup={}, builtin_map=bm)
    assert source == "builtin"
    assert guid == "29869db6-602d-4853-ab93-3484f905df50"

def test_non_builtin_still_unresolved_without_xml():
    entry = {"name": "AHPRA Registration Number", "guid_slug": "au-ahpra-registration",
             "label_code": "PROT_IT", "classifier_type": "Regex", "source": "TestPattern"}
    guid, source = bfx.resolve_guid(entry, xml_lookup={}, classifier_lookup={}, builtin_map={})
    assert source == "unresolved"

def test_explicit_uuid_wins_over_name_matched_builtin():
    # A row carrying an explicit UUID whose normalized name ALSO collides with a built-in:
    # the explicit UUID is the precise source and must win, not the name-matched built-in GUID.
    entry = {"name": "Australian Passport Number", "guid_slug": "11111111-2222-3333-4444-555555555555",
             "label_code": "SENS_Pvc", "classifier_type": "Regex", "source": "TestPattern"}
    bm = {_norm("Australian Passport Number"): "29869db6-602d-4853-ab93-3484f905df50"}
    guid, source = bfx.resolve_guid(entry, xml_lookup={}, classifier_lookup={}, builtin_map=bm)
    assert source == "spreadsheet"
    assert guid == "11111111-2222-3333-4444-555555555555"
