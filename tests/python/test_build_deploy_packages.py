import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("bdp", pathlib.Path(__file__).parents[2] / "scripts" / "build-deploy-packages.py")
bdp = importlib.util.module_from_spec(spec); spec.loader.exec_module(bdp)

def test_utf16_len_is_double_ascii():
    assert bdp.utf16_len("abc") == 6

def test_ffd_largest_first_and_cap():
    sizes = {"big": 90, "a": 40, "b": 40, "c": 40}
    bins, dropped = bdp.ffd_assign(sizes, wrapper=0, budget=100, max_packages=9)
    assert dropped == []
    assert any(set(b) == {"big"} for b in bins)      # largest got its own bin first
    assert len(bins) == 3

def test_ffd_drops_overflow_past_max_packages():
    sizes = {f"s{i}": 90 for i in range(10)}          # each needs its own 100-budget bin
    bins, dropped = bdp.ffd_assign(sizes, wrapper=0, budget=100, max_packages=9)
    assert len(bins) == 9
    assert len(dropped) == 1
