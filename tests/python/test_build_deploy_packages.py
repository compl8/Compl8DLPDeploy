import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("bdp", pathlib.Path(__file__).parents[2] / "scripts" / "build-deploy-packages.py")
bdp = importlib.util.module_from_spec(spec); spec.loader.exec_module(bdp)

def test_utf16_len_is_double_ascii():
    assert bdp.utf16_len("abc") == 6

def test_select_bin_fills_to_target_largest_first():
    sizes = {"a": 100, "b": 60, "c": 60, "d": 60}
    chosen, rest = bdp.select_bin(["a","b","c","d"], sizes, shrink=1.0, target=160)
    assert chosen == ["a","b"] and rest == ["c","d"]   # 100+60=160 <= target; rest carries over
