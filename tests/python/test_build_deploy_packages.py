import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("bdp", pathlib.Path(__file__).parents[2] / "scripts" / "build-deploy-packages.py")
bdp = importlib.util.module_from_spec(spec); spec.loader.exec_module(bdp)

def test_utf16_len_is_double_ascii():
    assert bdp.utf16_len("abc") == 6

def test_select_bin_fills_to_target_largest_first():
    sizes = {"a": 100, "b": 60, "c": 60, "d": 60}
    chosen, rest = bdp.select_bin(["a","b","c","d"], sizes, shrink=1.0, target=160, max_entities=50)
    assert chosen == ["a","b"] and rest == ["c","d"]   # 100+60=160 <= target; rest carries over

def test_select_bin_caps_entity_count():
    # 10 tiny slugs each with size=1; target is huge so size alone would let all 10 in.
    # max_entities=3 must stop at 3 and push the remaining 7 to rest.
    sizes = {f"s{i}": 1 for i in range(10)}
    remaining = [f"s{i}" for i in range(10)]
    chosen, rest = bdp.select_bin(remaining, sizes, shrink=1.0, target=10_000, max_entities=3)
    assert len(chosen) == 3
    assert len(rest) == 7
    assert set(chosen) | set(rest) == set(remaining)
