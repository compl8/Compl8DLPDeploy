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


def test_measure_slugs_retries_transient_failure_then_succeeds():
    # 'b' fails on the first sweep, succeeds on the retry. Nothing should end up missing.
    calls = {"b": 0}
    def measure_fn(s):
        if s == "b":
            calls["b"] += 1
            if calls["b"] == 1:
                raise TimeoutError("transient")
            return 42
        return 10
    single, missing = bdp.measure_slugs(["a", "b"], {}, measure_fn,
                                        delay=0, attempts=3, sleep_fn=lambda *_: None)
    assert missing == []
    assert single == {"a": 10, "b": 42}
    assert calls["b"] == 2  # failed once, retried once


def test_measure_slugs_reports_persistent_failure_as_missing():
    # 'b' always fails -> it must be reported in `missing` (caller fails the build), never silently dropped.
    def measure_fn(s):
        if s == "b":
            raise OSError("dns")
        return 7
    single, missing = bdp.measure_slugs(["a", "b"], {}, measure_fn,
                                        delay=0, attempts=3, sleep_fn=lambda *_: None)
    assert missing == ["b"]
    assert single == {"a": 7}


def test_measure_slugs_skips_already_cached():
    # A slug already present in `single` is not re-measured.
    def measure_fn(s):
        raise AssertionError(f"should not measure cached slug {s}")
    single, missing = bdp.measure_slugs(["a"], {"a": 99}, measure_fn,
                                        delay=0, attempts=3, sleep_fn=lambda *_: None)
    assert missing == []
    assert single == {"a": 99}
