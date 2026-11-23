import types

from loganalyzer.parsers import read_lines


def test_reads_files_in_order_with_line_numbers(write_log):
    first = write_log("a.log", ["a1", "a2"])
    second = write_log("b.log", ["b1"])

    assert list(read_lines([first, second])) == [
        (first, 1, "a1"),
        (first, 2, "a2"),
        (second, 1, "b1"),
    ]


def test_skips_blank_lines_but_keeps_real_line_numbers(write_log):
    path = write_log("a.log", ["one", "", "   ", "four"])

    assert list(read_lines([path])) == [(path, 1, "one"), (path, 4, "four")]


def test_strips_windows_line_endings(write_log):
    path = write_log("crlf.log", "one\r\ntwo\r\n")

    assert [line for _, _, line in read_lines([path])] == ["one", "two"]


def test_last_line_without_newline_is_read(write_log):
    path = write_log("a.log", "one\ntwo")

    assert [line for _, _, line in read_lines([path])] == ["one", "two"]


def test_invalid_utf8_is_replaced_not_raised(tmp_path):
    path = tmp_path / "bad.log"
    path.write_bytes(b"ok\n\xff\xfe broken\n")

    lines = [line for _, _, line in read_lines([str(path)])]

    assert lines[0] == "ok"
    assert lines[1].endswith(" broken")
    assert "�" in lines[1]


def test_empty_file_yields_nothing(write_log):
    assert list(read_lines([write_log("empty.log", "")])) == []


def test_is_lazy(write_log):
    path = write_log("big.log", [f"line {i}" for i in range(100_000)])

    lines = read_lines([path])

    assert isinstance(lines, types.GeneratorType)
    assert next(lines) == (path, 1, "line 0")


def test_sample_files_have_expected_line_counts(samples_dir):
    web = list(read_lines([str(samples_dir / "webserver.log")]))
    auth = list(read_lines([str(samples_dir / "auth.log")]))

    assert len(web) == 33
    assert web[25][2].startswith("[MALFORMED")
    assert len(auth) == 12
