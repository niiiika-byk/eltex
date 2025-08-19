import os
import sys
import pytest
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from script import count_characters

def test_even_char_count(tmp_path):
    test_file = tmp_path / "even.txt"
    test_file.write_text("1234")  # 4 characters (even)
    count, is_even = count_characters(test_file)
    assert is_even is True

def test_odd_char_count(tmp_path):
    test_file = tmp_path / "odd.txt"
    test_file.write_text("123")  # 3 characters (odd)
    count, is_even = count_characters(test_file)
    assert is_even is False

def test_empty_file(tmp_path):
    test_file = tmp_path / "empty.txt"
    test_file.write_text("")  # 0 characters (even)
    count, is_even = count_characters(test_file)
    assert is_even is True

def test_file_not_found():
    with pytest.raises(SystemExit):
        count_characters("non_existent_file.txt")

