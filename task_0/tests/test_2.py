import os
import sys
import pytest
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from script import count_characters

TEST_FILES_DIR = os.path.join(os.path.dirname(__file__), 'test_data')

test_files = [os.path.join(TEST_FILES_DIR, f) for f in os.listdir(TEST_FILES_DIR)
              if os.path.isfile(os.path.join(TEST_FILES_DIR, f))]

@pytest.mark.parametrize("test_file", test_files)
def test_even_char_count(test_file):
    count, is_even = count_characters(test_file)
    assert is_even is False