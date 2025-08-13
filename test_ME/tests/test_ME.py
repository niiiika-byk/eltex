import os
import sys
import pytest
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from script import execute_vrf_check

test_hosts = ['r2-g3', 'r1-g3', 'r4-g3']

@pytest.mark.parametrize("host", test_hosts)
def test_vrf_check(host):
    result = execute_vrf_check(host)
    assert result["status"] is True


