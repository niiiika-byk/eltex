import os
import sys
import pytest
import ipaddress
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from script import execute_vrf_check

test_hosts = ['r2-g3', 'r1-g3', 'r4-g3']
start_ip = ipaddress.IPv4Address("192.168.168.41")
end_ip = ipaddress.IPv4Address("192.168.168.43")

def is_ip_in_range(ip_with_mask, start_ip, end_ip):
    ip_str = ip_with_mask.split("/")[0]
    
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return start_ip <= ip <= end_ip
    except ipaddress.AddressValueError:
        return False

@pytest.mark.parametrize("host", test_hosts)
def test_vrf_check(host):
    result = execute_vrf_check(host)
    
    # Проверяем статус выполнения
    assert result["status"], f"Ошибка на хосте {host}: {result['error']}"
    
    # Проверяем парсированные данные
    for i, row in enumerate(result["data"]):
        if len(row) > 2:  # Убедимся, что есть второй элемент
            ip_str = row[2]
            if not is_ip_in_range(ip_str, start_ip, end_ip):
                pytest.fail(
                    f"Хост {host}, строка {i}: IP '{ip_str}' не в диапазоне 192.168.168.41–192.168.168.43"
                )
