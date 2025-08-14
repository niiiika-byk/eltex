import os
import sys
import pytest
import ipaddress
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from script import execute_vrf_check

test_hosts = ['r2-g3', 'r1-g3', 'r4-g3']
start_ip = ipaddress.IPv4Address("192.168.168.41")
end_ip = ipaddress.IPv4Address("192.168.168.43")

#генерируем ожидаемые ip из диапазона
expected_ips = {str(ipaddress.IPv4Address(ip_int)) 
               for ip_int in range(int(start_ip), int(end_ip) + 1)}

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
    
    assert result["status"], f"Ошибка на хосте {host}: {result['error']}"
    
    #создаем массив полученных ip
    ips_in_range = []
    
    #проверяем наличие всех ip в полученных данных
    for i, row in enumerate(result["data"]):
        if len(row) > 2:  #
            ip_str = row[2]
            if is_ip_in_range(ip_str, start_ip, end_ip):
                ips_in_range.append(ip_str.split("/")[0])
            else:
                pytest.fail(
                    f"Хост {host}, строка {i}: IP '{ip_str}' не в диапазоне {start_ip}–{end_ip}"
                )
    
    #вывод потерянного ip
    found_ips = set(ips_in_range)
    missing_ips = expected_ips - found_ips
    assert not missing_ips, f"Хост {host}: отсутствуют IP-адреса {missing_ips}"