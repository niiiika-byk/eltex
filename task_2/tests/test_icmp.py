import pytest
from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether, getmacbyip

CE_IPS = ["192.168.43.2", "192.168.41.2", "192.168.42.2", "192.168.44.1"]
MAC_DST = "68:13:e2:d8:01:12"
MAC_SRC = "60:cf:84:bd:eb:4f"
CE4_INTERFACE = "enp3s0"  #CE4 с VLAN 4028
VLAN_ID = 4028
TIMEOUT = 2
SOURCE_IP = "192.168.44.254"

def send_icmp_via_vlan(src_ip, dst_ip, vlan_id, interface):

    mac = getmacbyip(dst_ip)
    if not mac:
        print(f"Не удалось получить MAC для {dst_ip}")
        return False
    
    # Создаем пакет с VLAN-тегом
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / Dot1Q(vlan=vlan_id) / IP(src=src_ip, dst=dst_ip) / ICMP()
    
    # Отправляем пакет и ждем ответ
    ans = srp1(pkt, iface=interface, timeout=TIMEOUT, verbose=0)
    return ans is not None

@pytest.mark.parametrize("ce_ip", CE_IPS)
def test_icmp_to_ce(ce_ip):
    result = send_icmp_via_vlan(SOURCE_IP, ce_ip, VLAN_ID, CE4_INTERFACE)
    assert result, f"No ICMP reply received from {ce_ip} via VLAN {VLAN_ID}"