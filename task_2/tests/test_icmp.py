import pytest
from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether

IP_DST = ["192.168.43.2", "192.168.41.2", "192.168.42.2", "192.168.44.1"]
IP_SRC = "192.168.44.254"
MAC_DST = "68:13:e2:d8:01:12"
MAC_SRC = "60:cf:84:bd:eb:4f"
CE4_INTERFACE = "enp3s0"  #CE4 с VLAN 4028
VLAN_ID = 4028
TIMEOUT = 2

def send_icmp_via_vlan(src_ip, dst_ip, vlan_id, interface):

    # Создаем пакет с VLAN-тегом
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / Dot1Q(vlan=vlan_id) / IP(src=src_ip, dst=dst_ip) / ICMP(id=12345, seq=1)
    # Без VLAN-тега
    pkt = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=src_ip, dst=dst_ip) / ICMP(id=12345, seq=1)

    
    # Отправляем пакет и ждем ответ
    ans = srp1(pkt, iface="enp3s0", timeout=TIMEOUT, verbose=0, 
           filter=f"ether src {MAC_DST} and icmp")

    return ans

@pytest.mark.parametrize("ce_ip", IP_DST)
def test_icmp_to_ce(ce_ip):
    response_pkt = send_icmp_via_vlan(IP_SRC, ce_ip, VLAN_ID, CE4_INTERFACE)

    # Проверяем получение ответа
    assert response_pkt is not None, f"No ICMP reply received from {ce_ip}"
    
    # Анализируем структуру пакета
    assert Ether in response_pkt, "Ответ не содержит Ethernet-заголовок"
    assert IP in response_pkt, "Ответ не содержит IP-заголовок"
    assert ICMP in response_pkt, "Ответ не содержит ICMP-заголовок"
    
    # Проверяем VLAN-тег (если он есть в ответе)
    if Dot1Q in response_pkt:
        assert response_pkt[Dot1Q].vlan == VLAN_ID, f"Неверный VLAN-ID в ответе: ожидался {VLAN_ID}, получен {response_pkt[Dot1Q].vlan}"
    
    # Проверяем IP-адреса
    assert response_pkt[IP].src == ce_ip, f"Неверный исходный IP в ответе: ожидался {ce_ip}, получен {response_pkt[IP].src}"
    assert response_pkt[IP].dst == IP_SRC, f"Неверный целевой IP в ответе: ожидался {IP_SRC}, получен {response_pkt[IP].dst}"
    
    # Проверяем MAC-адреса
    assert response_pkt[Ether].src == MAC_DST, f"Неверный исходный MAC в ответе: ожидался {MAC_DST}, получен {response_pkt[Ether].src}"
    assert response_pkt[Ether].dst == MAC_SRC, f"Неверный целевой MAC в ответе: ожидался {MAC_SRC}, получен {response_pkt[Ether].dst}"
    