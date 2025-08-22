import pytest
from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether
from scapy.layers.l2 import ARP, Ether, Dot1Q

# MAC-адреса участников L2VPN
MAC_SRC = "de:ad:be:af:00:44"
MAC_DST_LIST = [ "de:ad:be:af:00:41", "de:ad:be:af:00:42",  "de:ad:be:af:00:43" ]
IP_SRC = "192.168.100.44"
IP_DST = "192.168.100.100"  # Фиктивный IP для ARP-запроса

CE4_INTERFACE = "enp3s0"
VLAN_ID = 4028
TIMEOUT = 2

def send_arp_via_vlan(src_mac, dst_mac, src_ip, target_ip, vlan_id, interface):
    """
    Отправляет ARP-запрос через VLAN и возвращает ответ
    """
    # Создаем ARP-запрос с VLAN-тегом
    pkt = (Ether(src=src_mac, dst=dst_mac) / 
           Dot1Q(vlan=vlan_id) / 
           ARP(op=1, hwsrc=src_mac, psrc=src_ip, 
               hwdst="00:00:00:00:00:00", pdst=target_ip))
    
    # Отправляем пакет и ждем ответ
    ans = srp1(pkt, iface=interface, timeout=TIMEOUT, verbose=0,
               filter=f"ether src {dst_mac} and arp")
    
    return ans

def send_icmp_via_vlan(src_mac, dst_mac, src_ip, dst_ip, vlan_id, interface):
    """
    Отправляет ICMP-запрос через VLAN и возвращает ответ
    """
    # Создаем ICMP-пакет с VLAN-тегом
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           Dot1Q(vlan=vlan_id) /
           IP(src=src_ip, dst=dst_ip) /
           ICMP(id=12345, seq=1))
    
    # Отправляем пакет и ждем ответ
    ans = srp1(pkt, iface=interface, timeout=TIMEOUT, verbose=0,
               filter=f"ether src {dst_mac} and icmp")
    
    return ans

@pytest.mark.parametrize("target_mac", MAC_DST_LIST)
def test_icmp_to_ce(target_mac):
    # Предполагаем IP-адрес на основе MAC
    target_ip = f"192.168.100.{target_mac.split(':')[-1]}"
    
    response_pkt = send_icmp_via_vlan(MAC_SRC, target_mac, IP_SRC, 
                                    target_ip, VLAN_ID, CE4_INTERFACE)
    
    # Проверяем получение ответа
    assert response_pkt is not None, f"No ICMP reply received from {target_mac}"
    
    # Анализируем структуру пакета
    assert Ether in response_pkt, "Ответ не содержит Ethernet-заголовок"
    assert IP in response_pkt, "Ответ не содержит IP-заголовок"
    assert ICMP in response_pkt, "Ответ не содержит ICMP-заголовок"
    
    # Проверяем MAC-адреса
    assert response_pkt[Ether].src == target_mac, (
        f"Неверный исходный MAC в ответе: ожидался {target_mac}, "
        f"получен {response_pkt[Ether].src}"
    )
    assert response_pkt[Ether].dst == MAC_SRC, (
        f"Неверный целевой MAC в ответе: ожидался {MAC_SRC}, "
        f"получен {response_pkt[Ether].dst}"
    )
    
    # Проверяем VLAN-тег (если есть)
    if Dot1Q in response_pkt:
        assert response_pkt[Dot1Q].vlan == VLAN_ID, (
            f"Неверный VLAN-ID в ответе: ожидался {VLAN_ID}, "
            f"получен {response_pkt[Dot1Q].vlan}"
        )
    
    # Проверяем IP-адреса
    assert response_pkt[IP].src == target_ip, (
        f"Неверный исходный IP в ответе: ожидался {target_ip}, "
        f"получен {response_pkt[IP].src}"
    )
    assert response_pkt[IP].dst == IP_SRC, (
        f"Неверный целевой IP в ответе: ожидался {IP_SRC}, "
        f"получен {response_pkt[IP].dst}"
    )