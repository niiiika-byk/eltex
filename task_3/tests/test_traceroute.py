import pytest
from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether
from scapy.layers.l2 import Dot1Q

IP_DST = ["192.168.43.2", "192.168.41.2", "192.168.42.2"]
IP_SRC = "192.168.44.254"
MAC_DST = "68:13:e2:d8:01:12"
MAC_SRC = "60:cf:84:bd:eb:4f"
CE4_INTERFACE = "enp3s0"  # CE4 с VLAN 4028
VLAN_ID = 4028

EXPECTED_HOPS = {
    "192.168.43.2": ["192.168.44.1", "192.168.43.1", "192.168.43.2"],
    "192.168.41.2": ["192.168.44.1", "192.168.41.2"], 
    "192.168.42.2": ["192.168.44.1", "192.168.42.1", "192.168.42.2"]
}
TIMEOUT = 2
MAX_HOPS = 15

def send_icmp_traceroute_via_vlan(src_ip, dst_ip, vlan_id, interface, ttl):
    #добавляем ttl
    pkt = (Ether(src=MAC_SRC, dst=MAC_DST) / 
           Dot1Q(vlan=vlan_id) / 
           IP(src=src_ip, dst=dst_ip, ttl=ttl) / 
           ICMP(type=8, code=0, id=12345, seq=ttl))

    ans = srp1(pkt, iface=interface, timeout=TIMEOUT, verbose=0)

    return ans

def trace_route_to_ce(dst_ip, vlan_id, interface):
    print("\nHop\tExpected IP\t\tActual IP\t\tStatus")
    print("-" * 70)
    
    hops_info = []
    reached_destination = False
    
    for ttl in range(1, MAX_HOPS + 1):
        response_pkt = send_icmp_traceroute_via_vlan(
            IP_SRC, dst_ip, vlan_id, interface, ttl
        )
        
        #получаем ожидаемый IP для этого хопа
        expected_ip = EXPECTED_HOPS.get(dst_ip, [])[ttl-1] if ttl <= len(EXPECTED_HOPS.get(dst_ip, [])) else "Unknown"
        
        if response_pkt is None:
            status = "Timeout"
            actual_ip = "*"
            is_correct = False
        else:
            actual_ip = response_pkt[IP].src
            
            # Проверяем правильность IP
            if expected_ip != "Unknown":
                is_correct = (actual_ip == expected_ip)
                status = "Correct" if is_correct else f"Expected: {expected_ip}"
            else:
                is_correct = True
                status = "Unknown expected"
            
            # Проверяем тип ответа
            if response_pkt.haslayer(ICMP):
                if response_pkt[ICMP].type == 0:
                    status += " Destination"
                    reached_destination = True
                elif response_pkt[ICMP].type == 11:
                    status += " Intermediate"
        
        print(f"{ttl}\t{expected_ip}\t\t{actual_ip}\t\t{status}")
        
        # Сохраняем информацию о хопе
        hops_info.append({
            'ttl': ttl,
            'expected_ip': expected_ip,
            'actual_ip': actual_ip,
            'is_correct': is_correct,
            'is_destination': reached_destination
        })
        
        if reached_destination:
            break
    
    if not reached_destination:
        print(f"Destination {dst_ip} not reached within {MAX_HOPS} hops")
    
    return hops_info, reached_destination

@pytest.mark.parametrize("ce_ip", IP_DST)
def test_traceroute_to_ce(ce_ip):
    hops_info, reached_destination = trace_route_to_ce(ce_ip, VLAN_ID, CE4_INTERFACE)
    
    #проверка достижения
    assert reached_destination, f"Destination {ce_ip} not reached"
    
    #правильность каждого хопа
    incorrect_hops = []
    for hop in hops_info:
        if not hop['is_correct'] and hop['expected_ip'] != "Unknown":
            incorrect_hops.append(f"Hop {hop['ttl']}: expected {hop['expected_ip']}, got {hop['actual_ip']}")
