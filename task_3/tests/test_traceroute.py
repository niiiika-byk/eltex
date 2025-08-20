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
    "192.168.42.2": ["192.168.44.1", "192.168.42.1", "192.168.42.2"],
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
    print(f"\nTraceroute to {dst_ip} via VLAN {vlan_id}:")
    print("Hop\tIP Address\t\tStatus")
    print("-" * 40)
    
    reached_destination = False
    
    for ttl in range(1, MAX_HOPS + 1):
        response_pkt = send_icmp_traceroute_via_vlan(
            IP_SRC, dst_ip, vlan_id, interface, ttl
        )
        
        if response_pkt is None:
            print(f"{ttl}\t*\t\t\tTimeout")
            continue
        
        # Анализируем тип ответа
        if response_pkt.haslayer(ICMP):
            if response_pkt[ICMP].type == 0:  # Echo Reply - достигли цели
                print(f"{ttl}\t{response_pkt[IP].src}\tDestination Reached!")
                reached_destination = True
                break
            elif response_pkt[ICMP].type == 11:  # Time Exceeded - промежуточный узел
                print(f"{ttl}\t{response_pkt[IP].src}\tIntermediate Hop")
            else:
                print(f"{ttl}\t{response_pkt[IP].src}\tICMP Type {response_pkt[ICMP].type}")
        else:
            print(f"{ttl}\t{response_pkt[IP].src}\tOther Protocol")
    
    if not reached_destination:
        print(f"Destination {dst_ip} not reached within {MAX_HOPS} hops")
    
    return reached_destination

@pytest.mark.parametrize("ce_ip", IP_DST)
def test_traceroute_to_ce(ce_ip):
    success = trace_route_to_ce(ce_ip, VLAN_ID, CE4_INTERFACE)
    assert success, f"Failed to reach destination {ce_ip}"