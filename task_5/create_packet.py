from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

IP_DST = "192.168.17.12"
IP_SRC = "192.168.17.13"
MAC_SRC = "de:ad:be:af:00:55"
MAC_DST = "68:13:e2:d8:01:05" 
TELNET_PORT = 23

def create_tcp_ack_packet(sport, seq, ack):
    """Создает TCP пакет с ACK флагом"""
    return Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
        sport=sport,
        dport=TELNET_PORT,
        seq=seq,
        ack=ack,
        flags="A"
    )

def create_telnet_data_packet(data, sport, seq, ack):
    """Создает IP/TCP пакет с TELNET данными"""
    return Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
        dport=TELNET_PORT,
        sport=sport,
        flags='PA',   # PSH + ACK
        seq=seq,
        ack=ack
    )/Raw(load=data)

def sniff_telnet_response(src_port, timeout=5):
    """Ожидание ответ от TELNET сервера"""
    return sniff(
        filter=f"tcp and host {IP_DST} and port {src_port}",
        count=1,
        timeout=timeout,
        iface="enp1s0"
    )

def handle_telnet_options(packet, src_port, seq, ack):
    """Минимальная обработка TELNET опций"""
    if Raw in packet and b'\xff' in packet[Raw].load:

        telnet_response = bytes([
            0xFF, 0xFB, 0x01,  # WILL Echo
            0xFF, 0xFD, 0x01,  # DO Echo
            0xFF, 0xFB, 0x1F,  # WILL NAWS  
            0xFF, 0xFD, 0x03   # DO Suppress Go Ahead
        ])
        
        response_packet = create_telnet_data_packet(telnet_response, src_port, seq, ack)
        sendp(response_packet, iface="enp1s0", verbose=0)
        return True, len(telnet_response)
    
    return False, 0

def close_telnet_connection(src_port, connection_params):
    """Закрывает TCP соединение с ожиданием подтверждения"""
    try:
        seq = connection_params['seq']
        ack = connection_params['ack']
        print("\nЗакрытие TCP соединения...")
        
        # Отправляем FIN пакет
        fin_packet = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
            dport=TELNET_PORT,
            sport=src_port,
            seq=seq,
            ack=ack,
            flags='FA',  # FIN + ACK
        )
        sendp(fin_packet, iface="enp1s0", verbose=0)
        
        # Ждем подтверждение FIN от сервера
        print("Ожидаем подтверждение FIN...")
        fin_ack_response = sniff(
            iface="enp1s0",
            count=1,
            timeout=5,
            filter=f"tcp and host {IP_DST} and port {src_port}",
            lfilter=lambda x: x.haslayer(TCP) and x[TCP].flags == 'FA'
        )
        
        if fin_ack_response:
            print("Получено подтверждение FIN")
            ack_packet = create_tcp_ack_packet(src_port, seq + 1, ack + 1)
            sendp(ack_packet, iface="enp1s0", verbose=0)
        else:
            print("Таймаут ожидания подтверждения FIN")
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
        
        print("\nСоединение закрыто")
        return True
        
    except Exception as e:
        print(f"Ошибка при закрытии соединения: {e}")
        return False