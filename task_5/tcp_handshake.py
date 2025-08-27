import os
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
import random

# Конфигурация маршрутизатора
IP_DST = "192.168.17.12"
IP_SRC = "192.168.17.13"
MAC_SRC = "de:ad:be:af:00:55"
MAC_DST = "68:13:e2:d8:01:05" 
TELNET_PORT = 23
USERNAME = os.environ.get('ROUTER_USER', 'admin')
PASSWORD = os.environ.get('ROUTER_PASSWORD', 'password')
src_port = random.randint(1024, 65535)

def telnet_connection_autoriz():
    """Устанавливает TCP соединение с маршрутизатором"""
    try:
        print(f"Пытаюсь установить TCP соединение с {IP_DST}:{TELNET_PORT}")
        
        # Отправляем SYN пакет
        syn_packet = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST)/TCP(sport=src_port,dport=TELNET_PORT, flags='S')
        syn_ack_response = srp1(
            syn_packet, 
            iface="enp1s0", 
            timeout=5, 
            verbose=0,
            filter=f"tcp and host {IP_DST} and port {src_port}"
        )

        if syn_ack_response is None:
            print("Нет ответа на SYN запрос")
            return False, None
        
        if syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 'SA':
            print("Получен SYN-ACK ответ, соединение установлено")
            
            # Формируем ACK пакет
            ack_packet = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC,dst=IP_DST) / TCP(
                dport=TELNET_PORT, 
                sport=src_port,
                seq=syn_ack_response[TCP].ack,      # seq = ack из SYN-ACK
                ack=syn_ack_response[TCP].seq + 1,  # ack = seq + 1 из SYN-ACK
                flags='A',
            )
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("TCP соединение установлено успешно")
            
            connection_params = {
                'seq': syn_ack_response[TCP].ack,
                'ack': syn_ack_response[TCP].seq + 1
            }

            # Возвращаем параметры для последующих пакетов
            return connection_params
        else:
            print(f"Неожиданный ответ: {syn_ack_response.summary()}")
            return False, None
            
    except Exception as e:
        print(f"Ошибка при установке соединения: {e}")
        return False, None