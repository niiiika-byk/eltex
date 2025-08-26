import os
import threading
import time
#import allure
import pytest
from scapy.all import *
from scapy.layers.inet import IP, TCP
import random

# Конфигурация маршрутизатора
ROUTER_IP = "192.168.17.12"
TELNET_PORT = 23
USERNAME = os.environ.get('ROUTER_USER', 'admin')
PASSWORD = os.environ.get('ROUTER_PASSWORD', 'password')
MAX_SESSIONS = 20

def establish_telnet_connection():
    """Устанавливает TCP соединение с маршрутизатором через TELNET
    и выполняет базовую аутентификацию"""
    try:
        # Создаем TCP SYN пакет для установки соединения
        print(f"Пытаюсь установить TCP соединение с {ROUTER_IP}:{TELNET_PORT}")
        
        # Отправляем SYN пакет
        syn_packet = IP(dst=ROUTER_IP)/TCP(dport=TELNET_PORT, flags='S')
        syn_ack_response = sr1(syn_packet, timeout=5, verbose=0)
        
        if syn_ack_response is None:
            print("Нет ответа на SYN запрос")
            return False
            
        if syn_ack_response.haslayer(TCP) and syn_ack_response[TCP].flags == 'SA':
            print("Получен SYN-ACK ответ, соединение установлено")
            
            # Отправляем ACK для завершения трехстороннего рукопожатия
            ack_packet = IP(dst=ROUTER_IP)/TCP(
                dport=TELNET_PORT, 
                sport=syn_ack_response[TCP].dport,
                seq=syn_ack_response[TCP].ack,
                ack=syn_ack_response[TCP].seq + 1,
                flags='A'
            )
            send(ack_packet, verbose=0)
            print("TCP соединение установлено успешно")
            
            # Теперь попробуем выполнить аутентификацию
            return authenticate_telnet()
            
        else:
            print(f"Неожиданный ответ: {syn_ack_response.summary()}")
            return False
            
    except Exception as e:
        print(f"Ошибка при установке соединения: {e}")
        return False

def authenticate_telnet():
    """Выполняет аутентификацию в TELNET сессии"""
    try:
        print("Пытаюсь выполнить аутентификацию...")
        
        # Создаем сырой сокет для отправки данных TELNET
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Отправляем имя пользователя
        username_packet = create_telnet_data_packet(USERNAME + "\r\n")
        send(username_packet, verbose=0)
        time.sleep(1)
        
        # Отправляем пароль
        password_packet = create_telnet_data_packet(PASSWORD + "\r\n")
        send(password_packet, verbose=0)
        time.sleep(1)
        
        print("Аутентификация выполнена (данные отправлены)")
        return True
        
    except Exception as e:
        print(f"Ошибка при аутентификации: {e}")
        return False

def create_telnet_data_packet(data):
    """
    Создает IP/TCP пакет с TELNET данными
    """
    return IP(dst=ROUTER_IP)/TCP(
        dport=TELNET_PORT,
        sport=RandShort(),  # Случайный исходный порт
        flags='PA',         # PSH + ACK флаги для данных
        seq=1000,           # Начальный номер последовательности
        ack=1001           # Номер подтверждения
    )/Raw(load=data)

# Пример использования
if __name__ == "__main__":
    establish_telnet_connection()