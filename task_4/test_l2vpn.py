import pytest
import allure
from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether, Dot1Q

# MAC-адреса участников L2VPN
MAC_SRC = "de:ad:be:af:00:44"
MAC_DST_LIST = ["de:ad:be:af:00:41", "de:ad:be:af:00:42", "de:ad:be:af:00:43"]
IP_SRC = "192.168.100.44"

CE4_INTERFACE = "enp3s0"
VLAN_ID = 4028
TIMEOUT = 2

@allure.step("Отправка ICMP-запроса")
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

@allure.step("Отправка ARP-запроса")
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
               filter=f"arp and ether src not {src_mac}")
    
    return ans

def packet_to_html_table(packet):
    """Преобразует структуру пакета в HTML таблицу"""
    html = """
    <table border="1" style="border-collapse: collapse; width: 100%;">
        <tr style="background-color: #f2f2f2;">
            <th style="padding: 8px; text-align: left;">Слой</th>
            <th style="padding: 8px; text-align: left;">Поле</th>
            <th style="padding: 8px; text-align: left;">Значение</th>
        </tr>
    """
    
    # Перебираем все слои пакета
    for layer in packet.layers():
        layer_name = layer.__name__
        layer_obj = packet.getlayer(layer)
        
        if layer_obj:
            # Добавляем заголовок слоя
            html += f"""
            <tr style="background-color: #e8f4f8;">
                <td colspan="3" style="padding: 8px; font-weight: bold;">
                    {layer_name}
                </td>
            </tr>
            """
            
            # Добавляем поля слоя
            for field in layer_obj.fields_desc:
                field_name = field.name
                field_value = getattr(layer_obj, field_name, 'N/A')
                
                # Форматируем специальные типы полей
                if isinstance(field_value, bytes):
                    field_value = field_value.hex()
                elif isinstance(field_value, list):
                    field_value = ', '.join(str(x) for x in field_value)
                
                html += f"""
                <tr>
                    <td style="padding: 6px;"></td>
                    <td style="padding: 6px; font-weight: bold;">{field_name}</td>
                    <td style="padding: 6px; font-family: monospace;">{field_value}</td>
                </tr>
                """
    
    html += "</table>"
    return html

def attach_packet_structure(response_pkt, step_name="Структура пакета"):
    """Прикрепляет структуру пакета как HTML таблицу в Allure"""
    html_table = packet_to_html_table(response_pkt)
    
    allure.attach(
        html_table,
        name=step_name,
        attachment_type=allure.attachment_type.HTML
    )

@allure.story("Проверка ICMP связности между CE")
@pytest.mark.parametrize("target_mac", MAC_DST_LIST)
def test_icmp_to_ce(target_mac):
    """
    Тест ICMP связности до удаленных MAC-адресов через L2VPN
    """
    allure.dynamic.title(f"ICMP тест до MAC: {target_mac}")
    
    # Предполагаем IP-адрес на основе MAC
    target_ip = f"192.168.100.{target_mac.split(':')[-1]}"
    
    with allure.step(f"Отправка ICMP запроса к {target_ip} ({target_mac})"):
        response_pkt = send_icmp_via_vlan(MAC_SRC, target_mac, IP_SRC, 
                                        target_ip, VLAN_ID, CE4_INTERFACE)
    
    # Проверяем получение ответа
    assert response_pkt is not None, f"No ICMP reply received from {target_mac}"
    
    with allure.step("Анализ структуры пакета ответа"):
        # Анализируем структуру пакета
        assert Ether in response_pkt, "Ответ не содержит Ethernet-заголовок"
        assert IP in response_pkt, "Ответ не содержит IP-заголовок"
        assert ICMP in response_pkt, "Ответ не содержит ICMP-заголовок"
        
        attach_packet_structure(response_pkt, "Детальная структура ответного пакета")
    
    with allure.step("Проверка MAC-адресов"):
        # Проверяем MAC-адреса
        assert response_pkt[Ether].src == target_mac, (
            f"Неверный исходный MAC в ответе: ожидался {target_mac}, "
            f"получен {response_pkt[Ether].src}"
        )
        assert response_pkt[Ether].dst == MAC_SRC, (
            f"Неверный целевой MAC в ответе: ожидался {MAC_SRC}, "
            f"получен {response_pkt[Ether].dst}"
        )
        
        allure.attach(
            f"Source MAC: {response_pkt[Ether].src}\n"
            f"Destination MAC: {response_pkt[Ether].dst}",
            name="MAC Addresses",
            attachment_type=allure.attachment_type.TEXT
        )
    
    with allure.step("Проверка VLAN-тега"):
        # Проверяем VLAN-тег (если есть)
        if Dot1Q in response_pkt:
            assert response_pkt[Dot1Q].vlan == VLAN_ID, (
                f"Неверный VLAN-ID в ответе: ожидался {VLAN_ID}, "
                f"получен {response_pkt[Dot1Q].vlan}"
            )
            
            allure.attach(
                f"VLAN ID: {response_pkt[Dot1Q].vlan}",
                name="VLAN Information",
                attachment_type=allure.attachment_type.TEXT
            )
        else:
            allure.attach(
                "VLAN тег не обнаружен в ответе",
                name="VLAN Information",
                attachment_type=allure.attachment_type.TEXT
            )
    
    with allure.step("Проверка IP-адресов"):
        # Проверяем IP-адреса
        assert response_pkt[IP].src == target_ip, (
            f"Неверный исходный IP в ответе: ожидался {target_ip}, "
            f"получен {response_pkt[IP].src}"
        )
        assert response_pkt[IP].dst == IP_SRC, (
            f"Неверный целевой IP в ответе: ожидался {IP_SRC}, "
            f"получен {response_pkt[IP].dst}"
        )
        
        allure.attach(
            f"Source IP: {response_pkt[IP].src}\n"
            f"Destination IP: {response_pkt[IP].dst}",
            name="IP Addresses",
            attachment_type=allure.attachment_type.TEXT
        )
    
    with allure.step("Успешное завершение теста"):
        allure.attach(
            f"Успешная ICMP связность с {target_mac} ({target_ip})",
            name="Test Result",
            attachment_type=allure.attachment_type.TEXT
        )

@allure.story("Проверка ARP связности между CE")
@pytest.mark.parametrize("target_mac", MAC_DST_LIST)
def test_arp_to_ce(target_mac):
    """
    Тест ARP связности до удаленных MAC-адресов через L2VPN
    """
    allure.dynamic.title(f"ARP тест до MAC: {target_mac}")
    
    # Предполагаем IP-адрес на основе MAC
    target_ip = f"192.168.100.{target_mac.split(':')[-1]}"
    
    with allure.step(f"Отправка ARP запроса к {target_ip} ({target_mac})"):
        response_pkt = send_arp_via_vlan(MAC_SRC, target_mac, IP_SRC, 
                                        target_ip, VLAN_ID, CE4_INTERFACE)
    
    # Проверяем получение ответа
    assert response_pkt is not None, f"No ARP reply received from {target_mac}"
    
    with allure.step("Анализ структуры пакета ответа"):
        # Анализируем структуру пакета
        assert Ether in response_pkt, "Ответ не содержит Ethernet-заголовок"
        
        attach_packet_structure(response_pkt, "Детальная структура ответного пакета")
    
    with allure.step("Проверка MAC-адресов"):
        # Проверяем MAC-адреса
        assert response_pkt[Ether].src == target_mac, (
            f"Неверный исходный MAC в ответе: ожидался {target_mac}, "
            f"получен {response_pkt[Ether].src}"
        )
        assert response_pkt[Ether].dst == MAC_SRC, (
            f"Неверный целевой MAC в ответе: ожидался {MAC_SRC}, "
            f"получен {response_pkt[Ether].dst}"
        )
        
        allure.attach(
            f"Source MAC: {response_pkt[Ether].src}\n"
            f"Destination MAC: {response_pkt[Ether].dst}",
            name="MAC Addresses",
            attachment_type=allure.attachment_type.TEXT
        )
    
    with allure.step("Проверка VLAN-тега"):
        # Проверяем VLAN-тег (если есть)
        if Dot1Q in response_pkt:
            assert response_pkt[Dot1Q].vlan == VLAN_ID, (
                f"Неверный VLAN-ID в ответе: ожидался {VLAN_ID}, "
                f"получен {response_pkt[Dot1Q].vlan}"
            )
            
            allure.attach(
                f"VLAN ID: {response_pkt[Dot1Q].vlan}",
                name="VLAN Information",
                attachment_type=allure.attachment_type.TEXT
            )
        else:
            allure.attach(
                "VLAN тег не обнаружен в ответе",
                name="VLAN Information",
                attachment_type=allure.attachment_type.TEXT
            )
    
    with allure.step("Успешное завершение теста"):
        allure.attach(
            f"Успешная ARP связность с {target_mac} ({target_ip})",
            name="Test Result",
            attachment_type=allure.attachment_type.TEXT
        )