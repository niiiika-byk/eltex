import pytest
import allure
import graphviz
from scapy.all import *
from scapy.layers.inet import ICMP, IP, Ether
from scapy.layers.l2 import Dot1Q
from allure_commons.types import AttachmentType

IP_DST = ["192.168.43.2", "192.168.41.2", "192.168.42.2"]
IP_SRC = "192.168.44.254"
MAC_DST = "68:13:e2:d8:01:12"
MAC_SRC = "60:cf:84:bd:eb:4f"
CE4_INTERFACE = "enp3s0"
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

@allure.step("Выполнение traceroute к {dst_ip}")
def trace_route_to_ce(dst_ip, vlan_id, interface):
    
    hops_info = []
    reached_destination = False
    
    # Создаем таблицу для allure
    with allure.step(f"Traceroute к {dst_ip} через VLAN {vlan_id}"):
        allure.attach(f"""
        Ожидаемый путь для {dst_ip}:
        {', '.join(EXPECTED_HOPS.get(dst_ip, []))}
        """, name="Ожидаемый маршрут")
    
    for ttl in range(1, MAX_HOPS + 1):
        with allure.step(f"Хоп {ttl}"):
            response_pkt = send_icmp_traceroute_via_vlan(
                IP_SRC, dst_ip, vlan_id, interface, ttl
            )
            
            # Получаем ожидаемый IP для этого хопа
            expected_ip = EXPECTED_HOPS.get(dst_ip, [])[ttl-1] if ttl <= len(EXPECTED_HOPS.get(dst_ip, [])) else "Unknown"
            
            if response_pkt is None:
                status = "Timeout"
                actual_ip = "*"
                is_correct = False
                allure.attach(f"TTL: {ttl}\nСтатус: {status}", name="Результат хопа")
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
                icmp_info = ""
                if response_pkt.haslayer(ICMP):
                    if response_pkt[ICMP].type == 0:
                        status += " Destination"
                        reached_destination = True
                        icmp_info = "ICMP Echo Reply - достигнута цель"
                    elif response_pkt[ICMP].type == 11:
                        status += " Intermediate"
                        icmp_info = "ICMP Time Exceeded - промежуточный узел"
                    else:
                        icmp_info = f"ICMP Type {response_pkt[ICMP].type}"
                
                # Добавляем информацию в allure
                hop_details = f"""
                TTL: {ttl}
                Ожидаемый IP: {expected_ip}
                Фактический IP: {actual_ip}
                Статус: {status}
                ICMP: {icmp_info}
                Правильность: {'✓' if is_correct else '✗'}
                """
                allure.attach(hop_details, name=f"Хоп {ttl} детали")
            
            # Сохраняем информацию о хопе
            hops_info.append({
                'ttl': ttl,
                'expected_ip': expected_ip,
                'actual_ip': actual_ip,
                'is_correct': is_correct,
                'is_destination': reached_destination,
                'status': status
            })
            
            if reached_destination:
                allure.step(f"Достигнута конечная точка: {actual_ip}")
                break
    
    return hops_info, reached_destination

@allure.epic("Сетевые тесты")
@allure.feature("Traceroute тестирование")
@allure.title("Traceroute к CE устройствам")
@allure.description("Тестирование маршрута до CE устройств через VLAN")
@pytest.mark.parametrize("ce_ip", IP_DST)
def test_traceroute_to_ce(ce_ip):
    
    allure.dynamic.title(f"Traceroute к {ce_ip}")
    allure.dynamic.description(f"Проверка маршрута до устройства {ce_ip}")
    
    with allure.step("Запуск traceroute"):
        hops_info, reached_destination = trace_route_to_ce(ce_ip, VLAN_ID, CE4_INTERFACE)
    
    # Проверка достижения цели
    with allure.step("Проверка достижения цели"):
        assert reached_destination, f"Цель {ce_ip} не достигнута"
        allure.attach(f"Цель {ce_ip} успешно достигнута", name="Результат")
    
    # Проверка правильности хопов
    with allure.step("Проверка правильности маршрута"):
        incorrect_hops = []
        for hop in hops_info:
            if not hop['is_correct'] and hop['expected_ip'] != "Unknown":
                incorrect_hops.append(f"Хоп {hop['ttl']}: ожидался {hop['expected_ip']}, получен {hop['actual_ip']}")
        
        # Добавляем таблицу с результатами в allure
        results_table = "TTL | Ожидаемый IP | Фактический IP | Статус | Правильность\n"
        results_table += "-" * 80 + "\n"
        for hop in hops_info:
            correctness = "✓" if hop['is_correct'] or hop['expected_ip'] == "Unknown" else "✗"
            results_table += f"{hop['ttl']} | {hop['expected_ip']} | {hop['actual_ip']} | {hop['status']} | {correctness}\n"
        
        allure.attach(results_table, name="Таблица результатов traceroute")
        
        # Проверяем, что все хопы правильные
        if incorrect_hops:
            error_msg = f"Найдены несоответствия в маршруте:\n" + "\n".join(incorrect_hops)
            allure.attach(error_msg, name="Ошибки маршрута")
            pytest.fail(error_msg)
    
    with allure.step("Итоговый результат"):
        allure.attach(f"""
        Traceroute к {ce_ip} выполнен успешно!
        Цель достигнута: {reached_destination}
        Количество хопов: {len(hops_info)}
        Все хопы соответствуют ожиданиям
        """, name="Итоговый отчет")

def create_network_topology_diagram():
    """Создает и добавляет в отчет схему сетевой топологии"""
    try:
        # Создаем граф
        dot = graphviz.Digraph(comment='Network Topology', 
                              graph_attr={'rankdir': 'TB', 'bgcolor': 'transparent', 'splines': 'ortho'},
                              node_attr={'style': 'filled', 'shape': 'box', 'fontname': 'Arial', 'fontsize': '10'},
                              edge_attr={'fontname': 'Arial', 'fontsize': '9'})
        
        # Добавляем узлы с правильным синтаксисом
        dot.node('Client', 'Клиент\n192.168.44.254', 
                **{'fillcolor': '#e6f3ff', 'color': '#1976d2'})
        
        # Маршрутизатор провайдера (PE)
        dot.node('PE_Router', 'PE Маршрутизатор\n(Провайдер)\n', 
                **{'fillcolor': '#fff3e0', 'color': '#f57c00', 'shape': 'diamond'})
        
        # Клиентские устройства CE
        dot.node('CE1', 'CE1\n192.168.43.2', 
                **{'fillcolor': '#e8f5e8', 'color': '#388e3c'})
        dot.node('CE2', 'CE2\n192.168.41.2', 
                **{'fillcolor': '#e3f2fd', 'color': '#1976d2'})
        dot.node('CE3', 'CE3\n192.168.42.2', 
                **{'fillcolor': '#fff8e1', 'color': '#ffa000'})
        
        # Добавляем связи
        dot.edge('Client', 'PE_Router', xlabel='VLAN 4028\n192.168.44.0/24')
        dot.edge('PE_Router', 'CE1', xlabel='192.168.43.0/24')
        dot.edge('PE_Router', 'CE2', xlabel='192.168.41.0/24')
        dot.edge('PE_Router', 'CE3', xlabel='192.168.42.0/24')
        
        # Генерируем PNG изображение
        png_data = dot.pipe(format='png')
        
        # Добавляем в allure отчет
        allure.attach(png_data, name="Сетевая топология", attachment_type=AttachmentType.PNG)
        
        # Также добавляем описание
        topology_description = """
        ## Сетевая топология тестовой среды
        
        **Архитектура сети:**
        - Клиент: 192.168.44.254 (тестовое устройство)
        - PE Маршрутизатор: 192.168.44.1 (маршрутизатор провайдера)
        - CE1: 192.168.43.2
        - CE2: 192.168.41.2 
        - CE3: 192.168.42.2
        
        **Сегменты сети:**
        - 192.168.44.0/24 - сеть клиента
        - 192.168.43.0/24 - сеть CE1
        - 192.168.41.0/24 - сеть CE2
        - 192.168.42.0/24 - сеть CE3
        
        **Назначение теста:** Проверка маршрутизации от клиента к CE устройствам через сеть провайдера
        """
        allure.attach(topology_description, name="Описание топологии", attachment_type=AttachmentType.TEXT)
        
    except Exception as e:
        allure.attach(f"Ошибка создания схемы: {str(e)}", name="Ошибка диаграммы")
        print(f"DEBUG: Ошибка создания диаграммы: {e}")

def create_traceroute_path_diagram(hops_info, target_ip):
    """Создает диаграмму пути traceroute для конкретного целевого IP"""
    try:
        dot = graphviz.Digraph(comment=f'Traceroute Path to {target_ip}',
                              graph_attr={'rankdir': 'TB', 'bgcolor': 'transparent', 'nodesep': '0.5'},
                              node_attr={'style': 'filled', 'shape': 'ellipse', 'fontname': 'Arial', 'fontsize': '9'})
        
        # Добавляем начальную точку (клиент)
        dot.node('Start', 'Клиент\n192.168.44.254', **{'fillcolor': '#e6f3ff'})
        
        # Добавляем хопы
        previous_node = 'Start'
        for i, hop in enumerate(hops_info):
            if hop['actual_ip'] and hop['actual_ip'] != '*':
                node_name = f'Hop{i+1}'
                status_color = '#c8e6c9' if hop['is_correct'] else '#ffcdd2'
                status_text = '✓' if hop['is_correct'] else '✗'
                
                # Определяем тип узла по IP
                node_label = f'{status_text} Хоп {i+1}\n{hop["actual_ip"]}'
                if hop['actual_ip'] == '192.168.44.1':
                    node_label = f'{status_text} PE Маршрутизатор\n{hop["actual_ip"]}'
                    status_color = '#fff3e0'
                
                dot.node(node_name, node_label, **{'fillcolor': status_color})
                dot.edge(previous_node, node_name, label=f'TTL={i+1}')
                previous_node = node_name
        
        # Добавляем целевую точку
        dot.node('Target', f'Цель CE\n{target_ip}', **{'fillcolor': '#fff9c4'})
        dot.edge(previous_node, 'Target', label='Достигнуто')
        
        png_data = dot.pipe(format='png')
        allure.attach(png_data, name=f"Путь до {target_ip}", attachment_type=AttachmentType.PNG)
        
    except Exception as e:
        allure.attach(f"Ошибка создания диаграммы пути: {str(e)}", name="Ошибка диаграммы")
        print(f"DEBUG: Ошибка создания диаграммы пути: {e}")

@allure.epic("Сетевые тесты")
@allure.feature("Сводный отчет")
@allure.title("Сводный отчет по всем traceroute тестам")
def test_traceroute_summary():
    """Сводный отчет по всем traceroute тестам"""

    create_network_topology_diagram()
    
    summary_results = {}
    
    for ce_ip in IP_DST:
        with allure.step(f"Тестирование {ce_ip}"):
            try:
                hops_info, reached = trace_route_to_ce(ce_ip, VLAN_ID, CE4_INTERFACE)

                create_traceroute_path_diagram(hops_info, ce_ip)
                
                # Считаем статистику
                correct_hops = sum(1 for hop in hops_info if hop['is_correct'] or hop['expected_ip'] == "Unknown")
                total_hops = len(hops_info)
                
                summary_results[ce_ip] = {
                    'success': reached and correct_hops == total_hops,
                    'reached': reached,
                    'correct_hops': correct_hops,
                    'total_hops': total_hops,
                    'path': [hop['actual_ip'] for hop in hops_info]
                }
                
            except Exception as e:
                summary_results[ce_ip] = {
                    'success': False,
                    'error': str(e)
                }
    