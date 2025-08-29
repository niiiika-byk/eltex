from tmp_main import *
from create_packet import *

def send_telnet_command(connection_params, command):
    """Функция для отправки команд с обработкой постраничного вывода (more)"""
    try:
        seq = connection_params['seq']
        ack = connection_params['ack']
        src_port = connection_params['src_port']

        full_command = command + "\r\n"
        print(f"\nОтправка команды: {repr(full_command)}")
        command_packet = create_telnet_data_packet(full_command, src_port, seq, ack)
        sendp(command_packet, iface="enp1s0", verbose=0)

        seq += len(full_command.encode('utf-8'))

        print("\nОжидаем ответ...")
        all_data = ""
        last_data_time = time.time()
        timeout_after_last_packet = 5
        more_detected = False
        more_timeout = 3  # таймаут для ожидания продолжения вывода после отправки пробела

        while True:
            response = sniff_telnet_response(src_port, timeout=2)
            if not response:
                if time.time() - last_data_time > timeout_after_last_packet:
                    # Если был обнаружен more, но новых данных нет, выходим
                    if more_detected:
                        print("Таймаут после more - выход")
                        break
                    # Обычный таймаут без more
                    if time.time() - last_data_time > timeout_after_last_packet:
                        break
                continue

            server_packet = response[0]
            last_data_time = time.time()

            # пропускаем некорректные пакеты
            if not (server_packet.haslayer(TCP) and server_packet[TCP].flags in ['PA', 'A']):
                continue

            data_length = len(server_packet[Raw].load) if Raw in server_packet else 0
            ack = server_packet[TCP].seq + data_length

            # добавляем данные к результату
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                all_data += server_data
                
                # Проверяем наличие индикатора more (постраничного вывода)
                if '-- More --' in server_data or '- More -' in server_data or 'more' in server_data.lower():
                    print("Обнаружен индикатор 'more' - отправляем пробел для продолжения")
                    more_detected = True
                    
                    # Отправляем пробел для продолжения вывода
                    space_command = " "
                    space_packet = create_telnet_data_packet(space_command, src_port, seq, ack)
                    sendp(space_packet, iface="enp1s0", verbose=0)
                    seq += len(space_command.encode('utf-8'))
                    
                    # Сбрасываем таймер для ожидания продолжения данных
                    last_data_time = time.time()
                    continue

            # Отправляем ACK
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("ACK отправлен")
            
            # Если был обнаружен more и получены новые данные, сбрасываем флаг
            if more_detected and server_data.strip():
                more_detected = False

        updated_params = {
            'seq': seq,
            'ack': ack,
            'src_port': src_port
        }

        print(f"\nПолный ответ: {repr(all_data)}")
        return True, updated_params

    except Exception as e:
        print(f"\nОшибка: {e}")
        return False, connection_params