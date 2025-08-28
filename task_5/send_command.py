from tmp_main import *
from create_packet import *

def send_telnet_command(connection_params, command):
    """Функция для отправки команд с поддержкой постраничного вывода"""
    try:
        # Используем оригинальные параметры, а не перезаписываем их
        seq = connection_params['seq']
        ack = connection_params['ack']
        src_port = connection_params['src_port']

        full_command = command + "\r\n"
        print(f"\nОтправка команды: {repr(full_command)}")
        command_packet = create_telnet_data_packet(full_command, src_port, seq, ack)
        sendp(command_packet, iface="enp1s0", verbose=0)

        # Обновляем seq после отправки команды
        seq += len(full_command.encode('utf-8'))  # Учет байтов, а не символов

        print("\nОжидаем ответ...")
        all_data = ""
        last_data_time = time.time()  # Для таймаута после последнего пакета
        timeout_after_last_packet = 5  # Секунды ожидания после последнего пакета

        while True:
            # Захватываем пакеты с таймаутом
            response = sniff_telnet_response(src_port, timeout=2)
            if not response:
                # Если нет новых пакетов, проверяем таймаут
                if time.time() - last_data_time > timeout_after_last_packet:
                    break
                continue

            server_packet = response[0]
            last_data_time = time.time()  # Обновляем время получения данных

            # Пропускаем некорректные пакеты
            if not (server_packet.haslayer(TCP) and server_packet[TCP].flags in ['PA', 'A']):
                continue

            # Получаем длину данных
            data_length = len(server_packet[Raw].load) if Raw in server_packet else 0
            ack = server_packet[TCP].seq + data_length  # Обновляем ack

            # Добавляем данные к результату
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                all_data += server_data
                print(f"\nДанные: {repr(server_data)}")

            # Отправляем ACK
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("ACK отправлен")

        # Формируем обновленные параметры соединения
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