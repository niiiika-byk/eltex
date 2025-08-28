from tcp_handshake import *
from create_packet import *

def authenticate_telnet(connection_params):
    """Выполняет аутентификацию в TELNET сессии и возвращает (success, seq, ack)"""
    try:
        print("Пытаюсь выполнить аутентификацию...")
        seq = connection_params['seq']
        ack = connection_params['ack']

        connection_params = {}

        #получение пакета с данными, конкретно опции telnet

        response = sniff_telnet_response(src_port, timeout=3)
        
        if response:
            server_packet = response[0]
            print(f"\nПолучен пакет с опциями")
            
            data_length = 0
            if Raw in server_packet:
                data_length = len(server_packet[Raw].load)
                
            # Обновляем ACK на основе полученных данных
            ack = server_packet[TCP].seq + data_length
            
            # Обрабатываем TELNET опции
            has_options, options_length = handle_telnet_options(server_packet, src_port, seq, ack)
            
            if has_options:
                seq += options_length
            
            # ACK с обновленным значением
            print("Отправляем ACK для подтверждения TELNET опций...")
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)

        #ждем приглашение login

        print("\nОжидаем приглашение login...")
        response = sniff_telnet_response(src_port, timeout=3)
        
        if response:
            server_packet = response[0]
            
            # Рассчитываем длину данных
            data_length = 0
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                data_length = len(server_packet[Raw].load)
            else:
                data_length = 1
            
            # Обновляем ack
            ack = server_packet[TCP].seq + data_length

            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)

        #отправляем логин

        username_data = USERNAME + "\r\n"
        username_packet = create_telnet_data_packet(username_data, src_port, seq, ack)
        sendp(username_packet, iface="enp1s0", verbose=0)
        
        seq += len(username_data)
        
        #ждем ЭХО логина от сервера

        print("Ожидаем ЭХО логина от сервера...")
        echo_response = sniff_telnet_response(src_port, timeout=3)
        
        if echo_response:
            echo_packet = echo_response[0]
            
            # Обрабатываем эхо
            echo_length = 0
            if Raw in echo_packet:
                echo_data = echo_packet[Raw].load.decode('utf-8', errors='ignore')
                echo_length = len(echo_packet[Raw].load)
            else:
                echo_length = 1

            ack = echo_packet[TCP].seq + echo_length

            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("Подтверждено получение эхо логина")
        
        #ждем запрос пароля
    
        print("\nОжидаем запрос пароля...")
        response = sniff_telnet_response(src_port, timeout=5)
        
        if not response:
            print("Не получен запрос пароля")
            return False, seq, ack
        
        server_packet = response[0]

        data_length = 0
        if Raw in server_packet:
            server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
            data_length = len(server_packet[Raw].load)
        else:
            data_length = 1
        
        ack = server_packet[TCP].seq + data_length
        
        ack_packet = create_tcp_ack_packet(src_port, seq, ack)
        sendp(ack_packet, iface="enp1s0", verbose=0)
        
        if "password" not in server_data.lower():
            print("Сервер не запросил пароль")
            return False, seq, ack
        
        #отправляем пароль

        password_data = PASSWORD + "\r\n"
        password_packet = create_telnet_data_packet(password_data, src_port, seq, ack)
        sendp(password_packet, iface="enp1s0", verbose=0)
        
        seq += len(password_data)
        
        #ждем ЭХО пароля от сервера
        
        print("Ожидаем ЭХО пароля от сервера...")
        echo_response = sniff_telnet_response(src_port, timeout=3)

        if echo_response:
            echo_packet = echo_response[0]
            
            echo_length = 0
            if Raw in echo_packet:
                echo_data = echo_packet[Raw].load.decode('utf-8', errors='ignore')
                echo_length = len(echo_packet[Raw].load)
                
            else:
                echo_length = 1
            
            ack = echo_packet[TCP].seq + echo_length
            
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("Подтверждено получение эхо пароля")

        # Ждем результат аутентификации - продолжаем слушать пока не получим welcome

        print("\nОжидаем результат аутентификации (может быть несколько пакетов)...")
        start_time = time.time()
        timeout = 15
        all_data = ""

        while time.time() - start_time < timeout:
            response = sniff_telnet_response(src_port, timeout=timeout - (time.time() - start_time))
            
            if not response:
                print("Таймаут ожидания результата аутентификации")
                break
                
            server_packet = response[0]
            
            # Обрабатываем данные пакета
            data_length = 0
            server_data = ""
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                data_length = len(server_packet[Raw].load)
                all_data += server_data
            else:
                data_length = 1
            
            ack = server_packet[TCP].seq + data_length
            
            # Отправляем подтверждение
            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            
            # Проверяем наличие приглашения ко вводу
            if any(marker in all_data for marker in ["#"]):
                print(f"Аутентификация успешна!")
                connection_params = {
                    'seq': seq,
                    'ack': ack
                }
                return True, connection_params
                
            # Если это просто \r\n или пустые данные, продолжаем ждать
            if server_data.strip() in ["", "\r\n"]:
                print("Получены служебные данные, продолжаем ожидание...")
                continue

        if any(marker in all_data for marker in ["Welcome", "Successfully"]):
            print("Аутентификация успешна!")
            connection_params = {
                    'seq': seq,
                    'ack': ack
                }
            return True, connection_params
        else:
            print("Аутентификация завершена, но не обнаружено приглашение")
            connection_params = {
                    'seq': seq,
                    'ack': ack
                }
            return False, connection_params
        
    except Exception as e:
        print(f"Ошибка при аутентификации: {e}")
        import traceback
        traceback.print_exc()
        connection_params = {
                    'seq': seq,
                    'ack': ack
                }
        return False, connection_params

def send_telnet_command(connection_params, command):
    """Функция для отправки команд"""
    try:
        seq = connection_params['seq']
        ack = connection_params['ack']
        connection_params = {}

        #отправляем команду
        
        full_command = command + "\r\n"
        print(f"\nОтправка команды: {repr(full_command)}")
        command_packet = create_telnet_data_packet(full_command, src_port, seq, ack)
        sendp(command_packet, iface="enp1s0", verbose=0)

        seq += len(full_command)
        
        #ждем ответ

        print("\nОжидаем ответ...")
        all_data = ""
        
        while True:
            response = sniff_telnet_response(src_port, timeout=5)
            if not response:
                break
                
            server_packet = response[0]
            
            if not (server_packet.haslayer(TCP) and server_packet[TCP].flags in ['PA', 'A']):
                continue
            data_length = len(server_packet[TCP].payload)            

            ack = server_packet[TCP].seq + data_length
            
            #получаем данные
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                all_data += server_data
                print(f"\nДанные: {repr(server_data)}")
            
            #подтверждаем получение

            ack_packet = create_tcp_ack_packet(src_port, seq, ack)
            sendp(ack_packet, iface="enp1s0", verbose=0)
            print("ACK отправлен")
            
            if any(marker in all_data for marker in ["#", ">"]):
                break
        
        connection_params = {
                'seq': ack,
                'ack': seq
            }

        return True, connection_params
        
    except Exception as e:
        print(f"\nОшибка: {e}")
        return False, connection_params


# Пример использования
if __name__ == "__main__":

    #настраиваем tcp соединение с сервером
    parametrs = telnet_connection()
    if parametrs != None:

        #входим в систему
        auth_result, connection_params = authenticate_telnet(parametrs)

        #запрашиваем кол-во пользователей
        auth_result, connection_params = send_telnet_command(connection_params, "show users")



        #закрываем tcp соединение
        close_telnet_connection(src_port, connection_params)

    else:
        print ("Не удалось получить параметры соединения")