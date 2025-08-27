from tcp_handshake import *

def create_telnet_data_packet(data, sport, seq, ack):
    """ Создает IP/TCP пакет с TELNET данными """
    return Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
        dport=TELNET_PORT,
        sport=sport,  # Используем порт из handshake
        flags='PA',   # PSH + ACK
        seq=seq,      # seq из handshake
        ack=ack       # ack из handshake
    )/Raw(load=data)

def sniff_telnet_response(src_port, timeout=5):
    """ Ожидание ответ от TELNET сервера """
    return sniff(
        filter=f"tcp and host {IP_DST} and port {src_port}",
        count=1,
        timeout=timeout,
        iface="enp1s0"
    )

def handle_telnet_options(packet, src_port, seq, ack):
    """Обрабатывает TELNET опции (IAC, WILL, WONT, DO, DONT) и отправляет ответы"""
    if Raw in packet:
        data = packet[Raw].load
        
        # Проверяем на наличие TELNET команд (IAC байт = 255)
        if b'\xff' in data:
            print(f"Обнаружены TELNET опции: {data.hex()}")
            
            # Анализируем опции
            i = 0
            responses = []
            while i < len(data):
                if data[i] == 0xff:  # IAC
                    if i + 1 < len(data):
                        command = data[i + 1]
                        if command in [251, 252, 253, 254]:  # WILL, WONT, DO, DONT
                            if i + 2 < len(data):
                                option = data[i + 2]
                                print(f"TELNET: IAC {command} {option}")
                                
                                # Формируем ответ (обычно отвечаем WONT на DO и DONT на WILL)
                                if command == 253:  # DO
                                    response = bytes([255, 252, option])  # WONT
                                    responses.append(response)
                                elif command == 251:  # WILL
                                    response = bytes([255, 254, option])  # DONT
                                    responses.append(response)
                                
                                i += 3
                                continue
                    i += 2
                else:
                    i += 1
            
            # Отправляем ответы на опции
            if responses:
                response_data = b''.join(responses)
                print(f"Отправляем ответ на TELNET опции: {response_data.hex()}")
                
                # Используем функцию create_telnet_data_packet для создания пакета
                response_packet = create_telnet_data_packet(response_data, src_port, seq, ack)
                
                sendp(response_packet, iface="enp1s0", verbose=0)
                return True, len(response_data)
            
            return True, 0
    
    return False, 0

def authenticate_telnet(connection_params):
    """ Выполняет аутентификацию в TELNET сессии и возвращает (success, seq, ack) """
    try:
        print("Пытаюсь выполнить аутентификацию...")
        seq = connection_params['seq']
        ack = connection_params['ack']
        
        # Ждем приветственное сообщение от маршрутизатора
        print("Ожидаем приветственное сообщение...")
        response = sniff_telnet_response(src_port)
        
        if not response:
            print("Не получен ответ от сервера")
            return False, seq, ack
        
        server_packet = response[0]
        handle_telnet_options(server_packet)  # Обрабатываем TELNET опции если есть
        
        if Raw in server_packet:
            server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"Ответ сервера: {repr(server_data)}")
            
            # Обновляем ack на основе полученных данных
            ack = server_packet[TCP].seq + len(server_packet[Raw].load)
            
            # Проверяем, что сервер готов принимать данные
            if "login" in server_data.lower() or "username" in server_data.lower():
                print("Сервер запросил логин")
            else:
                print(f"Неожиданный ответ: {server_data}")
        else:
            print("Ответ без данных (TELNET опции?)")
            # Если нет данных, все равно обновляем ack
            ack = server_packet[TCP].seq + 1
        
        # Отправляем имя пользователя
        username_data = USERNAME + "\r\n"
        username_packet = create_telnet_data_packet(username_data, src_port, seq, ack)
        sendp(username_packet, iface="enp1s0", verbose=0)
        print(f"Отправлено имя пользователя: {repr(username_data)}")
        
        # Обновляем seq после отправки
        seq += len(username_data)
        
        # Ждем запрос пароля
        print("Ожидаем запрос пароля...")
        response = sniff_telnet_response(src_port)
        
        if not response:
            print("Не получен ответ после имени пользователя")
            return False, seq, ack
        
        server_packet = response[0]
        if Raw in server_packet:
            server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"Ответ сервера: {repr(server_data)}")
            
            if "password" not in server_data.lower():
                print("Сервер не запросил пароль")
                return False, seq, ack
            
            # Обновляем ack
            ack = server_packet[TCP].seq + len(server_packet[Raw].load)
        
        # Отправляем пароль
        password_data = PASSWORD + "\r\n"
        password_packet = create_telnet_data_packet(password_data, src_port, seq, ack)
        sendp(password_packet, iface="enp1s0", verbose=0)
        print(f"Отправлен пароль: {repr(password_data)}")
        
        seq += len(password_data)
        
        # Ждем результат аутентификации
        print("Ожидаем результат аутентификации...")
        response = sniff_telnet_response(src_port)
        
        if response:
            server_packet = response[0]
            if Raw in server_packet:
                server_data = server_packet[Raw].load.decode('utf-8', errors='ignore')
                print(f"Финальный ответ: {repr(server_data)}")
                
                # Обновляем ack на основе финального ответа
                ack = server_packet[TCP].seq + len(server_packet[Raw].load)
                
                # Проверяем успешность аутентификации
                if any(marker in server_data for marker in [">", "#", "Last login", "Welcome"]):
                    print("✅ Аутентификация прошла успешно!")
                    return True, seq, ack
                elif "incorrect" in server_data.lower() or "fail" in server_data.lower():
                    print("❌ Ошибка аутентификации: неверные учетные данные")
                    return False, seq, ack
                else:
                    print(f"Неизвестный ответ: {server_data}")
                    return False, seq, ack
        
        print("Аутентификация завершена (без четкого ответа)")
        return True, seq, ack
        
    except Exception as e:
        print(f"Ошибка при аутентификации: {e}")
        return False, seq, ack



# Пример использования
if __name__ == "__main__":
    parametrs = telnet_connection_autoriz()
    if parametrs != None:
        auth_result, seq, ack = authenticate_telnet(parametrs)
        fin_packet = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
                    dport=TELNET_PORT,
                    sport=src_port,
                    seq=seq,  # Текущий seq
                    ack=ack,  # Текущий ack
                    flags='FA',  # FIN + ACK
                )
        sendp(fin_packet, iface="enp1s0", verbose=0)
        print("FIN пакет отправлен для закрытия сессии")
    else:
        print ("Не удалось получить параметры соединения")