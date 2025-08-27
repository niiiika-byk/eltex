from tcp_handshake import *

def create_tcp_ack_packet(sport, seq, ack):
    """Создает TCP пакет только с ACK флагом"""
    return Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
        sport=sport,
        dport=TELNET_PORT,
        seq=seq,
        ack=ack,
        flags="A"
    )

def create_telnet_data_packet(data, sport, seq, ack):
    """ Создает IP/TCP пакет с TELNET данными """
    return Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
        dport=TELNET_PORT,
        sport=sport,
        flags='PA',   # PSH + ACK
        seq=seq,
        ack=ack
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
    """Минимальная обработка TELNET опций - всегда отправляем стандартный ответ"""
    if Raw in packet and b'\xff' in packet[Raw].load:
        print("\nОбнаружены TELNET опции, отправляем стандартный ответ")
        
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

def authenticate_telnet(connection_params):
    """Выполняет аутентификацию в TELNET сессии и возвращает (success, seq, ack)"""
    try:
        print("Пытаюсь выполнить аутентификацию...")
        seq = connection_params['seq']
        ack = connection_params['ack']

        #получение пакета с данными, конкретно опции telnet

        response = sniff_telnet_response(src_port, timeout=3)
        
        if response:
            server_packet = response[0]
            print(f"Получен пакет с опциями")
            
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
            print("\nОтправляем ACK для подтверждения TELNET опций...")
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

        print("\nОжидаем ЭХО логина от сервера...")
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
        print("\nОжидаем ЭХО пароля от сервера...")
        echo_response = sniff_telnet_response(src_port, timeout=3)

        if echo_response:
            echo_packet = echo_response[0]
            
            echo_length = 0
            if Raw in echo_packet:
                echo_data = echo_packet[Raw].load.decode('utf-8', errors='ignore')
                echo_length = len(echo_packet[Raw].load)
                print(f"ЭХО пароля: {repr(echo_data)}")
            else:
                echo_length = 1
            
            ack = echo_packet[TCP].seq + echo_length
            print(f"ACK после эхо пароля: {ack}")
            
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
            
            # Проверяем наличие welcome или приглашения
            if any(marker in all_data for marker in [">", "#", "Welcome", "Successfully", "Last login"]):
                print(f"Аутентификация успешна! Полученные данные: {repr(all_data)}")
                return True, seq, ack
                
            # Если это просто \r\n или пустые данные, продолжаем ждать
            if server_data.strip() in ["", "\r\n"]:
                print("Получены служебные данные, продолжаем ожидание...")
                continue
                
            print(f"Промежуточные данные: {repr(all_data)}")

        print(f"Финальные полученные данные: {repr(all_data)}")

        if any(marker in all_data for marker in [">", "#", "Welcome", "Successfully"]):
            print("Аутентификация успешна!")
            return True, seq, ack
        else:
            print("Аутентификация завершена, но не обнаружено приглашение")
            return True, seq, ack  # или False в зависимости от требований
        
    except Exception as e:
        print(f"Ошибка при аутентификации: {e}")
        import traceback
        traceback.print_exc()
        return False, seq, ack


# Пример использования
if __name__ == "__main__":
    parametrs = telnet_connection_autoriz()
    if parametrs != None:
        auth_result, seq, ack = authenticate_telnet(parametrs)
        fin_packet = Ether(src=MAC_SRC, dst=MAC_DST) / IP(src=IP_SRC, dst=IP_DST) / TCP(
                    dport=TELNET_PORT,
                    sport=src_port,
                    seq=seq,
                    ack=ack,
                    flags='FA',  # FIN + ACK
                )
        sendp(fin_packet, iface="enp1s0", verbose=0)
        print("FIN пакет отправлен для закрытия сессии")
        ack_packet = create_tcp_ack_packet(src_port, seq, ack)
        sendp(ack_packet, iface="enp1s0", verbose=0)

    else:
        print ("Не удалось получить параметры соединения")