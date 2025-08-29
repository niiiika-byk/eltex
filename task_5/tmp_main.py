from tcp_handshake import *
from autorization import *
from send_command import *
import os
import random
import threading
import allure
import pytest
import time
from allure_commons.types import AttachmentType

# Конфигурация маршрутизатора
IP_DST = "192.168.17.12"
IP_SRC = "192.168.17.13"
MAC_SRC = "de:ad:be:af:00:55"
MAC_DST = "68:13:e2:d8:01:05" 
TELNET_PORT = 23
MAX_SESSION = 20

# Функция для скриншота (в контексте сетевого тестирования - логирование пакетов)
def take_network_snapshot(name="network_snapshot"):
    """Создает текстовый снапшот состояния сети"""
    snapshot_data = f"Network snapshot: {name}\nTimestamp: {time.time()}"
    allure.attach(snapshot_data, name=name, attachment_type=AttachmentType.TEXT)

# Функция для запуска одной сессии
@allure.step("Запуск Telnet сессии")
def run_telnet_session(session_id):
    try:
        with allure.step(f"Сессия {session_id}: Установка TCP соединения"):
            params = telnet_connection()
            if params is None:
                allure.attach("Не удалось установить TCP соединение", 
                             name=f"session_{session_id}_tcp_fail", 
                             attachment_type=AttachmentType.TEXT)
                return False
            
            take_network_snapshot(f"session_{session_id}_after_handshake")

        with allure.step(f"Сессия {session_id}: Аутентификация"):
            auth_result, connection_params = authenticate_telnet(params)
            
            if not auth_result:
                allure.attach("Ошибка аутентификации", 
                             name=f"session_{session_id}_auth_fail", 
                             attachment_type=AttachmentType.TEXT)
                return False
            
            take_network_snapshot(f"session_{session_id}_after_auth")

        with allure.step(f"Сессия {session_id}: Выполнение команд"):
            # Запрашиваем количество пользователей
            result, connection_params = send_telnet_command(connection_params, "show users")
            if not result:
                allure.attach("Ошибка выполнения команды show users", 
                             name=f"session_{session_id}_show_users_fail", 
                             attachment_type=AttachmentType.TEXT)
                return False
                
            allure.attach(f"Команда: show users\nРезультат: {result}", 
                         name=f"session_{session_id}_show_users", 
                         attachment_type=AttachmentType.TEXT)
            
            # Запрашиваем действующую конфигурацию
            result, connection_params = send_telnet_command(connection_params, "show run interface te 0/0/5.353")
            if not result:
                allure.attach("Ошибка выполнения команды show run", 
                             name=f"session_{session_id}_show_run_fail", 
                             attachment_type=AttachmentType.TEXT)
                return False
                
            allure.attach(f"Команда: show run interface te 0/0/5.353\nРезультат: {result}", 
                         name=f"session_{session_id}_show_run", 
                         attachment_type=AttachmentType.TEXT)
            
            take_network_snapshot(f"session_{session_id}_after_commands")

        with allure.step(f"Сессия {session_id}: Закрытие соединения"):
            close_result = close_telnet_connection(connection_params['src_port'], connection_params)
            if not close_result:
                allure.attach("Ошибка при закрытии соединения", 
                             name=f"session_{session_id}_close_fail", 
                             attachment_type=AttachmentType.TEXT)
                return False
                
            take_network_snapshot(f"session_{session_id}_after_close")

        allure.attach("Сессия завершена успешно", 
                     name=f"session_{session_id}_success", 
                     attachment_type=AttachmentType.TEXT)
        return True

    except Exception as e:
        error_msg = f"Ошибка в сессии {session_id}: {str(e)}"
        allure.attach(error_msg, 
                     name=f"session_{session_id}_error", 
                     attachment_type=AttachmentType.TEXT)
        return False

@allure.feature("Многопоточные Telnet сессии")
@allure.title("Запуск множественных Telnet сессий")
def test_multiple_telnet_sessions():
    """Тест запуска множественных Telnet сессий параллельно"""
    
    with allure.step("Настройка тестового окружения"):
        allure.attach(f"Целевой IP: {IP_DST}", name="target_ip", attachment_type=AttachmentType.TEXT)
        allure.attach(f"Максимум сессий: {MAX_SESSION}", name="max_sessions", attachment_type=AttachmentType.TEXT)
    
    with allure.step("Запуск параллельных сессий"):
        threads = []
        session_results = []
        results_lock = threading.Lock()  # Блокировка для потокобезопасного доступа к списку
        
        def session_wrapper(session_id):
            """Обертка для запуска сессии с сохранением результата"""
            try:
                result = run_telnet_session(session_id)
                with results_lock:
                    session_results.append(result)
                allure.attach(f"Сессия {session_id} завершена с результатом: {result}", 
                             name=f"session_{session_id}_result", 
                             attachment_type=AttachmentType.TEXT)
            except Exception as e:
                with results_lock:
                    session_results.append(False)
                allure.attach(f"Необработанная ошибка в сессии {session_id}: {str(e)}", 
                             name=f"session_{session_id}_unhandled_error", 
                             attachment_type=AttachmentType.TEXT)
        
        # Запускаем сессии параллельно
        for i in range(3):  # Измените на нужное количество сессий
            thread = threading.Thread(
                target=session_wrapper, 
                args=(i+1,),
                name=f"Telnet-Thread-{i+1}"
            )
            thread.start()
            threads.append(thread)
            allure.attach(f"Запущена сессия {i+1}", 
                         name=f"session_{i+1}_started", 
                         attachment_type=AttachmentType.TEXT)
            time.sleep(0.1)  # Небольшая задержка между запуском потоков

        # Ждем завершения всех потоков с таймаутом
        timeout = 60  # 60 секунд таймаут
        start_time = time.time()
        
        for thread in threads:
            remaining_time = timeout - (time.time() - start_time)
            if remaining_time <= 0:
                allure.attach("Таймаут ожидания завершения потоков", 
                             name="threads_timeout", 
                             attachment_type=AttachmentType.TEXT)
                break
            thread.join(remaining_time)
    
    with allure.step("Проверка результатов"):
        # Проверяем, все ли потоки завершились
        active_threads = [thread for thread in threads if thread.is_alive()]
        if active_threads:
            allure.attach(f"Не все потоки завершились: {len(active_threads)} активных", 
                         name="active_threads_warning", 
                         attachment_type=AttachmentType.TEXT)
        
        # Подсчитываем успешные сессии
        successful_sessions = sum(1 for result in session_results if result is True)
        total_sessions = len(session_results)
        
        allure.attach(f"Успешных сессий: {successful_sessions}/{total_sessions}", 
                     name="session_summary", 
                     attachment_type=AttachmentType.TEXT)
        
        # Детальная информация о каждой сессии
        for i, result in enumerate(session_results, 1):
            status = "Успешно" if result else "Неуспешно"
            allure.attach(f"Сессия {i}: {status}", 
                         name=f"session_{i}_detailed_result", 
                         attachment_type=AttachmentType.TEXT)
        
        assert successful_sessions == total_sessions, f"Не все сессии завершились успешно. Успешно: {successful_sessions}, Всего: {total_sessions}"
