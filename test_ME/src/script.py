import pexpect
import sys
import os
import time

username = os.environ.get('ROUTER_USER')
password = os.environ.get('ROUTER_PASSWORD')

def telnet_connect(host, username, password):
    try:
        #запрос в консоль
        child = pexpect.spawn(f'telnet {host}', encoding='utf-8')
        
        #логирование для проверки выполнения скрипта
        #child.logfile = sys.stdout 
        
        #таймаут
        child.timeout = 30
        
        #ожидание приглашения
        index = child.expect(['login:', pexpect.TIMEOUT, pexpect.EOF])

        
        if index == 0 :
            child.sendline(username)
            child.expect('[Pp]assword:')
            child.sendline(password)
            
            #проверка успешности
            index = child.expect([
                'Successfully connected',  # Ожидаем сообщение о подключении
                'Welcome',                # Или приветствие
                '#', '>',                # Или сразу приглашение
                pexpect.TIMEOUT
            ], timeout=15)

            if index in (0, 1):  # Если получили приветствие
                child.expect(['#', '>'])  # Ждём окончательное приглашение
                child.sendline('\n')
            elif index in (2, 3):  # Если сразу получили приглашение
                pass  # Ничего не делаем
            else:  # Таймаут или ошибка
                print("Ошибка: не получено приглашение после входа")
                child.close()
                return None
            return child
            
    except Exception as e:
        print(f"Ошибка: {str(e)}")
        return None

session = telnet_connect('r1-g3', username, password)
if session:
    try:
        #приглашение перед отправкой
        session.expect(['#', '>'])
        session.sendline('show version')
        
        #ожидаем эхо команды
        session.expect('show version\r\n')
        
        # Теперь ждем именно маркер начала нужного нам вывода
        index = session.expect(['Eltex ', r'#', pexpect.TIMEOUT], timeout=15)
        
        if index == 0:  # Если нашли "Eltex ME5200S"
            session.expect(r'0/')
            full_output = session.before
            
            # Выводим результат между "Eltex ME5200S" и приглашением
            print("\nРезультат команды:")
            print("Eltex " + full_output.split("Eltex ")[-1].strip())
            
        elif index == 1:  # Если сразу получили приглашение
            print("\nКоманда не вернула ожидаемый вывод")
            print("Получено:", session.before)
            
        else:  # Таймаут
            print("\nТаймаут при ожидании вывода команды")
            print("Получено:", session.before)

    except Exception as e:
        print(f"Ошибка выполнения команды: {str(e)}")
    
    finally:
        session.sendline('logout')
        session.expect(pexpect.EOF)
        session.close()