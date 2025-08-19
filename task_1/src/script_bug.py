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
        child.logfile = sys.stdout 
        
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

# Использование функции
session = telnet_connect('r1-g3', username, password)
if session:
    try:
        session.expect(['#', '>'])
        session.sendline('show version')
        session.expect(['#', '>'])

        session.expect(['Eltex ME5200S', 'ver.', '#', '>', pexpect.TIMEOUT], timeout=15)
        
        full_output = session.before + session.after
        print (full_output)
        if 'Eltex ME5200S' in full_output:
            print("\nРезультат команды:")
            print(full_output.split('show version')[-1].strip())
        else:
            print("\nНе удалось получить полный вывод команды")
            print("Получено:")
            print(full_output)


    except Exception as e:
        print(f"Ошибка выполнения команды: {str(e)}")
    
    finally:
        session.sendline('logout')
        session.expect(pexpect.EOF)
        session.close()