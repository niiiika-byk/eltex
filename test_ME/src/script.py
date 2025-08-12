import pexpect
import sys
import os
#import getpass

#password = getpass.getpass()
username = os.environ.get('ROUTER_USER')
password = os.environ.get('ROUTER_PASSWORD')

def telnet_connect(host, username, password):
    try:
        # Запуск telnet-сессии
        child = pexpect.spawn(f'telnet {host}')
        
        # Установка таймаута
        child.timeout = 30
        
        # Ожидание приглашения для ввода логина
        index = child.expect(['login:', pexpect.TIMEOUT, pexpect.EOF])
        
        if index == 0 or index == 1:
            child.sendline(username)
            child.expect('[Pp]assword:')
            child.sendline(password)
            
            # Проверка успешности входа
            index = child.expect(['#', '$', 'Login incorrect', pexpect.TIMEOUT])
            
            if index == 0 or index == 1:
                child.expect #
                print("Успешный вход в систему")
                return child
            else:
                print("Ошибка входа: неверный логин или пароль")
                child.close()
                return None
        else:
            print("Не удалось получить приглашение для ввода логина")
            child.close()
            return None
            
    except Exception as e:
        print(f"Ошибка: {str(e)}")
        return None

# Использование функции
session = telnet_connect('r1-g3', username, password)
if session:
    try:
        session.sendline('show version')  # Отправляем неполную команду
        # Ожидаем либо ошибку, либо приглашение
        session.expect(['0/', pexpect.TIMEOUT])
        print("Вывод команды:")
        print(session.before.decode('utf-8'))
        
    except Exception as e:
        print(f"Ошибка выполнения команды: {str(e)}")
    
    finally:
        session.sendline('logout')
        session.expect(pexpect.EOF)
        session.close()