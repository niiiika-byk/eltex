import pexpect
import textfsm
import os
from tabulate import tabulate

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
                'Successfully connected',
                'Welcome',
                '#', '>',
                pexpect.TIMEOUT
            ], timeout=15)

            if index in (0, 1):  # Если получили приветствие
                child.expect(['#', '>'])
                child.sendline('\n') #вот почему оно тут нужно?
            elif index in (2, 3):
                pass
            else:
                print("Ошибка: не получено приглашение после входа")
                child.close()
                return None
            return child
            
    except Exception as e:
        print(f"Ошибка: {str(e)}")
        return None

session = telnet_connect('r4-g3', username, password)
if session:
    try:
        #приглашение перед отправкой
        session.expect(['#', '>'])
        session.sendline('show route vrf G3')
        
        #ожидаем эхо команды
        session.expect('show route vrf G3\r\n')

        index = session.expect(['Codes: ', r'#', pexpect.TIMEOUT], timeout=15)
        
        if index == 0:
            session.expect(r'0/ME5200S')
            full_output = session.before
            
            vrf = full_output.split('R - RIP')[-1].split('Total entries:')[0].strip()
            vrf = '\n'.join(line.strip() for line in vrf.splitlines())
            #print(vrf)

            #обработка вывода результата подключенных клиентов через vrf
            with open('templates/vrf_client.template') as template:
                fsm = textfsm.TextFSM(template)
                result = fsm.ParseText(vrf)
                print(tabulate(result, headers=fsm.header, tablefmt="grid"))
            #
                 
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