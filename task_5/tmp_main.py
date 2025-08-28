from tcp_handshake import *
from autorization import *
from send_command import *
import os
import random

# Конфигурация маршрутизатора
IP_DST = "192.168.17.12"
IP_SRC = "192.168.17.13"
MAC_SRC = "de:ad:be:af:00:55"
MAC_DST = "68:13:e2:d8:01:05" 
TELNET_PORT = 23

# Пример использования
if __name__ == "__main__":

    #настраиваем tcp соединение с сервером
    parametrs = telnet_connection()
    if parametrs != None:

        #входим в систему
        auth_result, connection_params = authenticate_telnet(parametrs)

        #запрашиваем кол-во пользователей
        auth_result, connection_params = send_telnet_command(connection_params, "show users")

        #запрашиваем действующую конфигурацию
        auth_result, connection_params = send_telnet_command(connection_params, "show running-config")


        #закрываем tcp соединение
        close_telnet_connection(connection_params['src_port'], connection_params)

    else:
        print ("Не удалось получить параметры соединения")