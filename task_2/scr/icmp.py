from scapy.all import IP, ICMP, sr1

def execute_icmp_check(ip):
    #создаем пакет для запроса ICMP echo
    icmp_packet = IP(dst=ip)/ICMP(type=8, code=0)/"Hello, Scapy!"

    #получаем ответ от сервера
    icmp_answer = sr1(icmp_packet, timeout=2, verbose=False)

    if icmp_answer:
        print(f"ICMP-reply от {ip} получен")
        icmp_answer.show()
        return True
    else:
        print(f"ICMP-reply от {ip} не получен")
        return False

