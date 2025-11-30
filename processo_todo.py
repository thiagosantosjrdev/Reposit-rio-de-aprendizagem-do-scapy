# Esse código foi feito há muito tempo, portanto pode ter alguns maus hábitos.

from scapy.all import (
    Ether,
    IP,
    UDP,
    BOOTP,
    DHCP,
    RandINT,
    sendp
    )


class server_DHCP:
    def __init__(self, server_dhcp_ip='', client_mac='', client_xid=''):
        self.server_dhcp_ip = server_dhcp_ip if len(server_dhcp_ip) > 0 else None
        self.client_mac = client_mac if len(client_mac) > 0 else None
        self.client_xid = int(client_xid) if len(client_xid) > 0 else RandINT()
        if(self.server_dhcp == None):
            raise ValueError('[-] Não tem como simular sem o ip do servidor DHCP')
        if(self.client_mac == None):
            raise ValueError('[-] Não tem como simular sem o MAC do cliente')
        if(self.client_xid == None):
            raise ValueError('[-] Não tem como simular sem o XID do cliente')

    def discover(self) -> None:
        try:
            sendp(
                Ether(src=self.client_mac, dst="ff:ff:ff:ff:ff:ff")/
                IP(src="0.0.0.0",dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(op=1, xid=self.client_xid, chaddr=bytes.fromhex(self.client_mac.replace(":","")), yiaddr="0.0.0.0",ciaddr="0.0.0.0",siaddr=self.server_dhcp_ip)/
                DHCP(options=[
                    ('message-type','discover'),
                    ('req_param_list',[1,3,6]),
                    'end'
                ]),
                verbose=0
            )
        except Exception as e:
            print("[+] Houve um erro ao tentar executar o código discover:",e)
        print("[+] Pacote discover enviado com sucesso.")

    def offer(self,subnet_mask='255.255.255.0',offered_ip='') -> None:
        if len(offered_ip) < 1:
            raise ValueError("[+] Não tem como executar o código OFFER sem o IP oferecido.")
        else:
            sendp(
                Ether(dst=self.client_mac)/
                IP(src=self.server_dhcp_ip, dst="255.255.255.255")/
                UDP(sport=67, dport=68)/
                BOOTP(op=2, xid=self.client_xid, yiaddr=offered_ip,ciaddr="0.0.0.0",siaddr="192.168.3.1",chaddr=bytes.fromhex(self.client_mac.replace(":","")))/
                DHCP(options=[
                    ('message-type','offer'),
                    ('subnet_mask',subnet_mask),
                    ('lease_time',68400),
                    ('name_server','192.168.3.1'),
                    ('server_id','192.168.3.1'),
                    ('router','192.168.3.1'),
                    'end'
                ]),
                verbose=0
            )

    def nak(self) -> None:
        sendp(
            Ether(dst=self.client_mac)/
            IP(src="192.168.3.1",dst="255.255.255.255")/
            UDP(sport=67, dport=68)/
            BOOTP(op=2, xid=self.client_xid, chaddr=bytes.fromhex(self.client_mac.replace(":","")), yiaddr="0.0.0.0",ciaddr="0.0.0.0",siaddr="0.0.0.0")/
            DHCP(options=[
                ('message-type','nak'),
                'end'
            ]),
            verbose=0
        )

    def decline(self, offered_ip='') -> None:
        if len(offered_ip) < 1:
            raise ValueError("[+] Não tem como executar o código OFFER sem o IP oferecido.")
        else:
            sendp(
                Ether(src=self.client_mac, dst=self.server_dhcp_ip)/
                IP(src="0.0.0.0",dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(op=1, chaddr=bytes.fromhex(self.client_mac.replace(":","")), yiaddr=offered_ip, siaddr="0.0.0.0")/
                DHCP(options=[
                    ('message-type','decline'),
                    ('server_id',self.server_dhcp_ip),
                    ('requested_addr',offered_ip),
                    'end'
                ]),
                verbose=0
            )

    def request(self, offered_ip='') -> None:
        if len(offered_ip) < 1:
            raise ValueError("[+] Não tem como executar o código OFFER sem o IP oferecido.")
        else:
            sendp(
                Ether(src=self.client_mac, dst="ff:ff:ff:ff:ff:ff")/
                IP(src="0.0.0.0",dst="255.255.255.255")/
                UDP(sport=68, dport=67)/
                BOOTP(op=1, xid=self.client_xid, yiaddr=offered_ip, ciaddr="0.0.0.0",siaddr="0.0.0.0",flags=0x8000,chaddr=bytes.fromhex(self.client_mac.replace(":","")))/
                DHCP(options=[
                    ('message-type','request'),
                    ('requested_addr',offered_ip),
                    ('server_id',self.server_dhcp_ip),
                    'end'
                ]),
                verbose=0
            )

    def ack(self) -> None:
        sendp(
            Ether(dst=self.client_mac)/
            IP(src="192.168.3.1",dst="255.255.255.255")/
            UDP(sport=67,dport=68)/
            BOOTP(op=2, xid=self.client_xid, chaddr=bytes.fromhex(self.client_mac.replace(":","")))/
            DHCP(options=[
                ('message-type','ack'),
                ('lease_time',86400),
                ('server_id',self.server_dhcp_ip),
                ('router',self.server_dhcp_ip),
                ('subnet_mask','255.255.255.0'),
                'end'
            ]),
            verbose=0

        )
