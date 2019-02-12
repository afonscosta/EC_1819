# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import os
import asyncio
import socket
import getpass
from security import *

conn_port = 8888
max_msg_size = 9999

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, ID, key, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.id = ID
        self.msg_cnt = 0

        # Guardar chave
        self.key = key

    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """

        if msg:
            self.msg_cnt +=1
            print('Received (%d): %r' % (self.msg_cnt , decrypt(msg, self.key, str(self.id))))

        print('\nInput (empty to finish): ', end='')

        plaintext = input()

        if plaintext:
            new_msg = encrypt(plaintext, self.key, str(self.id))
        else: 
            new_msg = plaintext
        
        return new_msg if len(new_msg)>0 else None


def generateKSClient(ks_pass, msg, password):
    ks_key, salt = generate_key(ks_pass.encode())
    key = msg[:32]
    ID = msg[32:].decode()

    ks_content = salt + encrypt(key + password, ks_key, ID, True)
    saveFile('Clients/keystoreC_' + ID + '.txt', ks_content)
    return ID, key

def getContentKSClient(ks_pass, ID):
    try:
        ks_content = readFile('Clients/keystoreC_' + ID + '.txt')
    except (FileNotFoundError, IOError):
        return None, None, b'ERROR - User ID not found'
    salt = ks_content[:16]
    crypto = ks_content[16:]
    ks_key, salt = generate_key(ks_pass.encode(), salt)
    ks_content = decrypt(crypto, ks_key, str(ID), True)
    
    if ks_content[:5] != b'ERROR':
        key = ks_content[:32]
        password = ks_content[32:]
        error = None
    else:
        key = None
        password = None
        error = ks_content

    return key, password, error


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)

    addr = writer.get_extra_info('peername')
    
    ####
    first = True
    while first or msg[:5] == b'ERROR':
        if not first:
            print(msg.decode() + '\n')
        first = False
        ID = input('User ID ("R" to regist, "" to finish): ')
        if ID == '':
            break
        ks_pass = getpass.getpass()

        if ID=='R':
            password = os.urandom(16)
            ## Supõe-se canal seguro nesta zona
            writer.write(b'__REGIST__' + password)
            msg = yield from reader.read(max_msg_size)
            ##
            ID, key = generateKSClient(ks_pass, msg, password)
            error = None
        else:
            key, password, error = getContentKSClient(ks_pass, ID)
        
        if key == b'' and password == b'':
            msg = b'ERROR - User ID not found'
        elif error:
            msg = error
        else:
            session_key, salt = generate_key(key)
            msg = salt + encrypt(password, session_key, ID, True) + b'|' + ID.encode()
            # msg = generate_mac(key, msg) + msg
            writer.write(msg)
            crypto = yield from reader.read(max_msg_size)
            msg = decrypt(crypto, session_key, ID, True)
        
    if ID != '':
        print(msg.decode())
        client = Client(ID, session_key, addr)
    ####
        msg = client.process()
        while msg:
            writer.write(msg)
            msg = yield from reader.read(max_msg_size)
            if msg:
                msg = client.process(msg)
            else:
                break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
