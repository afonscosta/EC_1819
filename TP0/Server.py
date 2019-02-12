# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import getpass
from security import *

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999
next_id = 0
ks_key = b''

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, key, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.key = key
    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        self.msg_cnt += 1
        #
        # ALTERAR AQUI COMPORTAMENTO DO SERVIDOR
        #        

        txt = decrypt(msg, self.key, str(self.id))
        print('%s : %r' % (self.id,txt))
        new_msg = encrypt(txt.upper(), self.key, str(self.id))
        #
        return new_msg if len(new_msg)>0 else None


def saveKSServer(ks_key, key, password):
    global next_id
    ks_content = encrypt(key + password, ks_key, str(next_id), True)
    saveFile('Server/keystoreS_' + str(next_id) + '.txt', ks_content)
    next_id += 1


def authSessionKey(msg):
    msg_split = msg.rsplit(b'|', 1)
    salt = msg_split[0][:16]
    password = msg_split[0][16:]
    ID = msg_split[1].decode()

    ks_content = decrypt(readFile('Server/keystoreS_' + ID + '.txt'), ks_key, ID, True)
    key = ks_content[:32]
    ks_password = ks_content[32:]
    session_key, salt = generate_key(key, salt)
    
    if password != ks_password:
        msg = b'ERROR - Wrong password'

    msg = b'SUCCESS - Authentication succeeded. Your User ID is ' + ID.encode()
    
    return ID, msg, session_key



#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#


@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt, ks_key
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    ####
    first = True
    ID = '-1'
    while first or msg[:5] == b'ERROR':
        if not first:
            print(ID + ': ' + msg.decode())
            writer.write(encrypt(msg.decode(), session_key, str(ID)))
        first = False

        msg = yield from reader.read(max_msg_size)

        if msg == b'' or msg == b'\n':
            break
        if msg[:10] == b'__REGIST__':
            key = os.urandom(32)
            # Supõem-se canal seguro
            writer.write(key + str(next_id).encode())
            password = msg[10:]
            saveKSServer(ks_key, key, password)
            msg = yield from reader.read(max_msg_size)

        ID, msg, session_key = authSessionKey(msg)
        

    if msg != b'' and msg != b'\n':
        print(ID + ' : ' + msg.decode())
        writer.write(encrypt(msg.decode(), session_key, str(ID)))
        srvwrk = ServerWorker(ID, session_key, addr)
    ####
        data = yield from reader.read(max_msg_size)
        while True:
            if not data: continue
            if data[:1]==b'\n': break
            data = srvwrk.process(data)
            if not data: break
            writer.write(data)
            yield from writer.drain()
            data = yield from reader.read(max_msg_size)
        print("[%s]" % srvwrk.id)

    writer.close()


def run_server(): 
    global ks_key
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        ####
        ks_pass = getpass.getpass()
        try:
            salt = readFile('Server/saltS.txt')
        except (FileNotFoundError, IOError):
            salt = os.urandom(16)
            saveFile('Server/saltS.txt', salt)
        ks_key, salt = generate_key(ks_pass.encode(), salt)
        ####
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')

run_server()