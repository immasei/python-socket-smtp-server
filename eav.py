from a import config_check
from a import process_email_content
import os
import socket
import sys
import signal

def set_up_email(email:dict):
    email['sender'] = ''
    email['recipient'] = []
    email['date'] = ''
    email['subject'] = []
    email['content'] = []
    email['name'] = ''
    email['auth'] = False
    return email
    
def to_byte(string:str):
    return string.encode("ascii")

def to_string(bstring:bytes):
    return bstring.decode("ascii")

def prep_message(string:str):
    if string.endswith('\r\n') == True:
        return string[:-2]
    return string

def update_email(fig: dict, email:dict, client:str, server:str):
    cc = prep_message(client)
    ss = prep_message(server)
    #client cannot send more than 1 email due to eav close at first QUIT
    if ss.startswith('221') == True:
        if cc.startswith('QUIT'):
            sys.exit(0)
    
    if ss.startswith('250') == True: 
        #ehlo && rset
        if cc.startswith('EHLO ') == True or cc.startswith('RSET') == True:
            email = set_up_email(email)
        #mail
        if cc.startswith('MAIL FROM:') == True:
            email['sender'] = cc[10:]
        #rcpt
        if cc.startswith('RCPT TO:') == True:
            email['recipient'].append(cc[8:])
        #.
        if cc == '.':
            email = process_email_content(email)

            if email['auth'] == True:
                path = os.path.join(fig['spy_path'], f'auth.{email["name"]}')
            else:
                path = os.path.join(fig['spy_path'], f'{email["name"]}')

            #write emails into spy_path
            f2 = open(path, 'w')
            f2.write(f'From: {email["sender"]}\n')
            f2.write(f'To: {",".join(email["recipient"])}\n')
            f2.write(f'Date: {email["date"]}\n')
            f2.write(f'Subject: {email["subject"]}\n')
            for i in email['content']:
                f2.write(f'{i}\n')
            f2.close()
        
    #auth
    if ss.startswith('235') == True:
        email['auth'] = True

    #data
    if ss.startswith('354') == True and cc.startswith('DATA') == False:
        email['content'].append(cc)

#eav as server
def send_to_client(s: socket.socket, content:str):
    x = content + '\r\n'
    try:    
        s.send(to_byte(x))
    except Exception:
        print('AC: Connection lost\r\n', end='', flush=True)
        return False
    if x.count('\r\n') == 1:
        print('AC: ' + x, end='', flush=True)
    else:
        print('AC: ' + x.split("\r\n", 1)[0] + '\r\n', end='', flush=True)
        print('AC: ' + x.split('\r\n', 1)[1], end='', flush=True)

#eav as server
def recv_from_client(s: socket.socket, b: int):
    try:
        response = s.recv(b)
    except Exception:
        print('AC: Connection lost\r\n', end='', flush=True)
        return False

    if response == b'':
        # print(response)
        print('AC: Connection lost\r\n', end='', flush=True)
        return False
    while True:
        if b'\r\n' in response:
            break
        else:
            remaining = s.recv(b)
            if remaining:
                response += remaining
            else:
                break
    
    print('C: ' + to_string(response), end='', flush=True)
    return to_string(response)

#eav as client
def send_to_server(s: socket.socket, content:str):
    x = content + '\r\n'
    try:    
        s.send(to_byte(x))
    except Exception:
        print('AS: Connection lost\r\n', end='', flush=True)
        sys.exit(3)
    
    print('AS: ' + x, end='', flush=True) #C

#eav as client
def recv_from_server(s: socket.socket, b: int):
    try:
        response = s.recv(b)
    except Exception:
        print('AS: Connection lost\r\n', end='', flush=True)
        sys.exit(3)

    if response == b'':
        # print(response)
        print('AS: Connection lost\r\n', end='', flush=True)
        sys.exit(3)

    while True:
        if b'\r\n' in response:
            break
        else:
            remaining = s.recv(b)
            if remaining:
                response += remaining
            else:
                break
 
    if to_string(response).count('\r\n') == 1:
        print('S: ' + to_string(response), end='', flush=True)
    else:
        print('S: ' + to_string(response).split("\r\n", 1)[0] + '\r\n', end='', flush=True)
        print('S: ' + to_string(response).split('\r\n', 1)[1], end='', flush=True)

    return to_string(response)

def signal_handler(signum, frame):  
    raise KeyboardInterrupt

def main():
    fig = config_check('spy')
    try:
        #AS | Start EAV_Server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        smtp_s = ('localhost', fig['client_port'])
        s.bind(smtp_s)
        s.listen(5)

        signal.signal(signal.SIGINT, signal_handler)

        while True:    
            #AS | Wait for connection
            sa, address = s.accept()

            #AC | Connect to real server
            ac = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ac.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ac.settimeout(10)
            smtp_c = ('localhost', fig['server_port'])
            try:
                # Connect to server
                ac.connect(smtp_c)
            except Exception:
                print('AS: Cannot establish connection', flush=True)
                sys.exit(3)

            email = {}
            email = set_up_email(email)

            start_sa = recv_from_server(ac, 1024)
            start_ac = send_to_client(sa, prep_message(start_sa))
            if start_sa == False or start_ac == False:
                continue

            while True:
                x = recv_from_client(sa, 1024)
                if x == False:
                    break

                y = send_to_server(ac, prep_message(x)) #sub another message to mess up
                if y == False:
                    break
                
                m = recv_from_server(ac, 1024) 
                if m == False:
                    break
                
                n = send_to_client(sa, prep_message(m)) #sub another message to mess up
                if n == False:
                    break

                update_email(fig, email, x, m)

    except KeyboardInterrupt:
        #ed 1882 just close
        exit()

if __name__ == '__main__':
    main()