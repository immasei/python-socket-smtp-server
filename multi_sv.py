from a import config_check
from a import process_email_content
from a import validate_ip
from a import abnf_email
import socket
import os
import secrets
import hmac
import base64
import signal
import sys
     
PERSONAL_ID = '10E5F3'
PERSONAL_SECRET = 'ef8c34a62a9af5abfec5fae03c02a347'

def set_up_email(email:dict):
    email['sender'] = ''
    email['recipient'] = []
    email['date'] = ''
    email['subject'] = []
    email['content'] = []
    email['name'] = ''
    email['challenge'] = '' #ascii decoded of b64 encoded challenge 
    return email
    
def default(req:dict):
    req['ehlo'] = False
    req['mail'] = False
    req['rcpt'] = False
    req['data'] = False 
    req['auth'] = False #authenticated
    req['authing'] = False  #during authentication
    req['quit'] = False
    return req

def ehlo(req:dict, ipv4:str, email:dict):
    #validate ipv4 addr
    if validate_ip(ipv4) == False:
        code = 501 #invalid ipv4
    else:
        code = 250 #ehlo OK

    if code == 250:
        req = default(req)
        email = set_up_email(email)
        req['ehlo'] = True
        return '250 127.0.0.1\r\n250 AUTH CRAM-MD5'
    else:
        return '501 Syntax error in parameters or arguments'

def auth(req:dict, email:dict, cram:str):
    if cram != 'CRAM-MD5':
        return '504 Unrecognized authentication type' #auth type not recognised
    if req['ehlo'] == False or req['auth'] == True or req['mail'] == True:
        return '503 Bad sequence of commands'
    else:
        req['authing'] = True
        mx = secrets.token_bytes(16) #16 byte challenge
        ms = base64.b64encode(mx) #pre-b64 challenge 
        email['challenge'] = base64.b64encode(ms) #b64 challenge to client
        #use b64 challenge to generate md5 key
        email['server_ans'] = PERSONAL_ID + ' ' + hmac.new(to_byte(PERSONAL_SECRET), ms, digestmod='md5').hexdigest()
        
        return f'334 {to_string(email["challenge"])}'

def authing(req:dict, email:dict, msg:str):
    req['authing'] = False
    if msg == '*': #reject auth
        return '501 Syntax error in parameters or arguments'
    else:
        try:
            #sever b64 decode 'client answer'
            client_ans = to_string(base64.b64decode(to_byte(msg)))
        except Exception:
            return '501 Syntax error in parameters or arguments'
        
        #compare with 'server answer'
        if client_ans != email['server_ans']:
            return '535 Authentication credentials invalid'
        else:
            req['auth'] = True
            return '235 Authentication successful'

def mail(req:dict, addr:str, email:dict):
    if req['ehlo'] == False or req['mail'] == True:
        code = 503 #wrong state
    else:
        if abnf_email(addr) == True:
            code = 250 #mail OK
        else:
            code = 501 #invalid source

    if code == 250:
        req['mail'] = True
        email['sender'] = addr
        return '250 Requested mail action okay completed'
    elif code == 503:
        return '503 Bad sequence of commands'
    else:
        return '501 Syntax error in parameters or arguments'

def rcpt(req:dict, addr:str, email:dict):
    if req['ehlo'] == False or req['mail'] == False:
        code = 503 #wrong state
    else:
        if abnf_email(addr) == True:
            code = 250 #rcpt OK
        else:
            code = 501 #invalid destination

    if code == 250:
        req['rcpt'] = True
        email['recipient'].append(addr)
        return '250 Requested mail action okay completed'
    elif code == 503: 
        return '503 Bad sequence of commands'
    else:
        return '501 Syntax error in parameters or arguments'

def data(req:dict, blank:str):
    if req['ehlo'] == False or req['mail'] == False or req['rcpt'] == False:
        code = 503 #wrong state
    elif blank != '':
        code = 501 #>1 parameter
    else:
        code = 354 #data OK
        req['data'] = True

    if code == 501:
        return '501 Syntax error in parameters or arguments'
    if code == 503:
        return '503 Bad sequence of commands'
    if code == 354:
        return '354 Start mail input end <CRLF>.<CRLF>'

def none(req:dict, content:str, email:dict, config: dict, order:int, pid:int):
    if content == '.':
        req['data'] = False   
        email = process_email_content(email)

        if req['auth'] == True:
            path = os.path.join(config['inbox_path'], f'[{pid}][{order:0>2}]auth.{email["name"]}')
        else:
            path = os.path.join(config['inbox_path'], f'[{pid}][{order:0>2}]{email["name"]}')

        #Save on disks
        f = open(path, 'w')
        f.write(f'From: {email["sender"]}\n')
        f.write(f'To: {",".join(email["recipient"])}\n')
        f.write(f'Date: {email["date"]}\n')
        f.write(f'Subject: {email["subject"]}\n')
        for i in email['content']:
            f.write(f'{i}\n')
        f.close()

        #reset state data & email data
        req['mail'] = False
        req['rcpt'] = False
        req['data'] = False 
        email = set_up_email(email)

        return '250 Requested mail action okay completed'
    else:
        email['content'].append(content)
        return '354 Start mail input end <CRLF>.<CRLF>'

def quit(req:dict, blank:str):
    if blank != '':
        return '501 Syntax error in parameters or arguments'
    else:
        req['quit'] = True
        return '221 Service closing transmission channel'
    
def rset(req:dict, blank:str, email:dict):
    if blank != '':
        return '501 Syntax error in parameters or arguments'
    else:
        req['mail'] = False
        req['rcpt'] = False
        req['data'] = False 
        req['auth'] = False 
        email = set_up_email(email)
        return '250 Requested mail action okay completed'

def noop(blank:str):
    if blank != '':
        return '501 Syntax error in parameters or arguments'
    else:
        return '250 Requested mail action okay completed'

def to_byte(string:str):
    return string.encode("ascii")

def to_string(bstring:bytes):
    return bstring.decode("ascii")

def send(c: socket.socket, content:str, order:int, pid:int):
    x = content + '\r\n'
    try:    
        c.send(to_byte(x))
    except Exception:
        print(f'[{pid}][{order:0>2}]' + 'S: Connection lost\r\n', end='', flush=True)
        return False
    #sigint
    if content == '421 Service not available, closing transmission channel':
        print(f'[{pid}][{order:0>2}]S: SIGINT received, closing\r\n', end='', flush=True)
        return

    #ehlo response from server
    if content == '250 127.0.0.1\r\n250 AUTH CRAM-MD5':
        print(f'[{pid}][{order:0>2}]S: 250 127.0.0.1\r\n[{pid}][{order:0>2}]S: 250 AUTH CRAM-MD5\r\n', end='', flush=True)
        return

    #else
    print(f'[{pid}][{order:0>2}]' + 'S: ' + x, end='', flush=True)

def recv(c: socket.socket, b: int, order:int, pid:int):
    try:
        response = c.recv(b)
    except Exception:
        print(f'[{pid}][{order:0>2}]' + 'S: Connection lost\r\n', end='', flush=True)
        return False

    if response == b'':
        # print(response)
        print(f'[{pid}][{order:0>2}]' + 'S: Connection lost\r\n', end='', flush=True)
        return False
    while True:
        if b'\r\n' in response:
            break
        else:
            remaining = c.recv(b)
            if remaining:
                response += remaining
            else:
                break

    print(f'[{pid}][{order:0>2}]' + 'C: ' + to_string(response), end='', flush=True)
    return to_string(response)

def chop(response:str, req:dict) -> tuple:
    if response.endswith('\r\n') == True:
        response = response[:-2]
    if req['authing'] == True:
            return 'AUTHING', response
    #no content, only cmd
    if req['data'] == False:
        if response.startswith('EHLO '):
            ipv4 = response[5:]
            return 'EHLO', ipv4
            
        elif response.startswith('EHLO'):
            ipv4 = response[4:]
            return 'EHLO', ipv4

        elif response.startswith('AUTH '):
            cram = response[5:]
            return 'AUTH', cram
            
        elif response.startswith('AUTH'):
            cram = response[4:]
            return 'AUTH', cram

        elif response.startswith('MAIL FROM:'):
            sender = response[10:]
            return 'MAIL', sender

        elif response.startswith('MAIL'):
            sender = response[4:]
            return 'MAIL', sender

        elif response.startswith('RCPT TO:'):
            rcpt = response[8:]
            return 'RCPT', rcpt

        elif response.startswith('RCPT'):
            rcpt = response[4:]
            return 'RCPT', rcpt

        elif response.startswith('DATA'):
            should_be_none = response[4:]
            return 'DATA', should_be_none
            
        elif response.startswith('QUIT'):
            should_be_none = response[4:]
            return 'QUIT', should_be_none

        elif response.startswith('RSET'):
            should_be_none = response[4:]
            return 'RSET', should_be_none

        elif response.startswith('NOOP'):
            should_be_none = response[4:]
            return 'NOOP', should_be_none

        else:
            return 'ERROR', None

    #content
    else:
        content = response
        return 'NONE', content

def signal_handler(signum, frame):  
    raise KeyboardInterrupt

def handle_client(c: socket.socket, i:int, pid:int, dat:dict):
    email = {}
    email = set_up_email(email)
    req = {}
    req = default(req)
    start = send(c, '220 Service ready', i, pid)
    if start == False:
        return

    while True:
        x = recv(c, 1024, i, pid)
        if x == False:
            break
                    
        cmds = chop(x, req)[0]
        msg = chop(x, req)[1]
        if cmds == 'EHLO':
            sending = ehlo(req, msg, email)
        elif cmds == 'AUTHING':
            sending = authing(req, email, msg)
        elif cmds == 'AUTH':
            sending = auth(req, email, msg)
        elif cmds == 'MAIL':
            sending = mail(req, msg, email)
        elif cmds == 'RCPT':
            sending = rcpt(req, msg, email)
        elif cmds == 'DATA':
            sending = data(req, msg)
        elif cmds == 'NONE':
            sending = none(req, msg, email, dat, i, pid)
        elif cmds == 'QUIT':
            sending = quit(req, msg)
        elif cmds == 'RSET':
            sending = rset(req, msg, email)
        elif cmds == 'NOOP':
            sending = noop(msg)
        else:
            sending = f'500 Syntax error, command unrecognized'
                    
        y = send(c, sending, i, pid)
        if y == False:
            return   

        #ed 1948 silent quit
        if req['quit'] == True:
            return

def main():
    try:
        dat = config_check('server')

        #Start TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        smtp = ('localhost', dat['server_port'])
        s.bind(smtp)
        s.listen(5)

        signal.signal(signal.SIGINT, signal_handler)  
            
        i = 1
        while True:
            c, address = s.accept()
            cid = os.fork()
                
            if cid == 0:
                pid = os.getpid()
                handle_client(c, i, pid, dat) #child handle
                break #parent leave child handle
            else:
                i += 1

    except KeyboardInterrupt:
        try: 
            send(c, '421 Service not available, closing transmission channel', i , pid)
        except Exception:
            sys.exit(0)
        sys.exit(0)

if __name__ == '__main__': 
    main()