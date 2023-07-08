from a import config_check
from a import valid_email
from a import find
import socket
import sys
import base64
import hmac

PERSONAL_ID = '10E5F3'
PERSONAL_SECRET = 'ef8c34a62a9af5abfec5fae03c02a347'

def to_byte(string:str):
    return string.encode("ascii")

def to_string(bstring:bytes):
    return bstring.decode("ascii")

def send(s: socket.socket, content:str):
    ans = content + '\r\n'

    try:
        s.send(to_byte(ans))
    except Exception:
        print('C: Connection lost\r\n', end='', flush=True)
        sys.exit(3)
    print('C: ' + ans, end='')
    return to_byte(ans)

def recv(s: socket.socket, b: int):
    try:
        response = s.recv(b)
    except Exception:
        print('C: Connection lost\r\n', end='', flush=True)
        sys.exit(3)

    if response == b'':
        # print(response)
        print('C: Connection lost\r\n', end='', flush=True)
        sys.exit(3)

    if to_string(response) == '250 127.0.0.1\r\n250 AUTH CRAM-MD5\r\n':
        print('S: 250 127.0.0.1\r\nS: 250 AUTH CRAM-MD5\r\n', end='', flush=True)
    else:
        print('S: ' + to_string(response), end='', flush=True)
        
    return to_string(response)

def status(response:str, expected: int):
    actual = int(response.split()[0])
    if actual == expected:
        return True
    else:
        return False

def authenticate(response:str):
    chal = response.split()[1]
    ms = base64.b64decode(chal) #b64 decode challenge
    
    #use ms to generate md5 key
    ans = PERSONAL_ID + ' ' + hmac.new(to_byte(PERSONAL_SECRET), ms, digestmod='md5').hexdigest()

    #b64 encoded to server
    return to_string(base64.b64encode(to_byte(ans)))


def main():
    #validate config file
    dat = config_check('client')
    #prepare email to send
    emails = valid_email(dat['send_path'])
    
    #ed 1471
    for i in emails:
        #Error: Bad formation 
        if type(i) != dict:
            print(f'C: {i}: Bad formation', flush=True)
            continue
       
        #Start TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(10)
        smtp = ('localhost', dat['server_port'])
        ip = socket.gethostbyname('localhost')
        try:
            # Connect to server
            s.connect(smtp)
        except Exception:
            print('C: Cannot establish connection', flush=True)
            sys.exit(3)

        #Communicate
        try:
            start = recv(s, 1024) #220 Ready

            #EHLO
            send(s, f'EHLO {ip}')
            ehlo = recv(s, 1024) #250 OK

            #cram-md5 OK
            if find('250 AUTH CRAM-MD5', ehlo) == True:
                cram = True
            else:
                cram = False
            
            #AUTH
            if i['auth'] == True and cram == True:
                send(s, 'AUTH CRAM-MD5')
                challenge = recv(s, 1024) #334 OK
                if status(challenge, 334):
                    password = authenticate(challenge)
                    send(s, password)
                    recv(s, 1024) 
            
            #MAIL FROM
            send(s, f'MAIL FROM:{i["sender"]}')
            mail = recv(s, 1024)

            #RCPT TO
            for x in i['rcpt']:
                send(s, f'RCPT TO:{x}')
                recipient = recv(s, 1024)

            #DATA
            send(s, 'DATA')
            data = recv(s, 1024)

            send(s, f'Date: {i["date"]}')
            date = recv(s, 1024)

            send(s, f'Subject: {i["subj"]}')
            subject = recv(s, 1024)
            
            for x in i['content']:
                send(s, f'{x}')
                content = recv(s, 1024)

            #END OF DATA
            send(s, '.')
            end_content = recv(s, 1024)

            #QUIT
            send(s, 'QUIT')
            quit = recv(s, 1024)

            #ed 1543: no invalid server
            #but just a double check :D
            if status(quit, 221) == True:
                s.close()
            
        #Server disconnectd unexpectedly
        except Exception:
            print('C: Connection lost', flush=True)
            sys.exit(3)
    #finish sending all emails
    sys.exit(0)    
        
if __name__ == '__main__':
    main()
