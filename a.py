import sys
import os
import datetime
import re

# [S] = [MS S E]
# [A] = [All]
# [C] = [C]

# [S] validate ipv4 address
def validate_ip(ipv4:str):
    addr = ipv4.split('.')
    if len(addr) != 4:
        return False
    for i in addr:
        try:
            int(i)
        except Exception:
            return False
        if int(i) < 0 or int(i) > 255:
            return False
    return True

# [S] validate email address in ABNF form
def abnf_email(mailbox:str):
    if mailbox.count('@') != 1:
        return False
    
    if mailbox.startswith('<') == False or mailbox.endswith('>') == False:
        return False

    # * = 0 or more

    # atom = letdig *(letdig / '-')
    # letdig = alpha (lower ~ upper) / digit (0-9)

    # 1: DOT - STRING
    # dot_string = atom *("." atom)
    dot_string = mailbox.split('@')[0][1:]

    # . is between atom
    if dot_string.startswith('.') == True or dot_string.endswith('.') == True:
        return False

    # no dot, match 1 atom = ldig *(ldig / '-')
    # ed 1831
    if dot_string.count('.') == 0:
        atom = '[A-Za-z0-9]+[A-Za-z0-9-]*?'
        if(re.fullmatch(atom,dot_string)): 
            pass
        else:
            return False
    # have dot check each atom
    else:
        dot_split = dot_string.split('.')
        for i in dot_split:
            atom = '[A-Za-z0-9]+[A-Za-z0-9-]*?'
            if(re.fullmatch(atom,i)): 
                pass
            else:
                return False

    # * = 0 or more
    # 1* = 1 or more
    # [] = optional

    # letdig = alpha (lower ~ upper) / digit (0-9)
    # subdom = letdig [ *( ALPHA / DIGIT / "-" ) letdig ]

    # 2: DOMAIN
    # domain = (subdom 1*( '.' subdom))
    # domain = address-literal
    domain = mailbox.split('@')[-1][:-1] 

    #must has at least 1 .subdom 
    #ipv4 require at least 3. (handle later)
    if domain.count('.') == 0:
        return False

    # . is between subdom
    # . is between ipv4 number
    if domain.startswith('.') == True or domain.endswith('.') == True:
        return False

    #check each subdom
    dom_split = domain.split('.')
    dom = True
    for x in dom_split:
        subdom1 = '[A-Za-z0-9]+' #letdig
        subdom2 = '[A-Za-z0-9]+[A-Za-z|0-9|-]*?[A-Za-z0-9]+' #letdig [ldh-str]
        if(re.fullmatch(subdom1,x)): 
            pass
        elif(re.fullmatch(subdom2,x)): 
            pass
        else:
            dom = False
    
    if dom == False:
        #else: check ipv4 
        if domain.startswith('[') == False or domain.endswith(']') == False:
            return False
        #extract address
        ipv4 = domain[1:-1]
        if validate_ip(ipv4) == False:
            return False
        
    return True

# [A] Find sub-str in string
def find(auth:str, abspath:str):
    ver2 = abspath
    if auth == 'auth':
        ver2 = abspath.lower()
    if ver2.find(auth) != -1:
        return True
    else:
        False

# [S] update email content
def process_email_content(email:dict):
    if email['content'][0].startswith('Date: ') and email['content'][0] != 'Date: ':
        date = True
        email['date'] = email['content'][0][6:]
        email['content'].pop(0)
    else:
        date = False #missing - invalid
        email['date'] = ''
        email['name'] = 'unknown.txt'
        email['subject'] = ''

    if date == True:
        if rfc_5322(email['date']) == False:
            email['date'] = ''
            email['name'] = 'unknown.txt'
        else:
            email['name'] = f"{datetime.datetime.timestamp(datetime.datetime.strptime(email['date'], '%a, %d %b %Y %X %z')):.0f}.txt" 
        
        if email['content'][0].startswith('Subject: ') and email['content'][0] != 'Subject: ':
            email['subject'] = email['content'][0][9:]
            email['content'].pop(0)
        else:
            email['subject'] = ''

    return email

# [A] check config file
def config_check(x:str):
    
    #config path provided
    if len(sys.argv) != 2:
        sys.exit(1)

    #config path exists
    if os.path.exists(sys.argv[1]) == False:
        sys.exit(1)

    #parse config
    f = open(sys.argv[1], 'r')
    info = f.readlines()
    i = 0
    while i < len(info):
        #crop \n
        if info[i].endswith('\n') == True:
           info[i] = info[i][:-1]

        #missing '='
        if '=' not in info[i]:
            sys.exit(2)
        else:
            #inbox_path==~/inbox
            #ed 1556 filename not contain =
            info[i] = info[i].split('=')
            if len(info[i]) != 2:
                sys.exit(2)
        i += 1
    
    dat = {} #dictionary of property
    for i in info:
        if i[0] not in dat:
            dat[i[0]] = i[1]
        else:
            #repeat property
            sys.exit(2)

    #relative path to absolute path
    if 'inbox_path' in dat:
        if dat['inbox_path'].startswith('~/') == True:
            dat['inbox_path'] = dat['inbox_path'].replace('~','.', 1)
        dat['inbox_path'] = os.path.join(os.getcwd(), dat['inbox_path'])
        inbox = dat['inbox_path']
    if 'send_path' in dat:
        if dat['send_path'].startswith('~/') == True:
            dat['send_path'] = dat['send_path'].replace('~','.', 1)
        dat['send_path'] = os.path.join(os.getcwd(), dat['send_path'])
        send = dat['send_path']
    if 'spy_path' in dat:
        if dat['spy_path'].startswith('~/') == True:
            dat['spy_path'] = dat['spy_path'].replace('~','.', 1)
        dat['spy_path'] = os.path.join(os.getcwd(), dat['spy_path'])
        spy = dat['spy_path']

    #multiple *_path provided, must not equal
    try:
        if 'inbox_path' in dat and 'send_path' in dat and 'spy_path' in dat:
            if os.path.samefile(inbox, send) == True or os.path.samefile(inbox, spy) == True or os.path.samefile(send, spy) == True:
                sys.exit(2)
        elif 'inbox_path' in dat and 'send_path' in dat:
            if os.path.samefile(inbox, send) == True:
                sys.exit(2)
        elif 'inbox_path' in dat and 'spy_path' in dat:
            if os.path.samefile(inbox, spy) == True:
                sys.exit(2)
        elif 'send_path' in dat and 'spy_path' in dat:
            if os.path.samefile(send, spy) == True:
                sys.exit(2)
    except FileNotFoundError:
        pass
        
    #requirement for server | client | spy
    if x == 'server':
        #no server port/ inbox path
        if 'server_port' not in dat or 'inbox_path' not in dat:
            sys.exit(2)
        #inbox path not exist/ not a dir
        if os.path.exists(inbox) == False or os.path.isdir(inbox) == False:
            sys.exit(2)
        #inbox path not writable
        if os.access(inbox, os.W_OK) is not True:
            sys.exit(2)

    if x == 'client':
        #no server port/ send path
        if 'server_port' not in dat or 'send_path' not in dat:
            sys.exit(2)
        #send path not exist/ not a dir
        if os.path.exists(send) == False or os.path.isdir(send) == False:
            sys.exit(2)

        #nothing in send path: ed 1863 - exit code 0
        files = sorted(os.listdir(send)) 
        
        #send path files not readable
        i = 0
        while i < len(files):
            files[i] = os.path.join(send, files[i])
            i += 1
        for x in files:
            try:
                ed = open(x, 'r')
            except Exception:
                sys.exit(2)
            ed.close()

    if x == 'spy':
        #no server port/ client port/ spy path
        if 'server_port' not in dat or 'client_port' not in dat or 'spy_path' not in dat:
            sys.exit(2)
        #spy path not exist/ not a dir
        if os.path.exists(spy) == False or os.path.isdir(spy) == False:
            sys.exit(2)
        #inbox path not writable
        if os.access(spy, os.W_OK) is not True:
            sys.exit(2)

    #check port
    if 'client_port' in dat:
        try:
            #port is not int
            sport = int(dat['server_port'])
            cport = int(dat['client_port'])
        except Exception:
            sys.exit(2)
        
        dat['server_port'] = sport
        dat['client_port'] = cport
        #port should > 1024, server port and client port are different
        if sport <= 1024 or cport <= 1024 or sport == cport:
            sys.exit(2)
    else:
        try:
            #port is not int
            sport = int(dat['server_port'])
        except Exception:
            sys.exit(2)

        dat['server_port'] = sport
        #port should > 1024
        if sport <= 1024:
            sys.exit(2)

    return dat

# [A] check date time in rfc 5322 format
def rfc_5322(d):
    try:
        datetime.datetime.strptime(d, '%a, %d %b %Y %X %z')
    except ValueError:
        return False
    else:
        return True

# [C] validate email in send path
def valid_email(filepath):
    #all sub path under send_path
    files = sorted(os.listdir(filepath))
    i = 0
    while i < len(files):
        files[i] = os.path.join(filepath, files[i])
        i += 1

    out = []
    for email in files:
        #send_path contains dir
        if os.path.isfile(email) == False:
            #ed 1525 : only attempt to read regular files 
            continue

        f = open(email, 'r')
        f1 = f.readlines()
        f.close()

        #check if it's ASCII encoded
        invalid = False
        for i in f1:
            try:
                i.encode('ascii')
            except UnicodeDecodeError:
                invalid = True
                break
        if invalid == True:
            out.append(os.path.abspath(email))
            continue

        i = 0
        while i < len(f1):
            if f1[i].endswith('\n') == True:
                f1[i] = f1[i][:-1]
            i += 1

        #copy of f1, but strip()
        f2 = []
        for i in f1:
            f2.append(i.strip())
        
        #0: not enough info
        if len(f1) < 5:
            out.append(os.path.abspath(email))
            continue

        to_send = {} #contain email fields

        #1: Sender
        if f1[0].startswith('From: <') == False or f1[0].endswith('>') == False:
            out.append(os.path.abspath(email))
            continue
        
        to_send['sender'] = f2[0][6:]

        #2: Recipent
        if f1[1].startswith('To: <') == False or f1[1].endswith('>') == False:
            out.append(os.path.abspath(email))
            continue

        f2[1] = f2[1][4:].split(',')
        #multiple address not separated by commas
        if f1[1].count('<') != len(f2[1]) or f1[1].count('>') != len(f2[1]):
            out.append(os.path.abspath(email))
            continue
    
        invalid = False
        for i in f2[1]:
            if i[0] != '<' or i[-1]!= '>':
                invalid = True
                break
        if invalid == True:
            out.append(os.path.abspath(email))
            continue

        to_send['rcpt'] = f2[1]
        
        #3: check sending time
        if f1[2].startswith('Date: ') == False:
            out.append(False)
            continue

        #not in rfc_5322 format
        if rfc_5322(f1[2][6:]) == False:
            out.append(os.path.abspath(email))
            continue

        to_send['date'] = f1[2][6:]
        
        #4: check subject
        if f1[3].startswith('Subject: ') == False:
            out.append(os.path.abspath(email))
            continue
        #empty subject
        if f2[3] == 'Subject:':
            out.append(os.path.abspath(email))
            continue

        to_send['subj'] = f1[3][9:]
        to_send['content'] = f1[4:]
        to_send['path'] = os.path.abspath(email)
        if find('auth', to_send['path']) == True:
            to_send['auth'] = True
        else:
            to_send['auth'] = False
        out.append(to_send)
        # email exact spacing ed 1591

    return out