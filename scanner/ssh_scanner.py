#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.实现一个ssh账户扫描类
'''
from i_scanner import *
try:
    import paramiko
except ImportError:
    print "You should install python-paramiko package."

class c_ssh_scanner(i_scanner):
    def __init__(self):
        self.protocol_name = 'SSH'

    def the_parser(self, host, user, passwd, protocol):
        args  = protocol.split(' ')
        if len(args) > 1:
            ports = args[1].split('+')
            for port in ports:
                self.touch_ssh_leak(host,int(port),user,passwd, protocol)
        else:
            self.touch_ssh_leak(host,22,user,passwd, protocol)

    def touch_ssh_leak(self, host,port, user, passwd, protocol):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host,port,username=user, password=passwd, timeout=1)
            self.record_leak_info(host,port,user,passwd, protocol, 'OK')
            client.close()
        except paramiko.SSHException, error:
            #print 'here error:',error
            return -1
        except paramiko.AuthenticationException:
            #print 'Author failed.'
            return -1
        except:
            return -1
def main():
    pass

if __name__ == "__main__":
    main()
