#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.实现一个mysql账户扫描类
'''
from i_scanner import *
try:
    import MySQLdb
except ImportError:
    print "You should install python-MySQLdb package."

class c_mysql_scanner(i_scanner):
    def __init__(self):
        self.protocol_name = 'MYSQL'

    def the_parser(self, host, user, passwd, protocol):
        args  = protocol.split(' ')
        if len(args) > 1:
            ports = args[1].split('+')
            for port in ports:
                self.touch_mysql_leak(host,int(port),user,passwd, protocol)
        else:
            self.touch_mysql_leak(host,3306,user,passwd, protocol)

    def touch_mysql_leak(self, hst, prt, account, pwd, protocol):
        try:
            conn=MySQLdb.connect(host=hst,port=prt, user=account,passwd=pwd)
            conn.close()
            self.record_leak_info(hst,prt,account,pwd, protocol, 'OK')
        except MySQLdb.OperationalError as (errno, strerror):
            if errno == 1045:
                #print '\tpassword or account error:[', strerror, '].'
                return errno
            elif errno == 2003:
                #print '\t,host or error:[', strerror, '].'
                return errno
        #except:
            #print 'error.'
            #return -1

def main():
    pass

if __name__ == "__main__":
    main()
