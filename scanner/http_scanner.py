#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.实现一个http扫描类
'''
from i_scanner import *
import httplib,urllib

class c_http_scanner(i_scanner):
    def __init__(self):
        self.protocol_name = 'HTTP'

    def the_parser(self, host, user, passwd, protocol):
        args  = protocol.split(' ')
        if len(args) > 1:
            ports = args[1].split('+')
            for port in ports:
                self.touch_http_leak(host,int(port),user,passwd, protocol)
        else:
            self.touch_http_leak(host,80,user,passwd, protocol)

    def touch_http_leak(self,host,port, user, passwd, protocol):
        try:
            args  = protocol.split(' ')
            if len(args) > 2:
                sub_protocols = args[2].split('+')
                if len(sub_protocols) > 1:
                    sub_prtcl = sub_protocols[0].strip().upper()
                    if 'GET' == sub_prtcl:
                        self.touch_http_get_leak(host,port,user,passwd, protocol)
                    elif 'POST' == sub_prtcl:
                        self.touch_http_post_leak(host,port,user,passwd, protocol)
                    else:
                        str_info = '\tWe have not implement http ['+sub_prtcl+'] scanner, welcome you do it :)'
                        self.record_str(str_info)
            else:
                self.touch_http_get_leak(host,port,user,passwd, protocol)

        except IndexError:
            str_info = 'HTTP SCAN Index ERROR'
            self.record_str(str_info)
            return -1

    def touch_http_get_leak(self,host,port,user,passwd, protocol):
        self.record_leak_info(host,port,user,passwd, protocol, 'TEST')

    def touch_http_post_leak(self,host,port,user,passwd, protocol):
        try:
            url     = protocol.split(' ')[2].split('+')[1]
            params  = urllib.urlencode({'login':user,'password':passwd,'submit':'Login'})
            headers = {'Accept':'text/html,*/*','Host':host,'Referer':'localhost','User-Agent':'XU'}

            conn = httplib.HTTPConnection(host,port,timeout = 1)
            conn.request('POST',url,params,headers)
            res = conn.getresponse()
            str_info = 'RETURN INFO:'+str(res.status)+res.reason
            self.record_str(str_info)
            if res.status == 302:
                hd = res.getheaders()
                str_info = '\nHEADER:'+hd+'\nMESSAGE:'+res.msg
                self.record_str(str_info)
            elif res.status == 200:
                hd = res.getheaders()
                str_info = '\nHEADER:'+hd+'\nMESSAGE:'+res.msg
                self.record_str(str_info)
            conn.close()
            #self.record_leak_info(host,port,user,passwd, protocol, 'TEST')
        except IndexError:
            str_info = 'HTTP SCAN Index ERROR'
            self.record_str(str_info)
            return -1

def main():
    http_scanner = c_http_scanner()
    http_scanner.the_parser(host='localhost',user='admin',passwd='123456',protocol='http 80+8080')
    pass

if __name__ == "__main__":
    main()
