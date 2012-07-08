#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.
2.
3.
'''
import platform
import os
import time
import threading

class c_log_manager:
    def __init__(self, the_dir='./output/', the_type='txt'):
        if os.path.isdir(the_dir):
            self.output_dir   = the_dir
        else:
            self.output_dir   = os.getcwd()

        self.output_type  = the_type
        self.dir_splitter = '/'
        self.the_file_name=None
        self.the_file_handle=None

        sys = platform.system().upper()
        if 'LINUX' == sys[:5]:
            self.dir_splitter = '/'
        else:
            self.dir_splitter = '\\'

        file_name = time.strftime('%YY%mM%dD%HH')+'.'+self.output_type
        if self.output_dir[len(self.output_type)-1] == self.dir_splitter:
            self.the_file_name = self.output_dir + file_name
        else:
            self.the_file_name = self.output_dir + self.dir_splitter + file_name

        self.the_file_handle = open(self.the_file_name, 'a+')

    def __del__(self):
        if self.the_file_handle != None:
            self.the_file_handle.close()
            self.the_file_handle = None

    def record_str(self, str_info):
        try:
            str_info += '\n'
            self.the_file_handle.writelines(str_info)
            self.the_file_handle.flush()
        finally:
            pass

    def record_leak_info(self,host,port,user,passwd,protocol,leak_info=''):
        #global lock
        #lock.acquire()
        try:
            line = '\t\t'+leak_info+':[FIND PASSWD],['+host+']['+str(port)+']:['+user+']:['+passwd+']:['+protocol,'].\n'
            self.the_file_handle.writelines(line)
            self.the_file_handle.flush()
        finally:
            pass
            #lock.release()

def main():
    pass
    outputmgr = c_output_manager()
    outputmgr.record_leak_info('localhost', '80','admin','0123','http','your password is leak.')
    outputmgr.record_leak_info('127.0.0.1', '22','root','root','ssh','your password is leak.')
    outputmgr.record_leak_info('192.168.0.1', '3306','root','mysql','mysqlr','you password is leak.')

if __name__ == "__main__":
    main()
