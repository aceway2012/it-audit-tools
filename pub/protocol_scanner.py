#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.实现一个初始化数据，调度工作到类
2.计划在本层次实现检测IP是否存活，端口是否开放，探测各个 端口对应协议；更新ip,port列表, 避免深层次到无畏扫描，提高针对性，效率。
3.做线程的分配工作
4.数据到输出定义
5.对操作层暴露Interface，已便和GUI/WEB/CMD解偶
'''
import threading
import log_manager
from scanner import mysql_scanner
from scanner import http_scanner
from scanner import ssh_scanner

MAX_THREAD_COUNT = 50

class c_thread_scanning(threading.Thread):
    def __init__(self, *scan_args):
        threading.Thread.__init__(self)
        self.scan_args = scan_args

    def run(self):
        max_idx = len(self.scan_args[0])
        for idx in range(max_idx):
            func     = self.scan_args[0][idx][0]
            host     = self.scan_args[0][idx][1]
            user     = self.scan_args[0][idx][2]
            passwd   = self.scan_args[0][idx][3]
            protocol = self.scan_args[0][idx][4]
            func(host, user,passwd, protocol)

class c_protocol_scanner:
    def __init__(self, host_file='./config/host_list.txt', user_file='./config/user_list.txt', passwd_file='./config/passwd_list.txt', protocol_file='./config/protocol_list.txt'):
        self.__host_list      = None
        self.__user_list      = None
        self.__passwd_list    = None
        self.__protocol_list  = None

        self.host_file       = host_file
        self.user_file       = user_file
        self.passwd_file     = passwd_file
        self.protocol_file   = protocol_file
        self.__update_data()

        self.scanner_list    = []
        self.scanned_count   = 0
        self.thread_list     = []

        self.log_mgr         = log_manager.c_log_manager()
        self.log_mgr.record_str('Protocol scanner log:')

    def set_data(self, host_list=['127.0.0.1'], user_list=['admin'], passwd_list=['123456'], protocol_list=['mysql']):
        self.__host_list      = host_list
        self.__user_list      = user_list
        self.__passwd_list    = passwd_list
        self.__protocol_list  = protocol_list
    def set_host_data(self, host_list=['127.0.0.1']):
        self.__host_list      = host_list
    def set_user_data(self, user_list=['admin']):
        self.__user_list      = user_list
    def set_passwd_data(self, passwd_list=['123456']):
        self.__passwd_list    = passwd_list
    def set_protocol_data(self, protocol_list=['mysql']):
        self.__protocol_list  = protocol_list

    def __update_data(self):
        self.load_host_data(self.host_file)
        self.load_user_data(self.user_file)
        self.load_passwd_data(self.passwd_file)
        self.load_protocol_data(self.protocol_file)

    def load_host_data(self, host_file):
        self.host_file      = host_file
        self.__host_list     = self.__load_data(self.host_file)
    def load_user_data(self, user_file):
        self.user_file      = user_file
        self.__user_list     = self.__load_data(self.user_file)
    def load_passwd_data(self, passwd_file):
        self.passwd_file    = passwd_file
        self.__passwd_list   = self.__load_data(self.passwd_file)
    def load_protocol_data(self, protocol_file):
        self.protocol_file  = protocol_file
        self.__protocol_list = self.__load_data(self.protocol_file)

    def __load_data(self, the_file, comment_flag='#'):
        lines = [line.rstrip() for line in open(the_file)]
        ret_lines = []
        for line in lines:
            if len(line) == 0: continue         #空行略过
            if len(line) == (line.lstrip()):    #行首有空格的略过
                ret_lines.append(line)
            else:
                line = line.lstrip()
                if line[0] != comment_flag:
                    ret_lines.append(line)
        return ret_lines

    def __del__(self):
        self.log_mgr.record_str('Quit scann job!')
        if self.thread_list is not None:
            for the_thread in self.thread_list:
                pass
        else:
            pass

    def append_protocol_scanner(self, scanner):
        for scnn in self.scanner_list:
            if scnn.protocol_name.strip().upper() == scanner.protocol_name.strip().upper():
                str_info = 'The protocol ['+scanner.protocol_name+'] has in the scanner containner.'
                self.log_mgr.record_str(str_info)
                return
        scanner.record_leak_info = self.log_mgr.record_leak_info
        scanner.record_str = self.log_mgr.record_str
        self.scanner_list.append(scanner)

    def run(self, thread_count=1):
        thread_count = int(thread_count)
        if thread_count > 50: thread_count = 50
        if thread_count < 1: thread_count = 1

        total_count = len(self.__protocol_list)*len (self.__host_list)*len(self.__user_list)*len(self.__passwd_list)
        while total_count < thread_count:
            thread_count = int(thread_count/4)
        if thread_count < 1: thread_count = 1

        per_thread_cnt = int(total_count/thread_count)

        info_vector = []
        self.scanned_count   = 0
        str_info = '\nSTART TO SCAN! Will scanned count:['+str(total_count)+'], work thread count:['+str(thread_count)+'].'
        self.log_mgr.record_str(str_info)
        for protocol in self.__protocol_list:
            prtcl = protocol.split(' ')[0].upper()
            found_scanner = False
            for scanner in self.scanner_list:
                if prtcl ==  scanner.protocol_name.strip().upper():
                    found_scanner = True
                    str_info = '\tStart to do protocol ['+prtcl+'] scan.'
                    self.log_mgr.record_str(str_info)
                    for host in self.__host_list:
                        for user in self.__user_list:
                            for passwd in self.__passwd_list:
                                #info_vector.append([scanner.the_parser,host,user,passwd, protocol])
                                scanner.the_parser(host,user,passwd, protocol)
                                self.scanned_count  += 1
                                #print protocol, host,user,passwd, self.scanned_count
                                if len(info_vector) % per_thread_cnt == 0:
                                    #the_thread = c_thread_scanning(info_vector)
                                    #self.thread_list.append(the_thread)
                                    #the_thread.start()
                                    info_vector = []
                                elif self.scanned_count == total_count:
                                    #the_thread = c_thread_scanning(info_vector)
                                    #self.thread_list.append(the_thread)
                                    #the_thread.start()
                                    info_vector = []
                    str_info = '\tHave finished protocol ['+prtcl+'] scan.'
                    self.log_mgr.record_str(str_info)
            if found_scanner == False:
                str_info = 'Have not implement the ['+prtcl+'] protocol Scanner! Welcome you do it :)'
                self.log_mgr.record_str(str_info)
        str_info = 'HAVE FINISHED SCAN!\n'
        self.log_mgr.record_str(str_info)

    def suspend(self):
        str_info = "\nSuspend now..."
        self.log_mgr.record_str(str_info)
        if self.thread_list is not None:
            for the_thread in self.thread_list:
                str_info = 'suspend thread:['+the_thread+']'
                self.log_mgr.record_str(str_info)
        else:
            str_info = 'thread id list is none.'
            self.log_mgr.record_str(str_info)

def main():
    the_scanner = c_protocol_scanner()
############################################################################
#####实现一种协议的扫描类后，只需要在这里实例化一个实例，然后追加到扫描容器内
    the_mysql_scanner = mysql_scanner.c_mysql_scanner()
    the_scanner.append_protocol_scanner(the_mysql_scanner)

    the_http_scanner = http_scanner.c_http_scanner()
    the_scanner.append_protocol_scanner(the_http_scanner)

    the_ssh_scanner = ssh_scanner.c_ssh_scanner()
    the_scanner.append_protocol_scanner(the_ssh_scanner)
############################################################################
    the_scanner.run(1)

if __name__ == "__main__":
    main()
