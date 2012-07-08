#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.设计编码界面, ok--2012-04-27
2.MySQL的账户安全审计
3.SSH的账户安全审计
4.ftp的账户安全审计
5.telnet的账户安全审计
6.WEB的账户安全审计
'''
from Tkinter import *
from Tkconstants import *
import tkFileDialog
import protocol_scanner
from scanner import mysql_scanner
from scanner import http_scanner
from scanner import ssh_scanner

class c_gui_audit_app:
    def __init__(self, master):
        self.the_scanner = protocol_scanner.c_protocol_scanner()
        #IP的选择操作
        #单IP
        ip_frame  = Frame(master, relief=RIDGE, borderwidth=2)
        ip_frame.pack(side=TOP)
        self.single_ip = IntVar()
        self.single_ip.set(1)
        self.ip_radio = Radiobutton(ip_frame, variable=self.single_ip,value=1, text="单IP:", width=8,anchor=W)
        self.ip_radio.pack(side=LEFT)
        self.ip_radio.bind('<Button-1>', self.choose_data)

        self.the_ip = StringVar()
        self.the_ip.set("127.0.0.1")
        self.ip_entry = Entry(ip_frame, textvariable=self.the_ip)
        self.ip_entry.pack(side=LEFT)
        #IP列表
        self.ip_list_radio = Radiobutton(ip_frame, variable=self.single_ip, value=0,text="IP列表:", width=8,anchor=W)
        self.ip_list_radio['state'] = NORMAL
        self.ip_list_radio.pack(side=LEFT)
        self.ip_list_radio.bind('<Button-1>', self.choose_data)

        self.the_ip_list = StringVar()
        self.the_ip_list.set("./config/host_list.txt")
        self.ip_file = Entry(ip_frame, textvariable=self.the_ip_list)
        self.ip_file['state'] = DISABLED
        self.ip_file.pack(side=LEFT)
        self.ip_button = Button(ip_frame, text='选择')#, command = self.choose_file)
        self.ip_button['command'] = lambda:self.choose_file('IP')
        self.ip_button['state'] = DISABLED
        self.ip_button.pack()

        #USER的选择操作
        #单USER
        user_frame = Frame(master, relief=RIDGE, borderwidth=2)
        user_frame.pack(side=TOP)
        self.single_user = IntVar()
        self.single_user.set(1)
        self.user_radio=Radiobutton(user_frame,variable=self.single_user,value=1,text="单账户:",width=8,anchor=W)
        self.user_radio.pack(side=LEFT)
        self.user_radio.bind('<Button-1>', self.choose_data)

        self.the_user = StringVar()
        self.the_user.set('root')
        self.user_entry = Entry(user_frame, textvariable=self.the_user)
        self.user_entry.pack(side=LEFT)
        #USER列表
        self.user_list_radio = Radiobutton(user_frame, variable=self.single_user, value=0,text="账户列表:", width=8,anchor=W)
        self.user_list_radio['state'] = NORMAL
        self.user_list_radio.pack(side=LEFT)
        self.user_list_radio.bind('<Button-1>', self.choose_data)
        self.the_user_list = StringVar()
        self.the_user_list.set("./config/user_list.txt")
        self.user_file = Entry(user_frame, textvariable=self.the_user_list)
        self.user_file['state'] = DISABLED
        self.user_file.pack(side=LEFT)
        self.user_button = Button(user_frame, text='选择')#, command = self.choose_file)
        self.user_button['command'] = lambda:self.choose_file('USER')
        self.user_button['state'] = DISABLED
        self.user_button.pack()

        #PASSWORD的选择操作
        #单PASSWD
        passwd_frame = Frame(master, relief=RIDGE, borderwidth=2)
        passwd_frame.pack(side=TOP)
        self.single_passwd = StringVar()
        self.single_passwd.set(1)
        self.passwd_radio=Radiobutton(passwd_frame,variable=self.single_passwd,value=1,text="单密码:",width=8,anchor=W)
        self.passwd_radio.pack(side=LEFT)
        self.passwd_radio.bind('<Button-1>', self.choose_data)
        self.the_passwd = StringVar()
        self.the_passwd.set('123456')
        self.passwd_entry = Entry(passwd_frame, textvariable=self.the_passwd)
        self.passwd_entry.pack(side=LEFT)
        #PASSWD列表
        self.passwd_list_radio = Radiobutton(passwd_frame, variable=self.single_passwd, value=0,text="密码列表:", width=8,anchor=W)
        self.passwd_list_radio['state'] = NORMAL
        self.passwd_list_radio.pack(side=LEFT)
        self.passwd_list_radio.bind('<Button-1>', self.choose_data)
        self.the_passwd_list = StringVar()
        self.the_passwd_list.set("./config/passwd_list.txt")
        self.passwd_file = Entry(passwd_frame, textvariable=self.the_passwd_list)
        self.passwd_file['state'] = DISABLED
        self.passwd_file.pack(side=LEFT)
        self.passwd_button = Button(passwd_frame, text='选择')#, command = self.choose_file)
        self.passwd_button['command'] = lambda:self.choose_file('PASSWD')
        self.passwd_button['state'] = DISABLED
        self.passwd_button.pack()

        #PROTOCOL的选择操作
        #单PROTOCOL
        protocol_frame = Frame(master, relief=RIDGE, borderwidth=2)
        protocol_frame.pack(side=TOP)
        self.single_protocol = IntVar()
        self.single_protocol.set(1)
        self.protocol_radio=Radiobutton(protocol_frame,variable=self.single_protocol,value=1,text="单协议:",width=8,anchor=W)
        self.protocol_radio.pack(side=LEFT)
        self.protocol_radio.bind('<Button-1>', self.choose_data)

        self.the_protocol = StringVar()
        self.the_protocol.set('mysql')
        self.protocol_entry = Entry(protocol_frame, textvariable=self.the_protocol)
        self.protocol_entry.pack(side=LEFT)
        #PROTOCOL列表
        self.protocol_list_radio = Radiobutton(protocol_frame, variable=self.single_protocol, value=0,text="协议列表:", width=8,anchor=W)
        self.protocol_list_radio['state'] = NORMAL
        self.protocol_list_radio.pack(side=LEFT)
        self.protocol_list_radio.bind('<Button-1>', self.choose_data)
        self.the_protocol_list = StringVar()
        self.the_protocol_list.set("./config/protocol_list.txt")
        self.protocol_file = Entry(protocol_frame, textvariable=self.the_protocol_list)
        self.protocol_file['state'] = DISABLED
        self.protocol_file.pack(side=LEFT)
        self.protocol_button = Button(protocol_frame, text='选择')#, command = lambda:self.choose_file())
        self.protocol_button['command'] = lambda:self.choose_file('PROTOCOL')
        self.protocol_button['state'] = DISABLED
        self.protocol_button.pack()

        #输入GUI结束

        self.exit_button = Button(master, text="退出", fg="red", command=master.quit)
        self.exit_button.pack(side=RIGHT)
        self.suspend_button = Button(master, text="暂停", command=self.suspend_running)
        self.suspend_button.pack(side=RIGHT)
        self.start_button = Button(master, text="开始", command=self.lets_go)
        self.start_button.pack(side=RIGHT)
####################################################################################
########实现一种协议的扫描类后，只需要在这里实例化一个实例，然后追加到扫描容器内
        the_mysql_scanner = mysql_scanner.c_mysql_scanner()
        self.the_scanner.append_protocol_scanner(the_mysql_scanner)

        the_http_scanner = http_scanner.c_http_scanner()
        self.the_scanner.append_protocol_scanner(the_http_scanner)

        the_ssh_scanner = ssh_scanner.c_ssh_scanner()
        self.the_scanner.append_protocol_scanner(the_ssh_scanner)
####################################################################################

    def choose_file(self, event):
        r = tkFileDialog.askopenfilename(title='请选择列表文件', filetypes=[('text', '*.txt *.list *.data'), ('All files', '*.*')])
        if r is None: return
        if r.strip() == '' : return
        #print r
        if 'IP' == event:
            self.the_ip_list.set(r)
        elif 'USER' == event:
            self.the_user_list.set(r)
        elif 'PASSWD' == event:
            self.the_passwd_list.set(r)
        elif 'PROTOCOL' == event:
            self.the_protocol_list.set(r)

    def choose_data(self, event):
        if event.widget == self.ip_radio:
            #print 'single ip'
            self.ip_radio['state']          = ACTIVE
            self.ip_list_radio['state']     = NORMAL
            self.ip_entry['state']          = NORMAL
            self.ip_file['state']           = DISABLED
            self.ip_button['state']         = DISABLED
        elif event.widget == self.ip_list_radio:
            #print 'ip list'
            self.ip_radio['state']          = NORMAL
            self.ip_list_radio['state']     = ACTIVE
            self.ip_entry['state']          = DISABLED
            self.ip_file['state']           = NORMAL
            self.ip_button['state']         = ACTIVE
        elif event.widget == self.user_radio:
            #print 'single user'
            self.user_radio['state']        = ACTIVE
            self.user_list_radio['state']   = NORMAL
            self.user_entry['state']        = NORMAL
            self.user_file['state']         = DISABLED
            self.user_button['state']       = DISABLED
        elif event.widget == self.user_list_radio:
            #print 'user list'
            self.user_radio['state']        = NORMAL
            self.user_list_radio['state']   = ACTIVE
            self.user_entry['state']        = DISABLED
            self.user_file['state']         = NORMAL
            self.user_button['state']       = ACTIVE
        elif event.widget == self.passwd_radio:
            #print 'single password'
            self.passwd_radio['state']      = ACTIVE
            self.passwd_list_radio['state'] = NORMAL
            self.passwd_entry['state']      = NORMAL
            self.passwd_file['state']       = DISABLED
            self.passwd_button['state']     = DISABLED
        elif event.widget == self.passwd_list_radio:
            #print 'user password'
            self.passwd_radio['state']      = NORMAL
            self.passwd_list_radio['state'] = ACTIVE
            self.passwd_entry['state']      = DISABLED
            self.passwd_file['state']       = NORMAL
            self.passwd_button['state']     = ACTIVE
        elif event.widget == self.protocol_radio:
            #print 'single protocol'
            self.protocol_radio['state']      = ACTIVE
            self.protocol_list_radio['state'] = NORMAL
            self.protocol_entry['state']      = NORMAL
            self.protocol_file['state']       = DISABLED
            self.protocol_button['state']     = DISABLED
        elif event.widget == self.protocol_list_radio:
            #print 'user protocol'
            self.protocol_radio['state']      = NORMAL
            self.protocol_list_radio['state'] = ACTIVE
            self.protocol_entry['state']      = DISABLED
            self.protocol_file['state']       = NORMAL
            self.protocol_button['state']     = ACTIVE

    def input_data_update(self):
        if self.ip_entry['state'] == NORMAL and self.ip_file['state'] == DISABLED:
            self.ip_data = [self.the_ip.get()]
            self.the_scanner.set_host_data(self.ip_data)
        elif self.ip_entry['state'] == DISABLED and self.ip_file['state'] == NORMAL:
            the_file = self.the_ip_list.get()
            self.the_scanner.load_host_data(the_file)

        if self.user_entry['state'] == NORMAL and self.user_file['state'] == DISABLED:
            self.user_data = [self.the_user.get()]
            self.the_scanner.set_user_data(self.user_data)
        elif self.user_entry['state'] == DISABLED and self.user_file['state'] == NORMAL:
            the_file = self.the_user_list.get()
            self.the_scanner.load_user_data(the_file)

        if self.passwd_entry['state'] == NORMAL and self.passwd_file['state'] == DISABLED:
            self.passwd_data = [self.the_passwd.get()]
            self.the_scanner.set_passwd_data(self.passwd_data)
        elif self.passwd_entry['state'] == DISABLED and self.passwd_file['state'] == NORMAL:
            the_file = self.the_passwd_list.get()
            self.the_scanner.load_passwd_data(the_file)

        if self.protocol_entry['state'] == NORMAL and self.protocol_file['state'] == DISABLED:
            self.protocol_data = [self.the_protocol.get()]
            self.the_scanner.set_protocol_data(self.protocol_data)
        elif self.protocol_entry['state'] == DISABLED and self.protocol_file['state'] == NORMAL:
            the_file = self.the_protocol_list.get()
            self.the_scanner.load_protocol_data(the_file)

    def suspend_running(self):
        if self.the_scanner is not None:
            self.the_scanner.suspend()
        else:
            print 'HAS NOT RUNNED THE SCANNER!'

    def lets_go(self):
        self.input_data_update()
        self.the_scanner.run()

def main():
    pass

if __name__ == "__main__":
    main()
