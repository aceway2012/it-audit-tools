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
from pub.gui_audit_app import *


def main():
    gui_root = Tk()
    c_gui_audit_app(gui_root)
    gui_root.title('IT安全审计工具--账户审计')
    gui_root.resizable(False, False)
    gui_root.mainloop()

if __name__ == "__main__":
    main()
