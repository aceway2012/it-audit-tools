#!/usr/bin/python
#coding=utf-8
'''
信息安全审计工具，
TODO LIST：
1.各个扫描器的实现，需要继承本类，实现 the_parser 接口;定义扫描器名称(会根据它来做调用路由到你实现的扫描器)
2.在 protocol_scanner.py 中添加两行,将实现的扫描器加入执行容器
3.专注实现自己的扫描器功能
'''

class i_scanner:
    def __init__(self):
        self.protocol_name = None
    def the_parser(self, host, user, passwd, protocol):
        pass

    def record_str(self, str_info):
        pass

    def record_leak_info(self,host, port, user, passwd, protocol,info=''):
        pass

def main():
    pass

if __name__ == "__main__":
    main()
