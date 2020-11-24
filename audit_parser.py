import os
import sys
import re

print_flag = False
time = ''
key = ''
cmd = ''
exe = ''
pid = ''
ppid = ''

# 提取 EXECVE 字段中的 cmd 信息
def parse_execve(line):

    global print_flag
    global cmd

    cmd = ''
    argc = re.findall(r"argc=(\d)", line)
    if len(argc) < 1:
        print_flag = False
        return 1
    argc = int(argc[0])
    for i in range(0, argc):
        flag = r"a%d=\"(.+?)\"" % i
        argv = re.findall(flag, line)
        if len(argv) == 0:
            flag = r"a%d=(.+)" % i
            argv = re.findall(flag, line)
            if len(argv) == 0:
                print("parse error --> " + line)
                print_flag = False
                return 1

        argv = argv[0]
        cmd = cmd + argv + ' '

    print_flag = True

# 提取 SYSCALL 字段中的 key、exe、pid、ppid 信息
def parse_syscall(line):

    global print_flag
    global key
    global cmd
    global exe
    global pid
    global ppid

    exe = ''
    pid = ''
    ppid = ''

    if not print_flag:
        cmd = 'null'

    key = re.findall(r"key=(.+)", line)
    if len(key) > 0:
        key = key[0]
        if 'null' in key:
            print_flag = False
            return 1
    else:
        print_flag = False
        return 1

    exe = re.findall(r"exe=\"(.+?)\"", line)
    if len(exe) > 0:
        exe = exe[0]
    else:
        print("parse error --> " + line)
        print_flag = False
        return 1

    pids = re.findall(r"ppid=(.+?) pid=(.+?) ", line)
    if len(pids) > 0:
        pids = pids[0]
        ppid = pids[0]
        pid = pids[1]
    else:
        print("extra error --> " + line)
        print_flag = False
        return 1

    print_flag = True

# 信息打印函数
def print_log():

    global print_flag

    if print_flag:
        print("-----------------------------------------------------------------------\n")
        print("[+] time --> " + time)
        print("[+] key --> " + key)
        print("[+] exe --> " + exe)
        print("[+] cmd --> " + cmd)
        print("[+] pid --> " + pid)
        print("[+] ppid --> " + ppid + "\n")

    print_flag = False

# 入口点
if __name__ == '__main__':

    # 判断参数
    if len(sys.argv) < 2:
        print("[-] usage: audit_parser.py [log_path]")
        exit(-1)

    log_path = sys.argv[1]
    if os.path.isfile(log_path):
        f = open(log_path, 'r')
        lines = f.readlines()
        for line in lines:
            # 提取时间字段
            if 'time->' in line:
                time = re.findall(r"time->(.+)", line)[0]
            # 解析 EXECVE 字段
            if 'type=EXECVE' in line:
                parse_execve(line)
            # 解析 SYSCALL 字段
            if 'type=SYSCALL' in line:
                parse_syscall(line)
                # 打印结果
                print_log()

        f.close()