file  = open("./dhcpcd.txt")
ip = "192.168.0.99"
routers = "192.168.0.1"
domain_name_servers = "192.168.0.1"

fileStr = file.read(-1)
# fileStr = fileStr + '''
# interface eth0
# static ip_address=''' + ip + '''
# static routers=''' + routers + '''
# static domain_name_servers=''' + domain_name_servers

print(fileStr)
# eth0Position = fileStr.find('eth0')
# print(eth0Position)
# file.seek(eth0Position, 0)
# print(file.tell())
# for i in range(3):
# 	print(file.readline().strip('\n'))