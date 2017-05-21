#coding:utf-8
'''
Created on 2015年2月16日

@author: wfq
'''

from flask import Flask, render_template, request, redirect, session
import subprocess
import os
import hashlib

app = Flask(__name__)
# 用于session加密
app.secret_key = "SA125DCS14/56CS156"

def getNetworkInterfaceInfo(iface):
    cmd = "ifconfig " + iface + " | awk '/inet addr/ {split($2, a, \":\"); print a[2]}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    ip = p.stdout.read()

    cmd = "ifconfig " + iface + " | awk '/HWaddr/ {print $5}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    mac = p.stdout.read()

    cmd = "ifconfig " + iface + " | awk '/inet addr/ {split($3, a, \":\"); print a[2]}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    netMask = p.stdout.read()
    return (ip, mac, netMask)

def getWanInfo():
	cmd = "ip route show | awk '/via/ {print($3)}'"
	p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
	gateWay = p.stdout.read()

	cmd = "ifconfig -a eth0 | awk '/inet6 addr:/ {print($3)}'"
	p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
	ipv6 = p.stdout.read()

	cmd = "cat /etc/resolv.conf | awk '/nameserver/ {print($2)}'"
	p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
	dns = p.stdout.read()

	return (gateWay, ipv6, dns)

# 用于给密码进行md5加密
def md5(password):
     import hashlib
     m = hashlib.md5()
     m.update(password)
     return m.hexdigest()


@app.route('/')
@app.route('/<err>')
def login(err = None):
    if "login" in session:
        return redirect('/status')
    else:
        return render_template("login.html", err = err)

@app.route('/submitLogin', methods=['GET', 'POST'])
def submitLogin():
    password = request.form['password'].strip(' \n')

    passwordFile = open("./password", "r")
    passWord = passwordFile.read(-1).strip(' \n')
    passwordFile.close()

    if passWord == md5(password):
        session['login'] = 1
        return redirect('/status')
    else:
        return redirect('/0')

@app.route('/status')
def status():
    if "login" not in session:
        return redirect('/')

    wanIPAddress, wanMACAddress, wanNetMask = getNetworkInterfaceInfo('eth0')
    lanIPAddress, lanMACAddress, lanNetMask = getNetworkInterfaceInfo('wlan0')
    return render_template("main.html", wanMACAddress=wanMACAddress, wanIPAddress = wanIPAddress, wanNetMask = wanNetMask, lanMACAddress = lanMACAddress, lanIPAddress = lanIPAddress, lanNetMask = lanNetMask)

def getHostapdConfig(param):
    cmd = "awk '/" + param + "/ {split($1, a, \"=\"); print a[2]}' /etc/hostapd/hostapd.conf"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    return p.stdout.read()

@app.route('/wlanPort')
@app.route('/wlanPort/<err>')
def wlanPort(err = None):
    if "login" not in session:
        return redirect('/')

    ssid = getHostapdConfig('^ssid')
    ignoreBroadcastSSID = getHostapdConfig('ignore_broadcast_ssid').strip('\n')
    if ignoreBroadcastSSID == '1':
        broadcast = 0
    else:
        broadcast = 1
    channel = int(getHostapdConfig('channel'))
    passwd = getHostapdConfig('wpa_passphrase')
    return render_template('wlanPort.html', ssid = ssid, broadcast = broadcast, channel = channel, passwd = passwd, err = err)

@app.route('/submitWlanPort', methods=['GET', 'POST'])
def submitWlanPort():
    if "login" not in session:
        return redirect('/')

    ssid = request.form['ssid'].strip(' \n')
    channel = request.form['channel'].strip(' \n')
    passwd = request.form['passwd'].strip(' \n')
    if 'broadcast' in request.form:
        ignoreBroadcastSSID = '0'
    else:
        ignoreBroadcastSSID = '1'
    fileBuffer = render_template('hostapd.conf', ssid = ssid, ignoreBroadcastSSID = ignoreBroadcastSSID, channel = channel, passwd = passwd)

    try:
        with open('/etc/hostapd/hostapd.conf', 'w') as fp:
            fp.write(fileBuffer)
    except IOError:
        return u'写入配置文件失败'

    return redirect('/wlanPort/0')


@app.route('/wirelessClientList')
def clientList():
    if "login" not in session:
        return redirect('/')
    else:
        file = open('/var/lib/dhcp/dhcpd.leases')
    	clientsList = {}
    	i = 0

    	line = file.readline()
    	while (line):
    		if len(line) == 0:
    			break

    		clientList = {}
    		if line.find('{') != -1:
    			ip = line.split(' ')[1]
    			state = ""
    			hostname = ""
    			mac = ""

    			while True:
    				line = file.readline()

    				if line.find('}') != -1:
    					break

    				if line.find('state') != -1:
    					if line.split(' ')[3] == "state":
    						state = line.split(' ')[-1][0:-2]

    				if line.find('client-hostname') != -1:
    					hostname = line.split('"')[1]

    				if line.find('hardware') != -1:
    					mac = line.split(' ')[4][0:-2]

    			if state == "free":
    				continue

    			clientList['ip'] = ip
    			clientList['hostname'] = hostname
    			clientList['mac'] = mac

    		if clientList != {}:
    			if str(clientsList.values()).find(mac) == -1:
    				clientsList[i] = clientList
    				i += 1

    		line = file.readline()

    	file.close()
    	# print clientsList
    	return render_template('wirelessClientList.html', clientsList = clientsList)


def getInterfacesConfig(param):
    cmd0 = "awk 'BEGIN {n = -999} /iface wlan0/ {n = NR} NR == n+1 || NR== n+2 {print $0}' /etc/network/interfaces"
    cmd = cmd0 + " | awk '/" + param + "/ {print $2}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    return p.stdout.read()


def getDhcpServerInfo():
    cmd = "cat /etc/dhcp/dhcpd.conf | awk '/subnet/ {print($2)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    subnet = p.stdout.read()

    cmd = "cat /etc/dhcp/dhcpd.conf | awk '/subnet/ {print($4)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    netmask = p.stdout.read()

    cmd = "cat /etc/dhcp/dhcpd.conf | awk '/range/ {print($2)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    start = p.stdout.read()

    cmd = "cat /etc/dhcp/dhcpd.conf | awk '/range/ {print($3)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    end = p.stdout.read()

    cmd = "cat /etc/dhcp/dhcpd.conf | awk '/routers/ {print($3)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    routers = p.stdout.read()

    return (subnet, netmask, start, end, routers)

def getStaticInfo():
    cmd = "cat /etc/dhcpcd.conf | awk '/static ip_address/ {split($2,a,\"=\");print(a[2])}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    staticIpAddress = p.stdout.read()

    cmd = "cat /etc/dhcpcd.conf | awk '/static router/ {split($2,a,\"=\");print(a[2])}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    staticGateWay = p.stdout.read()

    cmd = "cat /etc/dhcpcd.conf | awk '/static domain_name_servers/ {split($2,a,\"=\");print(a[2])}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    staticDNS = p.stdout.read()

    return (staticIpAddress, staticGateWay, staticDNS)

@app.route('/wanPort')
@app.route('/wanPort/<err>')
def wanPort(err = None):
    if "login" not in session:
        return redirect('/')

    autoIpAddress = "0.0.0.0"
    autoNetmask = "0.0.0.0"
    autoGateWay = "0.0.0.0"
    autoIpv6 = "0.0.0.0"
    autoDNS = "0.0.0.0"

    staticIpAddress = "0.0.0.0"
    staticNetmask = "0.0.0.0"
    staticGateWay = "0.0.0.0"
    staticDNS = "0.0.0.0"

    option = ""

    dhcpcdFile = open('/etc/dhcpcd.conf', 'r')
    dhcpcd = dhcpcdFile.read(-1)
    dhcpcdFile.close()

    if dhcpcd.find('eth0') == -1:
        option = "0"
    	autoIpAddress, mac, autoNetmask = getNetworkInterfaceInfo('eth0')
    	autoGateWay, autoIpv6, autoDNS = getWanInfo()

    else:
        option = "1"
        staticIpAddress, staticGateWay, staticDNS = getStaticInfo()
        staticNetmaskNum = staticIpAddress.split("/")[1].strip(' \n')
        staticIpAddress = staticIpAddress.split("/")[0]

        staticNetmask = ""
        length = eval(staticNetmaskNum + "/8")
        for i in range(int(length)):
            staticNetmask = staticNetmask + "255."

        length = 4 - length
        for i in range(int(length)):
            staticNetmask = staticNetmask + "0."

        staticNetmask = staticNetmask.strip(".")

    return render_template('wanPort.html', option = option, autoGateWay = autoGateWay, autoIpv6 = autoIpv6, autoDNS = autoDNS, autoIpAddress = autoIpAddress, autoNetmask = autoNetmask, staticIpAddress = staticIpAddress, staticNetmask = staticNetmask, staticGateWay = staticGateWay, staticDNS = staticDNS, err = err)

@app.route('/submitWanPort', methods=['GET', 'POST'])
def submitWanPort():
    if "login" not in session:
        return redirect('/')

    selectOptionNumber = request.form['selectOptionNumber'].strip(' \n')

    if selectOptionNumber == "1":
        staticIpAddress = request.form['staticIpAddress'].strip(' \n')
        staticNetmask = request.form['staticNetmask'].strip(' \n')
        staticGateWay = request.form['staticGateWay'].strip(' \n')
        staticDNS = request.form['staticDNS'].strip(' \n')

        staticNetmaskNum = staticNetmask.count("255") * 8
        staticIpAddress = staticIpAddress + "/" + str(staticNetmaskNum)

        dhcpcdFileBuffer = render_template("dhcpcd.conf")
        dhcpcdFileBuffer = dhcpcdFileBuffer + '''
interface eth0
static ip_address=''' + staticIpAddress + '''
static routers=''' + staticGateWay + '''
static domain_name_servers=''' + staticDNS
    else:
        dhcpcdFileBuffer = render_template("dhcpcd.conf")

    try:
        with open('/etc/dhcpcd.conf', 'w') as fp1:
            fp1.write(dhcpcdFileBuffer)

    except IOError:
        return u'写入配置文件失败'

    return redirect("wanPort/0")

@app.route('/lanPort')
@app.route('/lanPort/<err>')
def lanPort(err = None):
    if "login" not in session:
        return redirect('/')

    ipAddress = getInterfacesConfig('address').strip('\n')
    netmask = getInterfacesConfig('netmask').strip('\n')
    return render_template('lanPort.html', ipAddress = ipAddress, netmask = netmask, err = err)


@app.route('/submitLanPort', methods=['GET', 'POST'])
def submitLanPort():
    if "login" not in session:
        return redirect('/')

    subnet, netmask, start, end, routers = getDhcpServerInfo()
    subnet = subnet.strip(';\n')
    netmask = netmask.strip(';\n')
    start = start.strip(';\n')
    end = end.strip(';\n')
    routers = routers.strip(';\n')

    ipAddress = request.form['ipAddress'].strip(' \n')
    netmask = request.form['netmask'].strip(' \n')
    interfacesFileBuffer = render_template('interfaces', ipAddress = ipAddress, netmask = netmask)

    subnet = ipAddress[0:-1] + '0'
    routers = ipAddress
    start = ipAddress[0:-1] + start.split('.')[3]
    end = ipAddress[0:-1] + end.split('.')[3]
    print start, end
    dhcpdFileBuffer = render_template('dhcpd.conf', subnet = subnet, netmask = netmask, start = start, end = end, routers = routers)

    try:
        with open('/etc/network/interfaces', 'w') as fp1:
            fp1.write(interfacesFileBuffer)
        with open('/etc/dhcp/dhcpd.conf', 'w') as fp2:
            fp2.write(dhcpdFileBuffer)

    except IOError:
        return u'写入配置文件失败'

    return redirect('/lanPort/0')

def getServiceStatus():
    cmd = "service isc-dhcp-server status | awk '/Active:/ {print($2)}'"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    return p.stdout.read()

@app.route('/dhcpServer')
@app.route('/dhcpServer/<err>')
def dhcpServer(err = None):
    if "login" not in session:
        return redirect('/')

    subnet, netmask, start, end, routers = getDhcpServerInfo()

    ipPre = (subnet.strip(' \n'))[0:subnet.rfind('.') + 1]
    serviceStatus = getServiceStatus().strip(' \n')
    start = (start.strip(' \n')).split('.')[3]
    end = (end.strip(' \n')).split('.')[3].strip(';')

    return render_template('dhcpServer.html', serviceStatus = serviceStatus, ipPre = ipPre, start = start, end = end, err = err)

@app.route('/submitDhcpServer', methods=['GET', 'POST'])
def submitDhcpServer():
    if "login" not in session:
        return redirect('/')

    serviceStatus = request.form['serviceStatus'].strip(' \n')

    if serviceStatus == "on":
        subprocess.call(["service", "isc-dhcp-server", "start"])
        subnet, netmask, start, end, routers = getDhcpServerInfo()
        subnet = subnet.strip(';\n')
        netmask = netmask.strip(';\n')
        start = start.strip(';\n')
        end = end.strip(';\n')
        routers = routers.strip(';\n')

        ipPre = request.form['ipPre'].strip(' \n')
        start = request.form['start'].strip(' \n')
        end = request.form['end'].strip(' \n')

        start = ipPre + start
        end = ipPre + end

        # print serviceStatus, start, end
        dhcpdFileBuffer = render_template('dhcpd.conf', subnet = subnet, netmask = netmask, start = start, end = end, routers = routers)

        try:
            with open('/etc/dhcp/dhcpd.conf', 'w') as fp2:
                fp2.write(dhcpdFileBuffer)

        except IOError:
            return u'写入配置文件失败'

    else:
        subprocess.call(["service", "isc-dhcp-server", "stop"])

    return redirect('/dhcpServer/0')

@app.route('/changePassword')
@app.route('/changePassword/<err>')
def changePassword(err = None):
    if "login" not in session:
        return redirect('/')

    return render_template("changePassword.html", err = err)

@app.route('/submitChangePassword', methods=['GET', 'POST'])
def submitChangePassword():
    if "login" not in session:
        return redirect('/')

    oldPassword = request.form['oldPassword'].strip(' \n')

    passwordFile = open("./password", "r")
    password = passwordFile.read(-1).strip(' \n')
    passwordFile.close()

    if password == md5(oldPassword):
        newPassword = request.form['newPassword'].strip(' \n')
        try:
            with open('./password', 'w') as fp2:
                fp2.write(md5(newPassword))

        except IOError:
            return u'密码更改失败'

        # 用于登出，将session中的login字段pop
        # Flask中的session基于字典类型实现，
        # 调用pop方法时会返回pop的键对应的值；
        # 如果要pop的键并不存在，
        # 那么返回值是pop()的第二个参数
        session.pop('login', None)
        return redirect('/')
    else:
        return redirect('/changePassword/1')

@app.route('/reboot')
def reboot():
    if "login" not in session:
        return redirect('/')

    os.system('sh reboot.sh &')
    return render_template('reboot.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
