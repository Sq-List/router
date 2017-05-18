#coding:utf-8
'''
Created on 2015年2月16日

@author: wfq
'''

from flask import Flask, render_template, request, redirect
import subprocess
import os

app = Flask(__name__)

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


@app.route('/')
@app.route('/status')
def status():
    wanIPAddress, wanMACAddress, wanNetMask = getNetworkInterfaceInfo('eth0')
    lanIPAddress, lanMACAddress, lanNetMask = getNetworkInterfaceInfo('wlan0')
    return render_template("main.html", wanMACAddress=wanMACAddress, wanIPAddress = wanIPAddress, wanNetMask=wanNetMask,
                           lanMACAddress=lanMACAddress, lanIPAddress = lanIPAddress, lanNetMask=lanNetMask)

def getHostapdConfig(param):
    cmd = "awk '/" + param + "/ {split($1, a, \"=\"); print a[2]}' /etc/hostapd/hostapd.conf"
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
    return p.stdout.read()

@app.route('/wlanPort')
@app.route('/wlanPort/<err>')
def wlanPort(err = None):
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

@app.route('/wanPort')
def wanPort():
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

    if dhcpcd.find('eth0') == -1:
        option = "0"
    	autoIpAddress, mac, autoNetmask = getNetworkInterfaceInfo('eth0')
    	autoGateWay, autoIpv6, autoDNS = getWanInfo()

    else:
        option = "1"

    return render_template('wanPort.html', option = option, autoGateWay = autoGateWay, autoIpv6 = autoIpv6, autoDNS = autoDNS, autoIpAddress = autoIpAddress, autoNetmask = autoNetmask, staticIpAddress = staticIpAddress, staticNetmask = staticNetmask, staticGateWay = staticGateWay, staticDNS = staticDNS)

# @app.route('submitWanPort')
# def submitWanPort():


@app.route('/lanPort')
@app.route('/lanPort/<err>')
def lanPort(err = None):
    ipAddress = getInterfacesConfig('address').strip('\n')
    netmask = getInterfacesConfig('netmask').strip('\n')
    return render_template('lanPort.html', ipAddress = ipAddress, netmask = netmask, err = err)


@app.route('/submitLanPort', methods=['GET', 'POST'])
def submitLanPort():
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
        with open('//etc/dhcp/dhcpd.conf', 'w') as fp2:
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
    subnet, netmask, start, end, routers = getDhcpServerInfo()

    ipPre = (subnet.strip(' \n'))[0:subnet.rfind('.') + 1]
    serviceStatus = getServiceStatus().strip(' \n')
    start = (start.strip(' \n')).split('.')[3]
    end = (end.strip(' \n')).split('.')[3].strip(';')

    return render_template('dhcpServer.html', serviceStatus = serviceStatus, ipPre = ipPre, start = start, end = end, err = err)

@app.route('/submitDhcpServer', methods=['GET', 'POST'])
def submitDhcpServer():
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

@app.route('/reboot')
def reboot():
    os.system('sh reboot.sh &')
    return render_template('reboot.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
