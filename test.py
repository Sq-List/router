def clientList():
	file = open('./file.txt')
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
			clientsList[i] = clientList
			i += 1
		

		line = file.readline()

	file.close()
	print(clientsList)

	print(str(clientsList.values()).find('f4:8b:32:6e:ea:14'))


clientList()