staticIpAddress = "192.168.0.99/24"
staticNetmaskNum = staticIpAddress.split("/")[1]
staticNetmask = ""
length = eval(staticNetmaskNum + "/8")
for i in range(int(length)):
    staticNetmask = staticNetmask + "255."

length = 4 - length
for i in range(int(length)):
    staticNetmask = staticNetmask + "0."

staticNetmask = staticNetmask.strip(".")
staticNetmaskNum = staticNetmask.count("255") * 8
staticIpAddress = staticIpAddress + "/" + str(staticNetmaskNum)

# print(staticIpAddress)
print(md5("123456"))