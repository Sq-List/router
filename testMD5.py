import hashlib

def md5(password):
     import hashlib
     m = hashlib.md5()
     m.update(password.encode("utf8"))
     return m.hexdigest()

passwordFile = open("./password", "r")
passWord = passwordFile.read(-1).strip(' \n')
print(passWord)