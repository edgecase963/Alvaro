#!/usr/bin/env python
import sys, os, time, random, asyncio, ssl, concurrent, pickle, base64, cryptography
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
__version__ = "0.4.3 (Beta)"



def encrypt(plainText, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    cText = f.encrypt(plainText)
    return cText, salt

def decrypt(cText, salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    try:
        plainText = f.decrypt(cText)
        return plainText
    except cryptography.fernet.InvalidToken:
        return False


def newStreamID(streams):
    pN = random.randint(1000000, 9999999)
    while "p{}".format(pN).encode() in streams:
        pN += 1
        if pN > 9999999:
            pN = random.randint(1000000, 9999999)
    return "p{}".format(pN).encode()

def convVarType(var, t):
    if t.lower() == "s": return str(var)
    if t.lower() == "i": return int(var)
    if t.lower() == "f": return float(var)
    if t.lower() == "b":
        if var.lower() == "true":
            return True
        elif var.lower() == "false":
            return False
        else:
            return bool(var)
    return var

def unpackMetaStr(metaStr):
    metaStr = metaStr.decode()
    metaData = {}
    while True:
        if len(metaStr) == 0:
            break
        mLen = int(metaStr[:18])
        metaStr = metaStr[18:]
        firstVar = metaStr[:mLen]
        firstVar = convVarType(firstVar[1:], firstVar[0])
        metaStr = metaStr[mLen:]
        mLen = int(metaStr[:18])
        metaStr = metaStr[18:]
        lastVar = metaStr[:mLen]
        lastVar = convVarType(lastVar[1:], lastVar[0])
        metaStr = metaStr[mLen:]
        metaData[firstVar] = lastVar
    return metaData

def getMetaStr(metaData):
    metaStr = ""
    for i in metaData:
        metaStr += str( len(str(i))+1 ).zfill(18) + str(i.__class__).split("'")[1][0] + str(i)
        metaStr += str( len(str(metaData[i]))+1 ).zfill(18) + str(metaData[i].__class__).split("'")[1][0] + str(metaData[i])
    return metaStr.encode()

def prepData(data, metaData=None):
    # Prepares the data to be sent
    # Structure: DATA:| <data_length>.zfill(18) <raw-data> META:| <meta-string>
    # (ignore spaces)
    if type(data) == str:
        data = data.encode()
    pData = ""
    pData = b'DATA:|' + str(len(data)).encode().zfill(18) + data
    if metaData:
        pData = pData + b'META:|' + getMetaStr(metaData)
    return pData

def dissectData(data):
    # Used after data is received to prepare it for later
    rawData = ""
    metaData = None
    if data.startswith(b'DATA:|'):
        data = data[6:]   # Remove "DATA:|"
        dataLen = int(data[:18])   # Extract length of data
        data = data[18:]   # Remove the data length
        rawData = data[:dataLen]   # Get the raw data
        metaStr = data[dataLen:]   # Get the meta-data (if any)
        if metaStr != "":
            if metaStr.startswith(b'META:|'):   # Received Meta-Data
                metaStr = metaStr[6:]   # Convert Meta-Data to dictionary
                metaData = unpackMetaStr(metaStr)
    else:
        return data, None, True
    return rawData, metaData, False



class User():
    def __init__(self, username):
        self.username = username
        self.cPass = None   # The encrypted password (ciphertext, salt)
        self.password = None   # This stays at `None` until the user is verified
        self.hasPassword = False

        self.connections = []

        self.loginHistory = []
        # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]

        self.loginAttempts = []
        # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]

    def reset(self):
        self.password = None
        self.connections = []

    def copy(self):
        userCopy = User(self.username)
        userCopy.cPass = self.cPass
        userCopy.hasPassword = self.hasPassword
        userCopy.loginAttempts = self.loginAttempts
        return userCopy

    def save(self, userDir):
        try:
            with open( os.path.join(userDir, self.username), "wb" ) as f:
                pickle.dump(self.copy(), f)
            return True
        except:
            return False

    def verify(self, password):
        if type(password) == str:
            password = password.encode()
        if self.hasPassword:
            if self.cPass and password:
                if password == decrypt(self.cPass[0], self.cPass[1], password):
                    return True
            else:
                return False
        else:
            return True

    def login(self, username, password, connection):
        if username == self.username and self.verify(password):
            if not connection in self.connections:
                self.connections.append(connection)
            self.password = password
            self.loginHistory.append( [ time.time(), connection.addr ] )
            connection.verifiedUser = True
            connection.currentUser = self
            return True
        else:
            self.loginAttempts.append( [ time.time(), connection.addr ] )
            return False

    def logout(self, client):
        client.verifiedUser = False
        client.currentUser = None
        if client in self.connections:
            self.connections.remove(client)
        if len(self.connections) == 0:
            self.password = None

    def addPassword(self, password):
        if type(password) == str:
            password = password.encode()
        if not self.hasPassword:
            cText, salt = encrypt(password, password)
            self.cPass = [cText, salt]
            self.password = password
            self.hasPassword = True
        return self


class Connection():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self, addr, port, reader, writer, server):
        self.connectionTime = time.time()
        self.addr = addr
        self.port = port
        self.reader = reader
        self.writer = writer

        self.server = server

        self.verifiedUser = False
        self.currentUser = None

    async def sendData(self, data, metaData=None):
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = prepData(data, metaData=metaData)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    async def sendRaw(self, data):
        try:
            if type(data) != str and type(data) != bytes:
                data = str(data)
            if type(data) == str:
                data = data.encode()
            data = data + self.sepChar
            self.writer.write(data)
            await self.writer.drain()
        except ConnectionResetError:
            pass

    async def disconnect(self):
        await self.sendRaw("disconnect")
        self.writer.close()
        self.logout()

    async def blacklist(self, bTime=600):
        await self.server.blacklistIP(self.addr, bTime=bTime)

    def logout(self):
        if self.currentUser:
            self.currentUser.logout(self)


class Host():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self, addr, port, verbose=False, logging=False, logFile=None, loginRequired=False, multithreading=True):
        self.running = False
        self.addr = addr
        self.port = port
        self.clients = []
        self.verbose = verbose
        self.loginRequired = loginRequired
        self.loginTimeout = 12.   # The amount of time to wait for a login before disconnecting the client (if logins are required)
        self.loginDelay = 0.6
        self.multithreading = multithreading

        self.loginAttempts = []
        # Structure: # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]

        self.blacklistThreshold = 1800   # (In seconds)
        # If too many login attempts are made within this threshold, the address will be blacklisted
        # 1800 = 30 minutes

        self.blacklistLimit = 6

        self.blacklist = {}
        # Structure: {<IP_address>: <time.time()>}

        self.lock = asyncio.Lock()

        self.userPath = "users"
        self.users = {}
        # Structure: {"username": <User Class>}

        self.logging = logging
        self.logFile = logFile

    def __start_loop__(self, loop, task, finishFunc):
        asyncio.set_event_loop(loop)
        loop.run_until_complete( asyncio.ensure_future(task()) )
        if finishFunc:
            asyncio.run(finishFunc())

    def newLoop(self, task, finishFunc=None):
        new_loop = asyncio.new_event_loop()
        t = Thread( target=self.__start_loop__, args=(new_loop, task, finishFunc) )
        t.start()

    async def loadUsers(self):
        for i in os.listdir(self.userPath):
            iPath = os.path.join(self.userPath, i)
            if os.path.isfile( iPath ):
                try:
                    with open(iPath, "rb") as f:
                        user = pickle.load(f)
                        self.users[user.username] = user
                except:
                    pass

    async def saveUsers(self):
        await self.lock.acquire()
        for uName in self.users:
            self.users[uName].save(self.userPath)
        self.lock.release()

    def addUser(self, username, password=None):
        user = User(username)
        if password:
            if type(password) == bytes: password = password.decode()
            if type(password) != str: password = str(password)
            user.addPassword(password)
        if not username in self.users:
            self.users[username] = user
            return True
        else:
            return False

    async def log(self, t):
        await self.lock.acquire()
        if type(t) == bytes: t = t.decode()
        logText = "[{}]\t{}\n".format(time.time(), t)
        if self.logging:
            if not os.path.exists(self.logFile):
                with open(self.logFile, "wb") as f: pass   # Create the path
            with open(self.logFile, "rb") as f: logData = f.read()
            with open(self.logFile, "wb") as f: f.write(logData + logText.encode())
        if self.verbose:
            sys.stdout.write(logText)
            sys.stdout.flush()
        self.lock.release()

    async def gotData(self, client, data, metaData):
        pass

    async def lostClient(self, client):
        pass

    async def newClient(self, client):
        pass

    async def blacklisted(self, addr):
        pass

    async def blacklistIP(self, addr, bTime=600):
        self.blacklist[addr] = time.time()+bTime
        await self.log("Blacklisted {} for {} seconds".format(addr, bTime))
        for client in self.clients:
            if client.addr == addr:
                await client.disconnect()

    async def getData(self, client, reader, writer, length=600):
        data = None
        try:
            data = await reader.read(length)
        except Exception as e:
            await self.log( str(e) + " - {}:{}".format(client.addr, client.port) )
        return data

    async def gotRawData(self, client, data):
        if type(data) == bytes:
            data = data.decode()
        if data.startswith("LOGIN:") and "|" in data:
            if len(data.split("|")) == 2:
                data = data[6:]
                username, password = data.split("|")
                if username in self.users:
                    await self.log("Login acquired - verifying...")
                    user = self.users[username]
                    time.sleep(self.loginDelay)
                    if user.login(username, password, client):
                        await self.log("{} logged in".format(username))
                        await client.sendRaw(b'login accepted')
                    else:
                        await self.log("Failed login attempt - {} | {} - {}:{}".format(username, password, client.addr, client.port))
                        self.loginAttempts.append( [time.time(), client.addr] )

                        if len( [i for i in self.loginAttempts if i[0] >= time.time()-self.blacklistThreshold] ) > self.blacklistLimit:
                            await self.blacklistIP(client.addr)

                        await client.disconnect()
                else:
                    await self.log("Login Failed - Username '{}' not recognized".format(username))
                    await client.sendRaw(b'login failed')
        elif data == "logout":
            if client.verifiedUser and client.currentUser:
                client.currentUser.logout(client)
                await self.log("User logged out - {} - {}:{}".format(client.currentUser.username, client.addr, client.port))

    async def handleClient(self, reader, writer):
        cliAddr = writer.get_extra_info('peername')
        client = Connection(cliAddr[0], cliAddr[1], reader, writer, self)
        self.clients.append(client)

        await self.log("New Connection: {}:{}".format(client.addr, client.port))

        if client.addr in self.blacklist:
            if self.blacklist[client.addr] < time.time():
                self.blacklist.pop(client.addr)
            else:
                await self.log("{} is blacklisted - disconnecting...".format(client.addr))
                await client.disconnect()
                return

        if self.loginRequired and not client.verifiedUser:
            await client.sendRaw(b'login required')

        await self.newClient(client)

        buffer = b''

        while self.running:
            if self.loginRequired and not client.verifiedUser:
                if time.time() - client.connectionTime >= self.loginTimeout:
                    await client.disconnect()
            data = await self.getData(client, reader, writer)
            if not data:
                break
            buffer += data

            for i in [  x for x in range(len( buffer.split(self.sepChar) )-1)  ]:
                message = buffer.split(self.sepChar)[i]
                message, metaData, isRaw = dissectData(message)

                if isRaw:
                    await self.gotRawData(client, message)
                elif (self.loginRequired and client.verifiedUser) or not self.loginRequired:
                    if self.multithreading:
                        self.newLoop(task=lambda: self.gotData(client, message, metaData))
                    else:
                        await self.gotData(client, message, metaData)
            buffer = buffer.split(self.sepChar)[len(buffer.split(self.sepChar))-1]

        await self.log("Lost Connection: {}:{}".format(client.addr, client.port))
        self.clients.remove(client)
        writer.close()
        client.logout()
        await self.lostClient(client)

    async def start(self, useSSL=False, sslCert=None, sslKey=None):
        self.running = True
        ssl_context = None

        server = None

        if self.logging:
            if self.logFile == None: self.logFile = "log.txt"
            await self.log("Starting server...")

        if not os.path.exists(self.userPath):
            await self.log("Creating user directory")
            os.mkdir(self.userPath)
        await self.log("Loading users...")
        await self.loadUsers()
        await self.log("Users loaded")

        if useSSL and sslCert and sslKey:
            await self.log("Loading SSL certificate...")
            if os.path.exists(sslCert) and os.path.exists(sslKey):
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(sslCert, sslKey)
                await self.log("SSL certificate loaded")

                server = await asyncio.start_server(self.handleClient, self.addr, self.port, ssl=ssl_context)
            else:
                await self.log("Unable to load certificate files")
                return
        else:
            server = await asyncio.start_server(self.handleClient, self.addr, self.port)

        if server:
            await self.log("Server started")
            async with server:
                await server.serve_forever()
        else:
            self.running = False
            await self.log("Unable to start server")



class Client():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self, multithreading=False):
        self.connected = False
        self.reader = None
        self.writer = None
        self.hostAddr = None
        self.hostPort = None
        self.conUpdated = time.time()   # Last time the connection status was changed
        self.login = (None, None)
        self.multithreading = multithreading
        self.gotDisconnect = False
        self.loginFailed = False

        self.verifiedUser = False

    def __start_loop__(self, loop, task, finishFunc):
        asyncio.set_event_loop(loop)
        loop.run_until_complete( asyncio.ensure_future(task()) )
        if finishFunc:
            asyncio.run(finishFunc())

    def newLoop(self, task, finishFunc=None):
        new_loop = asyncio.new_event_loop()
        t = Thread( target=self.__start_loop__, args=(new_loop, task, finishFunc) )
        t.start()

    async def gotData(self, data, metaData):
        pass

    async def lostConnection(self):
        pass

    async def madeConnection(self):
        pass

    async def loggedIn(self):
        pass

    async def getData(self, reader, writer, length=600):
        data = None
        try:
            data = await reader.read(length)
        except Exception as e:
            print("ERROR: {}".format(e))
        return data

    async def gotRawData(self, data):
        if data == b'login required':
            if self.login[0] and self.login[1]:
                username = self.login[0]
                password = self.login[1]
                if type(username) != str and type(username) != bytes:
                    username = str(username)
                if type(username) == str:
                    username = username.encode()
                if type(password) != str and type(password) != bytes:
                    password = str(password)
                if type(password) == str:
                    password = password.encode()
                await self.sendRaw(b'LOGIN:'+username+b'|'+password)
        if data == b'login accepted':
            self.verifiedUser = True
            await self.loggedIn()
        if data == b'login failed':
            self.loginFailed = True
        if data == b'disconnect':
            self.gotDisconnect = True

    async def logout(self):
        await self.sendRaw(b'logout')

    async def handleHost(self):
        buffer = b''

        if self.multithreading:
            self.newLoop(task=self.madeConnection)
        else:
            await self.madeConnection()

        while self.connected and self.reader:
            data = await self.getData(self.reader, self.writer)
            if not data:
                self.connected = False
                break
            buffer += data

            for i in [  x for x in range(len( buffer.split(self.sepChar) )-1)  ]:
                message = buffer.split(self.sepChar)[i]
                message, metaData, isRaw = dissectData(message)
                if isRaw:
                    await self.gotRawData(message)
                else:
                    if self.multithreading:
                        self.newLoop(task=lambda: self.gotData(self, message, metaData))
                    else:
                        await self.gotData(self, message, metaData)
            buffer = buffer.split(self.sepChar)[len(buffer.split(self.sepChar))-1]
        return self.lostConnection

    async def handleSelf(self):
        while self.connected:
            await asyncio.sleep(0.2)
        if not self.connected and self.reader:
            self.reader.feed_data(self.sepChar)

    async def connect(self, hostAddr, hostPort, login=(None, None), useSSL=False, sslCert=None):
        self.login = login
        self.gotDisconnect = False
        self.loginFailed = False
        try:
            ssl_context = None
            if useSSL and sslCert:
                if os.path.exists(sslCert):
                    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    ssl_context.load_verify_locations(sslCert)

            if ssl_context:
                self.reader, self.writer = await asyncio.open_connection(hostAddr, hostPort, ssl=ssl_context)
            else:
                self.reader, self.writer = await asyncio.open_connection(hostAddr, hostPort)

            self.connected = True
            self.conUpdated = time.time()
            loop = asyncio.get_running_loop()

            future = asyncio.run_coroutine_threadsafe(self.handleSelf(), loop)

            result = loop.call_soon_threadsafe(await self.handleHost())
        except Exception as e:
            print("ERROR: {}".format(e))
            self.connected = False
            self.conUpdated = time.time()
        self.connected = False
        self.conUpdated = time.time()

    async def sendData(self, data, metaData=None):
        if not self.connected:
            print("ERROR: Event loop not connected. Unable to send data")
            return None
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = prepData(data, metaData=metaData)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    async def sendRaw(self, data):
        if not self.connected:
            print("ERROR: Event loop not connected. Unable to send data")
            return None
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def waitForConnection(self, timeout=None):
        startTime = time.time()
        while self.conUpdated < startTime:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.connected

    def waitForLogin(self, timeout=None):
        startTime = time.time()
        while not self.verifiedUser and not self.gotDisconnect and not self.loginFailed:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.verifiedUser

    def disconnect(self):
        if self.connected and self.writer:
            self.writer.close()
            self.connected = False



async def receivedText(client, data, metaData):
    if data == b'exit':
        await client.disconnect()
    print("Data: {}".format(data))
    print("Meta: {}".format(metaData))


async def connection(client):
    await client.sendData("Thank you for connecting")

if __name__ == "__main__":
    x = Host("localhost", 8888, verbose=True, logging=True, loginRequired=True)
    x.addUser("admin", password="test123")
    x.gotData = receivedText
    x.newClient = connection
    asyncio.run( x.start(useSSL=False, sslCert=None, sslKey=None) )
