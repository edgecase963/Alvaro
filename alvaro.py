#!/usr/bin/env python
import sys, os, time, random, asyncio, ssl, concurrent, pickle, base64, cryptography
from threading import Thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
__version__ = "0.6.9 (Beta)"



def encrypt(plainText, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode( kdf.derive(password) )
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
    key = base64.urlsafe_b64encode( kdf.derive(password) )
    f = Fernet(key)
    try:
        plainText = f.decrypt(cText)
        return plainText
    except cryptography.fernet.InvalidToken:
        print(" ERROR: Invalid Token" )
        return False
    except Exception as e:
        print( "ERROR: {}".format(e) )
        return False


def convVarType(var, t):
    if t.lower() == "s":
        return str(var)
    elif t.lower() == "i":
        return int(var)
    elif t.lower() == "f":
        return float(var)
    elif t.lower() == "b":
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

    def encryptData(self, data):
        if self.hasPassword and self.password:
            cData, salt = encrypt( data, self.password.encode() )
            data = salt+cData
            return data
        else:
            return data

    def decryptData(self, data):
        if self.hasPassword and self.password:
            salt = data[:16]
            cData = data[16:]
            data = decrypt( cData, salt, self.password.encode() )
            return data
        else:
            return data

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
                if password == decrypt( self.cPass[0], self.cPass[1], password ):
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
            self.loginHistory.append( [time.time(), connection.addr] )
            connection.verifiedUser = True
            connection.currentUser = self
            return True
        else:
            self.loginAttempts.append( [time.time(), connection.addr] )
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

        self.encData = True

    async def send_data(self, data, metaData=None, enc=True):
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = prepData(data, metaData=metaData)

        if self.verifiedUser and enc:
            data = self.currentUser.encryptData(data)

        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def sendData(self, data, metaData=None, enc=True):
        if self.server.loop:
            try:
                asyncio.run_coroutine_threadsafe( self.send_data(data, metaData=metaData, enc=enc), self.server.loop )
            except Exception as e:
                print("ERROR: {}".format(e))

    async def send_raw(self, data, enc=True):
        try:
            if type(data) != str and type(data) != bytes:
                data = str(data)
            if type(data) == str:
                data = data.encode()

            if self.verifiedUser and enc:
                data = self.currentUser.encryptData(data)

            data = data + self.sepChar
            self.writer.write(data)
            await self.writer.drain()
        except ConnectionResetError:
            pass

    def sendRaw(self, data, enc=True):
        if self.server.loop:
            try:
                asyncio.run_coroutine_threadsafe( self.send_raw(data, enc=enc), self.server.loop )
            except Exception as e:
                print("ERROR: {}".format(e))

    def disconnect(self):
        self.sendRaw("disconnect")
        self.writer.close()
        self.logout()

    def blacklist(self, bTime=600):
        if self.server.loop:
            asyncio.run_coroutine_threadsafe( self.server.blacklistIP(self.addr, bTime=bTime), self.server.loop )

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
        self.loop = None
        self.chunkSize = 1000

        self.downloading = False

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
            if type(password) == bytes:
                password = password.decode()
            if type(password) != str:
                password = str(password)
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

    def gotData(self, client, data, metaData):
        pass

    def lostClient(self, client):
        pass

    def newClient(self, client):
        pass

    def blacklisted(self, addr):
        pass

    def loggedIn(self, client, user):
        pass

    def downloadStarted(self, client):
        pass

    def downloadStopped(self, client):
        pass

    async def blacklistIP(self, addr, bTime=600):
        self.blacklist[addr] = time.time()+bTime
        await self.log( "Blacklisted {} for {} seconds".format(addr, bTime) )
        for client in self.clients:
            if client.addr == addr:
                client.disconnect()

    async def getData(self, client, reader, writer):
        data = None
        try:
            data = await reader.read(self.chunkSize)
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
                        client.sendRaw(b'login accepted', enc=False)
                        self.loggedIn(client, user)
                    else:
                        await self.log( "Failed login attempt - {} - {}:{}".format(username, client.addr, client.port) )
                        self.loginAttempts.append( [time.time(), client.addr] )

                        if len( [i for i in self.loginAttempts if i[0] >= time.time()-self.blacklistThreshold] ) > self.blacklistLimit:
                            await self.blacklistIP(client.addr)

                        client.disconnect()
                else:
                    await self.log("Login Failed - Username '{}' not recognized".format(username))
                    client.sendRaw(b'login failed')
        if data.startswith("encData:"):
            await self.log( "{} set encryption to {}".format(client.currentUser.username, data.split(":")[1]) )
            if data.split(":")[1] == "True":
                client.encData = True
            elif data.split(":")[1] == "False":
                client.encData = False
        elif data == "logout":
            if client.verifiedUser and client.currentUser:
                client.currentUser.logout(client)
                await self.log( "User logged out - {} - {}:{}".format(client.currentUser.username, client.addr, client.port) )

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
                client.disconnect()
                return

        if self.loginRequired and not client.verifiedUser:
            client.sendRaw(b'login required')

        self.newClient(client)

        client.buffer = b''

        while self.running:
            if self.loginRequired and not client.verifiedUser:
                if time.time() - client.connectionTime >= self.loginTimeout:
                    client.disconnect()
            data = await self.getData(client, reader, writer)
            if not data:
                break
            client.buffer += data

            for i in [  x for x in range(len( client.buffer.split(self.sepChar) )-1)  ]:
                self.downloading = False
                message = client.buffer.split(self.sepChar)[i]
                if client.verifiedUser and client.encData:
                    message = client.currentUser.decryptData(message)
                if message:
                    message, metaData, isRaw = dissectData(message)

                    if isRaw:
                        await self.gotRawData(client, message)
                    elif (self.loginRequired and client.verifiedUser) or not self.loginRequired:
                        if self.multithreading:
                            Thread(target = self.gotData, args=[client, message, metaData]).start()
                        else:
                            self.gotData(client, message, metaData)
            client.buffer = client.buffer.split(self.sepChar)[len(client.buffer.split(self.sepChar))-1]
            if client.buffer:
                if self.downloading == False:
                    self.downloading = True
                    if self.multithreading:
                        Thread(target=self.downloadStarted, args=[client]).start()
                    else:
                        self.downloadStarted(client)
            else:
                self.downloading = False
                if self.multithreading:
                    Thread(target=self.downloadStopped, args=[client]).start()
                else:
                    self.downloadStopped(client)

        await self.log("Lost Connection: {}:{}".format(client.addr, client.port))
        self.clients.remove(client)
        writer.close()
        client.logout()
        self.lostClient(client)

    async def start(self, useSSL=False, sslCert=None, sslKey=None):
        self.running = True
        ssl_context = None
        self.loop = asyncio.get_running_loop()

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

    def __init__(self, multithreading=False, verbose=False):
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
        self.loop = None
        self.buffer = b''
        self.downloading = False
        self.chunkSize = 1000
        self.verbose = verbose

        self.verifiedUser = False
        self.encData = True

    def setUserEncrypt(self, newValue):
        async def SET_USER_ENCD(self, newValue):
            self.encData = newValue
        if type(newValue) == bool and self.loop:
            sData = "encData:{}".format(str(newValue))
            self.sendRaw(sData)
            asyncio.run_coroutine_threadsafe( SET_USER_ENCD(self, newValue), self.loop )

    def __start_loop__(self, loop, task, finishFunc):
        asyncio.set_event_loop(loop)
        loop.run_until_complete( asyncio.ensure_future(task()) )
        if finishFunc:
            asyncio.run(finishFunc())

    def newLoop(self, task, finishFunc=None):
        new_loop = asyncio.new_event_loop()
        t = Thread( target=self.__start_loop__, args=(new_loop, task, finishFunc) )
        t.start()

    def encryptData(self, data):
        if self.login[1]:
            cData, salt = encrypt( data, self.login[1].encode() )
            data = salt+cData
            return data
        else:
            return data

    def decryptData(self, data):
        if self.login[1]:
            salt = data[:16]
            cData = data[16:]
            data = decrypt( cData, salt, self.login[1].encode() )
            return data
        else:
            return data

    def gotData(self, data, metaData):
        pass

    def lostConnection(self):
        pass

    def madeConnection(self):
        pass

    def loggedIn(self):
        pass

    def downloadStarted(self):
        pass

    def downloadStopped(self):
        pass

    async def getData(self, reader, writer):
        data = None
        try:
            data = await reader.read(self.chunkSize)
        except Exception as e:
            if self.verbose:
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
                self.sendRaw(b'LOGIN:'+username+b'|'+password)
        if data == b'login accepted':
            self.verifiedUser = True
            self.loggedIn()
            if not self.encData:
                self.encData = True
                await self.send_raw("encData:False")
                self.encData = False
        if data == b'login failed':
            self.loginFailed = True
        if data == b'disconnect':
            self.gotDisconnect = True

    async def logout(self):
        self.sendRaw(b'logout')

    async def handleHost(self):
        if self.multithreading:
            Thread(target=self.madeConnection).start()
        else:
            self.madeConnection()

        while self.connected and self.reader:
            data = await self.getData(self.reader, self.writer)
            if not data:
                self.connected = False
                break
            self.buffer += data

            for i in [  x for x in range(len( self.buffer.split(self.sepChar) )-1)  ]:
                self.downloading = False
                message = self.buffer.split(self.sepChar)[i]
                if self.login[1] and self.verifiedUser:
                    message = self.decryptData(message)
                if message:
                    message, metaData, isRaw = dissectData(message)
                    if isRaw:
                        await self.gotRawData(message)
                    else:
                        if self.multithreading:
                            Thread(target=self.gotData, args=[self, message, metaData]).start()
                        else:
                            self.gotData(self, message, metaData)
            self.buffer = self.buffer.split(self.sepChar)[len(self.buffer.split(self.sepChar))-1]
            if self.buffer:
                if self.downloading == False:
                    self.downloading = True
                    if self.multithreading:
                        Thread(target=self.downloadStarted).start()
                    else:
                        self.downloadStarted()
            else:
                self.downloading = False
                if self.multithreading:
                    Thread(target=self.downloadStopped).start()
                else:
                    self.downloadStopped()
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
            self.loop = asyncio.get_running_loop()

            future = asyncio.run_coroutine_threadsafe(self.handleSelf(), self.loop)

            result = self.loop.call_soon_threadsafe(await self.handleHost())
        except Exception as e:
            if self.verbose:
                print("ERROR: {}".format(e))
            self.connected = False
            self.conUpdated = time.time()
        self.connected = False
        self.conUpdated = time.time()

    async def send_data(self, data, metaData=None):
        if not self.connected:
            if self.verbose:
                print("ERROR: Event loop not connected. Unable to send data")
            return None
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = prepData(data, metaData=metaData)
        if self.login[1] and self.verifiedUser and self.encData:
            data = self.encryptData(data)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def sendData(self, data, metaData=None):
        if self.loop:
            try:
                asyncio.run_coroutine_threadsafe( self.send_data(data, metaData=metaData), self.loop )
            except Exception as e:
                if self.verbose:
                    print("ERROR: {}".format(e))

    async def send_raw(self, data):
        if not self.connected:
            print("ERROR: Event loop not connected. Unable to send data")
            return None
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        if self.login[1] and self.verifiedUser and self.encData:
            data = self.encryptData(data)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def sendRaw(self, data):
        if self.loop:
            try:
                asyncio.run_coroutine_threadsafe( self.send_raw(data), self.loop )
            except Exception as e:
                print("ERROR: {}".format(e))

    def waitForConnection(self, timeout=None):
        startTime = time.time()
        while self.conUpdated < startTime:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.connected

    def waitForLogin(self, timeout=None):
        startTime = time.time()
        while not self.verifiedUser and not self.gotDisconnect and not self.loginFailed and self.connected:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.verifiedUser

    def disconnect(self):
        if self.connected and self.writer:
            self.writer.close()
            self.connected = False



def receivedText(client, data, metaData):
    if data == b'exit':
        client.disconnect()
    print("Data Length: {}".format( len(data) ))
    print("Meta:        {}".format(metaData))


def connection(client):
    client.sendData("Thank you for connecting")

if __name__ == "__main__":
    x = Host("localhost", 8888, verbose=True, logging=True, loginRequired=True)
    x.addUser("admin", password="test123")
    x.gotData = receivedText
    x.newClient = connection
    asyncio.run( x.start(useSSL=False, sslCert=None, sslKey=None) )
