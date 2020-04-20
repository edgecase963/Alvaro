#!/usr/bin/env python
import sys, os, time, asyncio, ssl, concurrent, pickle
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
__version__ = "0.1.1 (Beta)"



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
    plainText = f.decrypt(cText)

    return plainText


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
            if metaStr.startswith(b'META:|'):
                metaStr = metaStr[6:]
                # meta-data exists - convert to dictionary
                metaData = unpackMetaStr(metaStr)
    else:
        return data, None, True
    return rawData, metaData, False



class User():
    def __init__(self, username):
        self.username = username
        self.cPass = None
        self.password = None   # This stays at `None` until the user is verified
        hasPassword = False
        verified = False

        self.connections = []

        self.loginAttempts = []

    def copy(self):
        userCopy = User(self.username)
        userCopy.cPass = self.cPass
        userCopy.hasPassword = self.hasPassword
        userCopy.loginAttempts = self.loginAttempts
        return userCopy

    def save(self, userDir):
        try:
            with open( os.path.join(userDir, username), "wb" ) as f:
                pickle.dump(self.copy(), f)
            return True
        except:
            return False

    def verify(self, password):
        if self.hasPassword
            if self.cPass and password:
                if password == decrypt(self.cPass[0], self.cPass[1], password):
                    return True
            else:
                return False
        else:
            return True

    def login(self, username, password, connection):
        if username == self.username and self.verify(password):
            self.connections.append(connection)
            self.password = password
            return True
        else:
            self.loginAttempts.append( [time.time(), connection.addr+"|"+str(connection.port)] )
            return False

    def addPassword(self, password, userDir):
        if not self.hasPassword:
            cText, salt = encrypt(password, password)
            self.cPass = [cText, salt]
        return self


class Connection():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self, addr, port, reader, writer):
        self.connectionTime = time.time()
        self.addr = addr
        self.port = port
        self.reader = reader
        self.writer = writer

    async def sendData(self, data, metaData=None):
        if type(data) != str and type(data) != bytes:
            data = str(data)
        if type(data) == str:
            data = data.encode()
        data = prepData(data, metaData=metaData)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def disconnect(self):
        self.writer.close()


class Host():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self, addr, port, verbose=False, logging=False, logFile=None):
        self.running = False
        self.addr = addr
        self.port = port
        self.clients = []
        self.verbose = verbose

        self.userPath = "users"

        self.logging = logging
        self.logFile = logFile

    def log(self, t):
        if type(t) == bytes: t = t.decode()
        logText = "[{}] {}\n".format(time.time(), t)
        if self.logging:
            if not os.path.exists(self.logFile):
                with open(self.logFile, "wb") as f: pass   # Create the path
            with open(self.logFile, "rb") as f: logData = f.read()
            with open(self.logFile, "wb") as f: f.write(logData + logText.encode())
        if self.verbose:
            sys.stdout.write(logText)
            sys.stdout.flush()

    async def gotData(self, client, data, metaData):
        pass

    async def lostClient(self, client):
        pass

    async def newClient(self, client):
        pass

    async def getData(self, client, reader, writer, length=100):
        data = None
        try:
            data = await reader.read(length)
        except:
            print("Exception occurred")
        return data

    async def handleClient(self, reader, writer):
        cliAddr = writer.get_extra_info('peername')
        client = Connection(cliAddr[0], cliAddr[1], reader, writer)
        self.clients.append(client)

        self.log("New Connection: {}:{}".format(client.addr, client.port))
        await self.newClient(client)

        buffer = b''

        while self.running:
            data = await self.getData(client, reader, writer)
            if not data:
                break
            buffer += data

            for i in [  x for x in range(len( buffer.split(self.sepChar) )-1)  ]:
                message = buffer.split(self.sepChar)[i]
                #message = buffer.split(self.startChar)[1].split(self.endChar)[0]
                #buffer = buffer[ len(corrData) + len(self.startChar) + len(message) + len(self.endChar): ]
                message, metaData, isRaw = dissectData(message)
                self.log( "Received Data | Client: {}:{} | Size: {}".format(client.addr, client.port, len(message)) )
                await self.gotData(client, message, metaData)
            buffer = buffer.split(self.sepChar)[len(buffer.split(self.sepChar))-1]

        self.log("Lost Connection: {}:{}".format(client.addr, client.port))
        self.clients.remove(client)
        writer.close()
        await self.lostClient(client)

    async def start(self, useSSL=False, sslCert=None, sslKey=None):
        self.running = True
        ssl_context = None

        server = None

        if self.logging:
            if self.logFile == None: self.logFile = "log.txt"
            self.log("Starting server...")

        if not os.path.exists(self.userPath):
            self.log("Creating user directory")
            os.path.mkdir(self.userPath)

        if useSSL and sslCert and sslKey:
            if os.path.exists(sslCert) and os.path.exists(sslKey):
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(sslCert, sslKey)

                server = await asyncio.start_server(self.handleClient, self.addr, self.port, ssl=ssl_context)
            else:
                self.log("Unable to load certificate files")
                return
        else:
            server = await asyncio.start_server(self.handleClient, self.addr, self.port)

        if server:
            self.log("Server started")
            async with server:
                await server.serve_forever()
        else:
            self.running = False
            self.log("Unable to start server")



class Client():
    sepChar = b'\n\t_SEPARATOR_\t\n'

    def __init__(self):
        self.connected = False
        self.reader = None
        self.writer = None
        self.hostAddr = None
        self.hostPort = None
        self.conUpdated = time.time()   # Last time the connection status was changed

    async def gotData(self, data, metaData):
        pass

    def lostConnection(self):
        pass

    def madeConnection(self):
        pass

    async def getData(self, reader, writer, length=100):
        data = None
        try:
            data = await reader.read(length)
        except:
            print("Exception occurred")
        return data

    async def handleHost(self):
        buffer = b''

        while self.connected and self.reader:
            data = await self.getData(self.reader, self.writer)
            print("Data: {}".format(data))
            if not data:
                self.connected = False
                break
            buffer += data

            for i in [  x for x in range(len( buffer.split(self.sepChar) )-1)  ]:
                message = buffer.split(self.sepChar)[i]
                #message = buffer.split(self.startChar)[1].split(self.endChar)[0]
                #buffer = buffer[ len(corrData) + len(self.startChar) + len(message) + len(self.endChar): ]
                #message = buffer.split(self.endChar)[0]
                message, metaData, isRaw = dissectData(message)
                await self.gotData(message, metaData)
                #buffer = buffer[len(buffer.split(self.endChar)[0])+len(self.endChar):]
            buffer = buffer.split(self.sepChar)[len(buffer.split(self.sepChar))-1]
        return self.lostConnection

    async def handleSelf(self):
        while self.connected:
            await asyncio.sleep(0.2)
        if not self.connected and self.reader:
            self.reader.feed_data(self.sepChar)

    async def connect(self, hostAddr, hostPort, useSSL=False, sslCert=None):
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

            #loop = asyncio.get_event_loop()
            future = asyncio.run_coroutine_threadsafe(self.handleSelf(), loop)

            result = loop.call_soon_threadsafe(await self.handleHost())
        except:
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

    def waitForConnection(self, timeout=None):
        startTime = time.time()
        while self.conUpdated < startTime:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.connected

    def disconnect(self):
        if self.connected and self.writer:
            self.writer.close()
            self.connected = False



async def receivedText(client, data, metaData):
    if data == b'exit': client.disconnect()
    print("Data: {}".format(data))
    print("Meta: {}".format(metaData))

async def connection(client):
    await client.sendData("Thank you for connecting")

if __name__ == "__main__":
    x = Host("localhost", 8888, verbose=True, logging=True)
    x.gotData = receivedText
    x.newClient = connection
    asyncio.run( x.start() )
