#!/usr/bin/env python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from threading import Thread
import cryptography
import asyncio
import json
import base64
import time
import sys
import ssl
import os

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ModuleNotFoundError:
    # uvloop not installed
    # uvloop is not required for the script to run but it won't be as fast
    pass
except Exception as e:
    print("Error: {}".format(e))


def encrypt(plainText, password):
    if isinstance(password, str):
        password = password.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    cText = f.encrypt(plainText)
    return cText, salt


def encryptFile(filePath, password):
    if isinstance(password, str):
        password = password.encode()
    if not os.path.exists(filePath):
        return False
    if not os.path.isfile(filePath):
        return False
    try:
        with open(filePath, "rb") as f:
            data = f.read()
        cipherData, salt = encrypt(data, password)
        with open(filePath, "wb") as f:
            f.write(b"ENCRYPTED_FILE" + salt + cipherData)
        return True
    except Exception as e:
        print("Error encrypting file: {}".format(e))
        return False


def decrypt(cText, salt, password):
    if isinstance(password, str):
        password = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    try:
        plainText = f.decrypt(cText)
        return plainText
    except cryptography.fernet.InvalidToken:
        return False
    except Exception as e:
        print("Error decrypting data: {}".format(e))
        return False


def decryptFile(filePath, password):
    if isinstance(password, str):
        password = password.encode()
    if not os.path.exists(filePath):
        print("ERROR: Path does not exist")
        return False
    if not os.path.isfile(filePath):
        print("ERROR: Path is a directory")
        return False
    try:
        with open(filePath, "rb") as f:
            data = f.read()
        if not data.startswith(b"ENCRYPTED_FILE"):
            return True
        data = data.lstrip(b"ENCRYPTED_FILE")
        if len(data) <= 16:
            print("ERROR: File data corrupt or not encrypted")
            return False
        salt = data[:16]
        cipherData = data.lstrip(salt)
        plainData = decrypt(cipherData, salt, password)
        with open(filePath, "wb") as f:
            f.write(plainData)
    except Exception as e:
        print("Error decrypting file: {}".format(e))


def make_bytes(var):
    if isinstance(var, str):
        var = var.encode()
    if not isinstance(var, bytes):
        return make_bytes(str(var))
    return var


def convVarType(var, t):
    varDict = {"s": str, "i": int, "f": float}
    if t.lower() == "b":
        if var.lower() == "true":
            return True
        if var.lower() == "false":
            return False
        return bool(var)
    if t in varDict:
        return varDict[t](var)
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
        metaStr += (
            str(len(str(i)) + 1).zfill(18) + str(i.__class__).split("'")[1][0] + str(i)
        )
        metaStr += (
            str(len(str(metaData[i])) + 1).zfill(18)
            + str(metaData[i].__class__).split("'")[1][0]
            + str(metaData[i])
        )
    return metaStr.encode()


def prepData(data, metaData=None):
    # Prepares the data to be sent
    # Structure: DATA:| <data_length>.zfill(18) <raw-data> META:| <meta-string>
    # (ignore spaces)
    if isinstance(data, str):
        data = data.encode()
    pData = ""
    pData = b"DATA:|" + str(len(data)).encode().zfill(18) + data
    if metaData:
        pData = pData + b"META:|" + getMetaStr(metaData)
    return pData


def dissectData(data):
    # Used after data is received to prepare it for later
    rawData = ""
    metaData = None
    if data.startswith(b"DATA:|"):
        data = data.lstrip(b"DATA:|")  # Remove "DATA:|"
        dataLen = int(data[:18])  # Extract length of data
        data = data[18:]  # Remove the data length
        rawData = data[:dataLen]  # Get the raw data
        metaStr = data[dataLen:]  # Get the meta-data (if any)
        if metaStr != "":
            if metaStr.startswith(b"META:|"):  # Received Meta-Data
                metaStr = metaStr.lstrip(b"META:|")  # Remove "META:|"
                metaData = unpackMetaStr(metaStr)  # Convert Meta-Data to dictionary
    else:
        return data, None, True
    return rawData, metaData, False


class User:
    def __init__(self, username):
        self.username = username
        self._cipher_pass = None  # The encrypted password (ciphertext, salt)
        self.password = None  # This stays at `None` until the user is verified
        self.hasPassword = False

        self.connections = []

        self.loginHistory = []
        # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]
        #                         Login 1                        Login 2

        self.loginAttempts = []
        # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]
        #                        Attempt 1                      Attempt 2

    def encryptData(self, data):
        if self.hasPassword and self.password:
            cData, salt = encrypt(data, self.password.encode())
            data = salt + cData
            return data
        return data

    def decryptData(self, data):
        if self.hasPassword and self.password:
            salt = data[:16]
            cData = data[16:]
            data = decrypt(cData, salt, self.password.encode())
            return data
        return data

    def reset(self):
        self.password = None
        self.connections = []

    def save(self, userDir):
        user_info = {
            "username": self.username,
            "hasPassword": self.hasPassword,
            "loginHistory": self.loginHistory,
            "loginAttempts": self.loginAttempts,
        }

        if self._cipher_pass and self.hasPassword:
            secret_info = self._cipher_pass[1] + self._cipher_pass[0]

        savePath = os.path.join(userDir, self.username + ".json")
        secretPath = os.path.join(userDir, self.username + "-secret")

        with open(savePath, "w") as f:
            json.dump(user_info, f)
        if self._cipher_pass and self.hasPassword:
            with open(secretPath, "wb") as f:
                f.write(secret_info)
        return savePath

    def load(self, filePath):
        filePath = filePath.rstrip("/")
        if not os.path.exists(filePath):
            return
        fileName = os.path.basename(filePath)
        userDir = filePath.rstrip(fileName)

        if fileName.endswith(".json"):
            secretPath = os.path.join(userDir, fileName.replace(".json", "-secret"))
            with open(filePath, "r") as f:
                user_info = json.load(f)

            secret_info = None
            if os.path.exists(secretPath):
                with open(secretPath, "rb") as f:
                    secret_info = f.read()
            if secret_info and user_info["hasPassword"]:
                if len(secret_info) > 16:
                    self._cipher_pass = [secret_info[16:], secret_info[:16]]

            self.username = user_info["username"]
            self.hasPassword = user_info["hasPassword"]
            self.loginHistory = user_info["loginHistory"]
            self.loginAttempts = user_info["loginAttempts"]
            return self

    def verify(self, password):
        if isinstance(password, str):
            password = password.encode()
        if self.hasPassword:
            if self._cipher_pass and password:
                if password == decrypt(
                    self._cipher_pass[0], self._cipher_pass[1], password
                ):
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
            self.loginHistory.append([time.time(), connection.addr])
            connection.verifiedUser = True
            connection.currentUser = self
            return True
        self.loginAttempts.append([time.time(), connection.addr])
        return False

    def logout(self, client):
        client.verifiedUser = False
        client.currentUser = None
        if client in self.connections:
            self.connections.remove(client)
        if len(self.connections) == 0:
            self.password = None

    def addPassword(self, password):
        if isinstance(password, str):
            password = password.encode()
        if not self.hasPassword:
            cText, salt = encrypt(password, password)
            self._cipher_pass = [cText, salt]
            self.password = password
            self.hasPassword = True


class Connection:
    sepChar = b"\n\t_SEPARATOR_\t\n"

    def __init__(self, addr, port, reader, writer, server):
        self.connectionTime = time.time()
        self.addr = addr
        self.port = port
        self.reader = reader
        self.writer = writer

        self.server = server

        self.verifiedUser = False
        self.currentUser = None
        self.next_message_length = 0
        self.downloading = False

        self.encData = False

    def getDownloadProgress(self):
        if not self.writer.is_closing():
            if self.reader:
                return len(self.reader._buffer), self.next_message_length
                #       <current buffer length>, <target buffer length>
        return 0

    async def send_data(self, data, metaData=None, enc=True):
        data = make_bytes(data)
        data = prepData(data, metaData=metaData)

        if self.verifiedUser and enc and self.encData:
            data = self.currentUser.encryptData(data)

        data = data + self.sepChar
        await self.send_raw("msgLen={}".format(str(len(data))))
        self.writer.write(data)
        await self.writer.drain()

    def sendData(self, data, metaData=None, enc=True):
        if self.server.loop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.send_data(data, metaData=metaData, enc=enc), self.server.loop
                )
            except Exception as e:
                print("Error sending data: {}".format(e))

    async def send_raw(self, data, enc=True):
        try:
            data = make_bytes(data)

            if self.verifiedUser and enc and self.encData:
                data = self.currentUser.encryptData(data)

            data = data + self.sepChar
            self.writer.write(data)
            await self.writer.drain()
        except ConnectionResetError:
            pass

    def sendRaw(self, data, enc=True):
        if self.server.loop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.send_raw(data, enc=enc), self.server.loop
                )
            except Exception as e:
                print("Error sending data: {}".format(e))

    def disconnect(self, reason=None):
        if self.writer.is_closing():
            return
        if self.server:
            if self.server.loop:
                self.server.log("Disconnecting {} - {}...".format(self.addr, reason))
        self.sendRaw("disconnect")
        try:
            self.writer.close()
        except Exception as e:
            print("Error closing stream: {}".format(e))
        self.logout()

    def blacklist(self, bTime=600):
        if self.server.loop:
            asyncio.run_coroutine_threadsafe(
                self.server.blacklistIP(self.addr, bTime=bTime), self.server.loop
            )

    def logout(self):
        if self.currentUser:
            self.currentUser.logout(self)


class Host:
    sepChar = b"\n\t_SEPARATOR_\t\n"

    def __init__(
        self,
        addr,
        port,
        verbose=False,
        logging=False,
        logFile=None,
        loginRequired=False,
        multithreading=True,
    ):
        self.running = False
        self.addr = addr
        self.port = port
        self.clients = []
        self.verbose = verbose
        self.loginRequired = loginRequired
        self.loginTimeout = 12.0  # The amount of time to wait for a login before disconnecting the client (if logins are required)
        self.loginDelay = 0.6
        self.multithreading = multithreading
        self.loop = None
        self.defaultBlacklistTime = 600
        self.download_indication_size = 1024 * 10
        self.buffer_update_interval = 0.01
        self.default_buffer_limit = 644245094400
        self._enable_buffer_monitor = True

        self.loginAttempts = []
        # Structure: # Structure: [ [<time.time()>, <IP_Address>], [<time.time()>, <IP_Address>] ]
        #                                     Attempt 1                      Attempt 2

        self.blacklistThreshold = 1800  # (In seconds)
        # If too many login attempts are made within this threshold, the address will be blacklisted
        # 1800 = 30 minutes

        self.blacklistLimit = 6

        self.blacklist = {}
        # Structure: { <IP_address>: <time.time() + duration> }

        self._lock = asyncio.Lock()

        self.userPath = "users"
        self.users = {}
        # Structure: {"username": <User Class>}

        self.logging = logging
        self.logFile = logFile

        self._save_vars = ["blacklist", "loginAttempts"]
        # A list containing all server variables that will be saved when `self.save_server` is executed

    def __pack_server_info__(self):
        server_info = {}
        for sVar in self._save_vars:
            if sVar in self.__dict__:
                server_info[sVar] = self.__dict__[sVar]
        return server_info

    def __start_loop__(self, loop, task, finishFunc):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(asyncio.ensure_future(task()))
        if finishFunc:
            asyncio.run(finishFunc())

    def newLoop(self, task, finishFunc=None):
        new_loop = asyncio.new_event_loop()
        t = Thread(target=self.__start_loop__, args=(new_loop, task, finishFunc))
        t.start()

    def save(self, location, password=None):
        location = location.rstrip("/")
        base_name = os.path.basename(location)
        location_directory = location.rstrip(base_name)
        if os.path.exists(location_directory) or location.count("/") == 0:
            if not (location.endswith(".json")):
                location += ".json"
            with open(location, "w") as f:
                json.dump(self.__pack_server_info__(), f)
            if password:
                if isinstance(password, str):
                    password = password.encode()
                encryptFile(location, password)

    def load(self, location, password=None, wait=False):
        if os.path.exists(location):
            if os.path.isfile(location):
                if password:
                    if isinstance(password, str):
                        password = password.encode()
                    if isinstance(password, bytes):
                        decryptFile(location, password)
                with open(location, "rb") as f:
                    server_info = json.load(f)
                if password:
                    if isinstance(password, bytes):
                        encryptFile(location, password)
                for sVar in self._save_vars:
                    if sVar in self.__dict__ and sVar in server_info:
                        self.__dict__[sVar] = server_info[sVar]

    def loadUsers(self):
        self.log("Loading users...")
        for i in os.listdir(self.userPath):
            iPath = os.path.join(self.userPath, i)
            if os.path.isfile(iPath) and iPath.endswith(".json"):
                user = User("").load(iPath)
                self.users[user.username] = user
        self.log("Users loaded")

    def saveUsers(self):
        self.log("Saving users...")
        for username in self.users:
            savePath = self.users[username].save(self.userPath)
        self.log("Users saved")

    def addUser(self, username, password=None):
        if "." in username:
            return False
        user = User(username)
        if password:
            if isinstance(password, bytes):
                password = password.decode()
            if not isinstance(password, str):
                password = str(password)
            user.addPassword(password)
        if not username in self.users:
            self.users[username] = user
            return True
        return False

    async def __add_to_log__(self, text):
        await self._lock.acquire()
        if isinstance(text, bytes):
            text = text.decode()
        logText = "[{}]\t{}\n".format(time.time(), text)
        if self.logging:
            if not os.path.exists(self.logFile):
                with open(self.logFile, "wb") as f:
                    pass  # Create the path
            with open(self.logFile, "ab") as f:
                f.write(logText.encode())
        if self.verbose:
            sys.stdout.write(logText)
            sys.stdout.flush()
        self._lock.release()

    def log(self, text):
        if not self.loop:
            print("Loop not running - unable to log text")
        asyncio.run_coroutine_threadsafe(self.__add_to_log__(text), self.loop)

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

    def serverStarted(self, server):
        pass

    async def blacklistIP(self, addr, bTime=None):
        if not bTime:
            bTime = self.defaultBlacklistTime
        self.blacklist[addr] = time.time() + bTime
        self.log("Blacklisted {} for {} seconds".format(addr, bTime))
        for client in self.clients:
            if client.addr == addr:
                client.disconnect("Blacklisted")
        if self.multithreading:
            Thread(target=self.blacklisted, args=[addr]).start()
        else:
            self.blacklisted(addr)

    def __buffer_monitor__(self, client, reader):
        client.downloading = False
        while self.running and not client.writer.is_closing():
            if (
                len(reader._buffer) >= self.download_indication_size
                and not client.downloading
            ):
                client.downloading = True
                Thread(target=self.downloadStarted, args=[client]).start()
            if not reader._buffer and client.downloading:
                client.downloading = False
                Thread(target=self.downloadStopped, args=[client]).start()
            time.sleep(self.buffer_update_interval)

    async def getData(self, client, reader):
        data = b""
        try:
            data = await reader.readuntil(self.sepChar)
        except asyncio.LimitOverrunError as e:
            self.log(
                "ERROR: Buffer limit too small for incoming data ("
                " asyncio.LimitOverrunError ) - {}:{}".format(client.addr, client.port)
            )
        except asyncio.exceptions.IncompleteReadError:
            self.log(
                "asyncio.exceptions.IncompleteReadError - {}:{}".format(
                    client.addr, client.port
                )
            )
        except Exception as e:
            self.log("{} - {}:{}".format(e, client.addr, client.port))
        return data.rstrip(self.sepChar)

    async def gotRawData(self, client, data):
        if isinstance(data, bytes):
            data = data.decode()

        if data.startswith("msgLen=") and len(data) > 7:
            if not data[7:].isalnum():
                return
            client.next_message_length = int(data[7:])
            if client.next_message_length < self.default_buffer_limit:
                client.reader._limit = client.next_message_length
        elif data.startswith("LOGIN:") and "|" in data:
            if len(data.split("|")) == 2:
                data = data[6:]
                username, password = data.split("|")
                if username in self.users:
                    self.log("Login acquired - verifying {}...".format(client.addr))
                    user = self.users[username]
                    time.sleep(self.loginDelay)
                    if user.login(username, password, client):
                        self.log("{} logged in".format(username))
                        client.sendRaw(b"login accepted", enc=False)
                        if self.multithreading:
                            Thread(target=self.loggedIn, args=[client, user]).start()
                        else:
                            self.loggedIn(client, user)
                    else:
                        self.log(
                            "Failed login attempt - {} - {}:{}".format(
                                username, client.addr, client.port
                            )
                        )
                        self.loginAttempts.append([time.time(), client.addr])

                        if (
                            len(
                                [
                                    i
                                    for i in self.loginAttempts
                                    if i[0] >= time.time() - self.blacklistThreshold
                                ]
                            )
                            > self.blacklistLimit
                        ):
                            await self.blacklistIP(client.addr)

                        client.disconnect("Failed login")
                else:
                    self.log(
                        "Login Failed - Username '{}' not recognized".format(username)
                    )
                    client.sendRaw(b"login failed")
        elif data.startswith("encData:"):
            self.log(
                "{} set encryption to {}".format(
                    client.currentUser.username, data.split(":")[1]
                )
            )
            if data.split(":")[1] == "True":
                client.encData = True
            elif data.split(":")[1] == "False":
                client.encData = False
        elif data == "logout":
            if client.verifiedUser and client.currentUser:
                client.currentUser.logout(client)
                self.log(
                    "User logged out - {} - {}:{}".format(
                        client.currentUser.username, client.addr, client.port
                    )
                )

    async def handleClient(self, reader, writer):
        addr, port = writer.get_extra_info("peername")
        client = Connection(addr, port, reader, writer, self)
        self.clients.append(client)

        if self._enable_buffer_monitor:
            Thread(target=self.__buffer_monitor__, args=[client, reader]).start()

        self.log("New Connection: {}:{}".format(client.addr, client.port))

        if client.addr in self.blacklist:
            if self.blacklist[client.addr] < time.time():
                self.blacklist.pop(client.addr)
            else:
                client.disconnect("Blacklisted")
                return

        if self.loginRequired and not client.verifiedUser:
            client.sendRaw(b"login required")

        if self.multithreading:
            Thread(target=self.newClient, args=[client]).start()
        else:
            self.newClient(client)

        while self.running and not writer.is_closing():
            if self.loginRequired and not client.verifiedUser:
                if (
                    time.time() - client.connectionTime >= self.loginTimeout
                    and not client.verifiedUser
                ):
                    client.disconnect("Login timeout")
            data = await self.getData(client, reader)
            if not data:
                break

            if client.verifiedUser and client.encData:
                data = client.currentUser.decryptData(data)
            if data:
                data, metaData, isRaw = dissectData(data)

                if isRaw:
                    await self.gotRawData(client, data)
                elif (
                    self.loginRequired and client.verifiedUser
                ) or not self.loginRequired:
                    if self.multithreading:
                        Thread(
                            target=self.gotData, args=[client, data, metaData]
                        ).start()
                    else:
                        self.gotData(client, data, metaData)

        self.log("Lost Connection: {}:{}".format(client.addr, client.port))
        self.clients.remove(client)
        try:
            writer.close()
        except Exception as e:
            print("Error closing stream: {}".format(e))
        client.logout()
        if self.multithreading:
            Thread(target=self.lostClient, args=[client]).start()
        else:
            self.lostClient(client)

    async def start(self, useSSL=False, sslCert=None, sslKey=None, buffer_limit=65536):
        self.running = True
        ssl_context = None
        self.loop = asyncio.get_running_loop()

        server = None

        if self.logging:
            if self.logFile is None:
                self.logFile = "log.txt"
            self.log("Starting server...")

        if not os.path.exists(self.userPath):
            self.log("Creating user directory")
            os.mkdir(self.userPath)

        self.loadUsers()

        if useSSL and sslCert and sslKey:
            self.log("Loading SSL certificate...")
            if os.path.exists(sslCert) and os.path.exists(sslKey):
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.load_cert_chain(sslCert, sslKey)
                self.log("SSL certificate loaded")

                server = await asyncio.start_server(
                    self.handleClient,
                    self.addr,
                    self.port,
                    ssl=ssl_context,
                    limit=buffer_limit,
                )
            else:
                self.log("Unable to load certificate files")
                return
        else:
            server = await asyncio.start_server(
                self.handleClient, self.addr, self.port, limit=buffer_limit
            )

        if server:
            self.log("Server started")
            Thread(target=self.serverStarted, args=[self]).start()
            async with server:
                await server.serve_forever()
        else:
            self.running = False
            self.log("Unable to start server")


class Client:
    sepChar = b"\n\t_SEPARATOR_\t\n"

    def __init__(self, multithreading=False):
        self.connected = False
        self.reader = None
        self.writer = None
        self.hostAddr = None
        self.hostPort = None
        self.connection_updated = (
            time.time()
        )  # Last time the connection status was changed
        self.login = (None, None)
        self.multithreading = multithreading
        self.loop = None
        self.download_indication_size = 1024 * 10
        self.buffer_update_interval = 0.01
        self.next_message_length = 0
        self.default_buffer_limit = 644245094400
        self._enable_buffer_monitor = True

        self.downloading = False

        self._got_disconnect = False
        self._login_failed = False

        self.verifiedUser = False
        self.encData = False

    def setUserEncrypt(self, newValue):
        async def SET_USER_ENCD(self, newValue):
            self.encData = newValue

        if isinstance(newValue, bool) and self.loop:
            sData = "encData:{}".format(str(newValue))
            self.sendRaw(sData)
            asyncio.run_coroutine_threadsafe(SET_USER_ENCD(self, newValue), self.loop)

    def __start_loop__(self, loop, task, finishFunc):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(asyncio.ensure_future(task()))
        if finishFunc:
            asyncio.run(finishFunc())

    def newLoop(self, task, finishFunc=None):
        new_loop = asyncio.new_event_loop()
        t = Thread(target=self.__start_loop__, args=(new_loop, task, finishFunc))
        t.start()

    def encryptData(self, data):
        if self.login[1]:
            cData, salt = encrypt(data, self.login[1].encode())
            data = salt + cData
            return data
        return data

    def decryptData(self, data):
        if self.login[1]:
            salt = data[:16]
            cData = data[16:]
            data = decrypt(cData, salt, self.login[1].encode())
            return data
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

    def getDownloadProgress(self):
        if not self.writer.is_closing():
            if self.reader:
                return len(self.reader._buffer), self.next_message_length
                #       <current buffer length>, <target buffer length>
        return 0

    def __buffer_monitor__(self, reader):
        self.downloading = False
        while self.connected and not self.writer.is_closing():
            if (
                len(reader._buffer) >= self.download_indication_size
                and not self.downloading
            ):
                self.downloading = True
                Thread(target=self.downloadStarted).start()
            if not reader._buffer and self.downloading:
                self.downloading = False
                self.next_message_length = 0
                Thread(target=self.downloadStopped).start()
            time.sleep(self.buffer_update_interval)

    async def getData(self, reader, writer):
        data = b""
        try:
            data = await reader.readuntil(self.sepChar)
        except asyncio.LimitOverrunError:
            print(
                "ERROR: Buffer limit too small for incoming data ("
                " asyncio.LimitOverrunError )"
            )
        except asyncio.exceptions.IncompleteReadError:
            print("asyncio.exceptions.IncompleteReadError")
        except Exception as e:
            print("Error retrieving data: {}".format(e))
        return data.rstrip(self.sepChar)

    async def gotRawData(self, data):
        if isinstance(data, bytes):
            data = data.decode()

        if data.startswith("msgLen=") and len(data) > 7:
            if not data[7:].isalnum():
                return
            self.next_message_length = int(data[7:])
            if self.next_message_length < self.default_buffer_limit:
                self.reader._limit = self.next_message_length
        elif data == "login required":
            if self.login[0] and self.login[1]:
                username = self.login[0]
                password = self.login[1]
                username = make_bytes(username)
                password = make_bytes(password)
                self.sendRaw(b"LOGIN:" + username + b"|" + password)
        elif data == "login accepted":
            self.verifiedUser = True
            if self.multithreading:
                Thread(target=self.loggedIn).start()
            else:
                self.loggedIn()
        elif data == "login failed":
            self._login_failed = True
        elif data == "disconnect":
            self._got_disconnect = True

    async def logout(self):
        self.sendRaw(b"logout")

    async def handleHost(self):
        if self._enable_buffer_monitor:
            Thread(target=self.__buffer_monitor__, args=[self.reader]).start()

        if self.multithreading:
            Thread(target=self.madeConnection).start()
        else:
            self.madeConnection()

        while self.connected and self.reader and not self.writer.is_closing():
            data = await self.getData(self.reader, self.writer)
            if not data:
                self.connected = False
                break

            if self.login[1] and self.verifiedUser and self.encData:
                data = self.decryptData(data)
            if data:
                data, metaData, isRaw = dissectData(data)
                if isRaw:
                    await self.gotRawData(data)
                else:
                    if self.multithreading:
                        Thread(target=self.gotData, args=[self, data, metaData]).start()
                    else:
                        self.gotData(self, data, metaData)
        self.connected = False
        return self.lostConnection

    async def handleSelf(self):
        while self.connected:
            await asyncio.sleep(0.2)
        if not self.connected and self.reader:
            self.reader.feed_data(self.sepChar)

    async def connect(
        self,
        hostAddr,
        hostPort,
        login=(None, None),
        useSSL=False,
        sslCert=None,
        buffer_limit=65536,
    ):
        self.login = login
        self._got_disconnect = False
        self._login_failed = False
        try:
            ssl_context = None
            if useSSL and sslCert:
                if os.path.exists(sslCert):
                    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    ssl_context.load_verify_locations(sslCert)

            if ssl_context:
                self.reader, self.writer = await asyncio.open_connection(
                    hostAddr, hostPort, ssl=ssl_context, limit=buffer_limit
                )
            else:
                self.reader, self.writer = await asyncio.open_connection(
                    hostAddr, hostPort, limit=buffer_limit
                )

            self.connected = True
            self.connection_updated = time.time()
            self.loop = asyncio.get_running_loop()

            future = asyncio.run_coroutine_threadsafe(self.handleSelf(), self.loop)

            result = self.loop.call_soon_threadsafe(await self.handleHost())
        except Exception as e:
            print("Error with connection: {}".format(e))
            self.connected = False
            self.connection_updated = time.time()
        self.connected = False
        self.connection_updated = time.time()

    async def send_data(self, data, metaData=None):
        if not self.connected:
            print("ERROR: Event loop not connected. Unable to send data")
            return None
        data = make_bytes(data)
        data = prepData(data, metaData=metaData)
        if self.login[1] and self.verifiedUser and self.encData:
            data = self.encryptData(data)
        data = data + self.sepChar
        await self.send_raw("msgLen={}".format(str(len(data))))
        self.writer.write(data)
        await self.writer.drain()

    def sendData(self, data, metaData=None):
        if self.loop:
            try:
                asyncio.run_coroutine_threadsafe(
                    self.send_data(data, metaData=metaData), self.loop
                )
            except Exception as e:
                print("Error sending data: {}".format(e))
                self.disconnect()
        else:
            self.disconnect()

    async def send_raw(self, data):
        if not self.connected:
            print("ERROR: Event loop not connected. Unable to send data")
            return None
        data = make_bytes(data)
        if self.login[1] and self.verifiedUser and self.encData:
            data = self.encryptData(data)
        data = data + self.sepChar
        self.writer.write(data)
        await self.writer.drain()

    def sendRaw(self, data):
        if self.loop:
            try:
                asyncio.run_coroutine_threadsafe(self.send_raw(data), self.loop)
            except Exception as e:
                print("Error sending data: {}".format(e))
                self.disconnect()
        else:
            self.disconnect()

    def waitForConnection(self, timeout=None):
        startTime = time.time()
        while self.connection_updated < startTime:
            if timeout:
                if time.time() >= startTime + float(timeout):
                    break
        return self.connected

    def waitForLogin(self, timeout=None):
        startTime = time.time()
        while (
            not self.verifiedUser
            and not self._got_disconnect
            and not self._login_failed
            and self.connected
        ):
            try:
                if timeout:
                    if time.time() >= startTime + float(timeout):
                        break
            except Exception as e:
                print("Error waiting for login: {}".format(e))
                self.disconnect()
        return self.verifiedUser

    def disconnect(self):
        if self.connected:
            self.connected = False
        if self.writer:
            try:
                self.writer.close()
            except Exception as e:
                print("Error closing stream: {}".format(e))


def echoData(client, data, metaData):
    if data == b"exit":
        client.disconnect("Exit detected")
    print("Got Data: {}".format(data.decode()))
    client.sendData(data)


def downloading(client):
    print("Download started...\n")
    while client.downloading:
        dProg = client.getDownloadProgress()
        sys.stdout.write("\rProgress: {}%    ".format(int(dProg[0] / dProg[1] * 100.0)))
        sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    x = Host(
        "localhost",
        8888,
        verbose=True,
        logging=False,
        loginRequired=True,
        multithreading=False,
    )
    x.addUser("admin", "test123")
    x.gotData = echoData
    x.downloadStarted = downloading

    try:
        asyncio.run(x.start(useSSL=False, sslCert=None, sslKey=None))
    except KeyboardInterrupt:
        print("Ending script...")
        sys.exit()
