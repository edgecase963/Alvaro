#!/usr/bin/env python
import sys, os, time, asyncio
__version__ = "0.1.0 (Beta)"



class Connection():
    endChar = b'\t\t_END_\t\t'

    def __init__(self, addr, port, reader, writer):
        self.connectionTime = time.time()
        self.addr = addr
        self.port = port
        self.reader = reader
        self.writer = writer

    async def sendData(self, data):
        if type(data) == str:
            data = data.encode()
        self.writer.write(data+self.endChar)
        await self.writer.drain()


class Host():
    endChar = b'\t\t_END_\t\t'

    def __init__(self, addr, port, verbose=False, logging=False, logFile=None):
        self.running = False
        self.addr = addr
        self.port = port
        self.clients = []
        self.verbose = verbose

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

    def gotData(self, client, data):
        pass

    def lostClient(self, client):
        pass

    def newClient(self, client):
        pass

    async def getData(self, client, reader, writer, length=100):
        data = await reader.read(length)
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
            while self.endChar in buffer:
                message = buffer.split(self.endChar)[0]
                self.log( "Received Data | Client: {}:{} | Size: {}".format(client.addr, client.port, len(data)-len(self.endChar)) )
                self.gotData(client, message)
                buffer = buffer[len(buffer.split(self.endChar)[0])+len(self.endChar):]

        self.log("Lost Connection: {}:{}".format(client.addr, client.port))
        self.clients.remove(client)
        writer.close()
        self.lostClient(client)

    async def main(self):
        server = await asyncio.start_server(self.handleClient, self.addr, self.port)

        addr = server.sockets[0].getsockname()

        #await self.getData()

        async with server:
            await server.serve_forever()

    def start(self):
        self.running = True
        if self.logging:
            if self.logFile == None: self.logFile = "log.txt"
            self.log("Server Started")
        asyncio.run(self.main())



class Client():
    endChar = b'\t\t_END_\t\t'

    def __init__(self):
        self.connected = False
        self.reader = None
        self.writer = None
        self.hostAddr = None
        self.hostPort = None
        self.conUpdated = time.time()   # Last time the connection status was changed

    async def gotData(self, data):
        pass

    def lostConnection(self):
        pass

    def madeConnection(self):
        pass

    async def getData(self, reader, writer, length=100):
        data = await reader.read(length)
        return data

    async def handleHost(self):
        buffer = b''

        while self.connected and self.reader:
            data = await self.getData(self.reader, self.writer)
            if not data:
                break
            buffer += data
            while self.endChar in buffer:
                message = buffer.split(self.endChar)[0]
                await self.gotData(message)
                buffer = buffer[len(buffer.split(self.endChar)[0])+len(self.endChar):]
        return self.lostConnection

    async def connect(self, hostAddr, hostPort):
        try:
            self.reader, self.writer = await asyncio.open_connection(hostAddr, hostPort)

            self.connected = True
            self.conUpdated = time.time()
            loop = asyncio.get_running_loop()
            result = loop.call_soon_threadsafe(await self.handleHost())
        except:
            self.connected = False
            self.conUpdated = time.time()
        self.connected = False
        self.conUpdated = time.time()

    async def sendData(self, data):
        if type(data) == str:
            data = data.encode()
        self.writer.write(data+self.endChar)
        await self.writer.drain()

    def waitForConnection(self, timeout=None):
        startTime = time.time()
        while self.conUpdated < startTime:
            if timeout:
                if time.time() >= startTime+float(timeout):
                    break
        return self.connected



def received(client, data):
    pass

async def connection(client):
    await client.sendData("Thank you for connecting")

if __name__ == "__main__":
    x = Host("localhost", 8888, verbose=True, logging=True)
    x.gotData = received
    x.newClient = connection
    x.start()
