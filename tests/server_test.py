#!/usr/bin/env python
import asyncio
import sys

if sys.platform == "linux":
    sys.path.append("../alvaro")
elif sys.platform == "win32":
    sys.path.append(1, "..\\alvaro\\")

import alvaro


async def serverStarted(server):
    server.loadUsers("users")

async def echoData(client, data, metaData):
    if data == "testing speed":
        client.testingSpeed = True
    if data == "exit":
        client.disconnect("Exit detected")
    if not client.testingSpeed:
        print("Got Data: {}".format(data))
        if metaData:
            print("Meta Data: {}".format(metaData))
    client.sendData(data)

async def newClient(client):
    client.testingSpeed = False

async def lostClient(client):
    pass

async def userLogin(client, user):
    pass

async def downloading(client):
    print("Download started...\n")
    while client.downloading:
        dProg = client.getDownloadProgress()
        sys.stdout.write("\rProgress: {}%    ".format(int(dProg[0] / dProg[1] * 100.0)))
        sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    server = alvaro.Host(
        "localhost",
        8888,
        verbose=True,
        logging=False,
        loginRequired=True,
        multithreading=False,
    )
    server.gotData = lambda client, data, meta: echoData(client, data, meta)
    server.downloadStarted = downloading
    server.newClient = newClient
    server.lostClient = lostClient
    server.loggedIn = userLogin
    server.serverStarted = serverStarted

    try:
        asyncio.run(server.start(useSSL=False, sslCert=None, sslKey=None))
    except KeyboardInterrupt:
        print("Ending script...")
        sys.exit()
