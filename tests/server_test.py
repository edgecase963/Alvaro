#!/usr/bin/env python
import alvaro
import asyncio


def echoData(client, data, metaData):
    if data == b"testing speed":
        client.testingSpeed = True
    if data == b"exit":
        client.disconnect("Exit detected")
    if not client.testingSpeed:
        print("Got Data: {}".format(data.decode()))
    client.sendData(data)

def newClient(client):
    client.testingSpeed = False

def downloading(client):
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
    server.addUser("admin", "test123")
    server.gotData = echoData
    server.downloadStarted = downloading
    server.newClient = newClient

    try:
        asyncio.run(server.start(useSSL=False, sslCert=None, sslKey=None))
    except KeyboardInterrupt:
        print("Ending script...")
        sys.exit()
