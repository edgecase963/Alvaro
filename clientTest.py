#!/usr/bin/env python
import time, asyncio, threading
import alvaro



def lostConnection():
    print("Connection Lost!")

def gotMessage(client, data, metaData):
    print("Got Message: {}".format(data))
    print("Meta-Data:   {}\n".format(metaData))

def connected():
    print("Connected!")

def downloading():
    print("Download started...")



if __name__ == "__main__":
    cli = alvaro.Client(verbose=True)

    cli.lostConnection = lostConnection
    cli.gotData = gotMessage
    cli.madeConnection = connected
    cli.downloadStarted = downloading

    target = lambda: asyncio.run(
        cli.connect("localhost", 8888,
                    useSSL=False,
                    sslCert=None,
                    login=("admin", "test123"))
    )

    cliThread = threading.Thread(target=target)
    cliThread.start()

    c = cli.waitForConnection(timeout=6)
    if c: print("Connected!")

    li = cli.waitForLogin(timeout=6)

    if c and li:
        print("Logged in!")

        while cli.connected:
            inp = input("Inp: ")
            cli.sendData(inp, metaData={"From Client?": "Yes"})
    else:
        print("Failure to connect")
