#!/usr/bin/env python
import time
import sys
import asyncio
import threading

if sys.platform == "win32":
    sys.path.insert(1, "..\\alvaro\\")
elif sys.platform == "linux":
    sys.path.insert(1, "../alvaro/")

import alvaro


def lostConnection():
    print("Connection Lost!")


def gotMessage(client, data, metaData):
    print("\nGot Message: {}\n".format(data))


def connected():
    print("Connected!")


def downloading():
    print("Download started...")
    while cli.downloading:
        dProg = cli.getDownloadProgress()
        sys.stdout.write("\r{}    ".format(dProg[0] / dProg[1]))
        sys.stdout.flush()


if __name__ == "__main__":
    cli = alvaro.Client()

    cli.lostConnection = lostConnection
    cli.gotData = gotMessage
    cli.madeConnection = connected
    cli.downloadStarted = downloading

    target = lambda: asyncio.run(
        cli.connect(
            "localhost", 8888, useSSL=False, sslCert=None, login=("admin", "test123")
        )
    )

    cliThread = threading.Thread(target=target)
    cliThread.start()

    c = cli.waitForConnection(timeout=6)

    li = cli.waitForLogin(timeout=6)

    if c and li:
        print("Logged in!")
        print("Type what you want and press Enter to send")

        while cli.connected:
            try:
                inp = input("")
                cli.sendData(inp, metaData={"test": "test"})
            except KeyboardInterrupt:
                cli.disconnect()
                break
    else:
        if not c:
            print("Failure to connect")
        if not li:
            print("Failure to log in")
