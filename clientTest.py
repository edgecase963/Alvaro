#!/usr/bin/env python
import time, asyncio, threading
import alvaro



def lostConnection():
    print("Connection Lost!")


if __name__ == "__main__":
    cli = alvaro.Client()

    cli.lostConnection = lostConnection

    target = lambda: asyncio.run( cli.connect("localhost", 8888) )

    cliThread = threading.Thread(target=target)
    cliThread.start()

    c = cli.waitForConnection(timeout=6)

    if c:
        print("Connected!")

        while cli.connected:
            inp = input("Inp: ")
            asyncio.run( cli.sendData(inp, metaData={"From Client?": 1}) )
    else:
        print("Failure to connect")
