#!/usr/bin/env python
import time, asyncio, threading
import alvaro



def lostConnection():
    print("Connection Lost!")


if __name__ == "__main__":
    cli = alvaro.Client()

    cli.lostConnection = lostConnection

    cliThread = threading.Thread(target = lambda: asyncio.run(cli.connect("localhost", 8888)))
    cliThread.start()

    c = cli.waitForConnection(timeout=6)

    if c:
        print("Connected!")
        while True:
            inp = input("Inp: ")
            asyncio.run(cli.sendData(inp))
    else:
        print("Failure to connect")
