#!/usr/bin/env python
import time, sys, asyncio, threading
import alvaro



def lostConnection():
    print("Connection Lost!")

def gotMessage(client, data, metaData):
    diff = time.time()-float(data)
    speed = int(1./diff)
    client.lst.append(speed)
    viewThresh = 100
    if client.encData:
        viewThresh = 10
    try:
        shortened_list = client.lst[len(client.lst)-viewThresh:]
        client.lst = shortened_list
        avg = int(sum(shortened_list) / len(shortened_list))
        sys.stdout.write("\rAverage Speed: {} messages/s      ".format(avg))
        sys.stdout.flush()
        client.sendData( str(time.time()) )
    except:
        pass

def connected():
    print("Connected!")



if __name__ == "__main__":
    cli = alvaro.Client(verbose=True)

    cli.lostConnection = lostConnection
    cli.gotData = gotMessage
    cli.madeConnection = connected

    target = lambda: asyncio.run(
        cli.connect("localhost", 8888,
                    useSSL=False,
                    sslCert=None,
                    login=("admin", "test123")
                    )
        )

    cliThread = threading.Thread(target=target)
    cliThread.start()

    c = cli.waitForConnection(timeout=6)
    if c: print("Connected!")

    li = cli.waitForLogin(timeout=6)

    if c and li:
        print("Logged in!")
        cli.lst = []
        cli.sendData( str(time.time()) )
    else:
        if not c:
            print("Failure to connect")
        if not li:
            print("Failure to log in")
