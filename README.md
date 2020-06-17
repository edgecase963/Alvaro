# Alvaro
---

Alvaro is an easy to use networking module built to save you time on your projects without compromising on reliability, security or functionality.


## Usage
Alvaro requires Asyncio. Fortunately, this is easy to implement into your code


### Basic Server

```
# Minimal server
import alvaro, asyncio

server = Alvaro.Host("localhost", 8888)
asyncio.run( server.start() )
```


### Basic Client
```
import alvaro, asyncio, threading

client = alvaro.Client()

t = lambda: asyncio.run( client.connect("localhost", 8888) )

clientThread = threading.Thread( target = t )
clientThread.start()

c = client.waitForConnection( timeout=6 )

if c:
    print("Connected!")
```

You do not have to use threading for this to work, but `client.connect()` blocks.
So if you have more code that needs to be executed, either do that before you connect to a server or use the threading module.



### Built in functions
Alvaro is also capable of executing blocks of code that you assign after certain events (such as data being received from a client)

```
import alvaro, asyncio


def gotMessage(client, data, metaData):
    print( "Message: {}".format(data) )

def newClient(client):
    print( "New connection from {}".format(client.addr) )
    client.sendData("Hello, World!")


server = alvaro.Host("localhost", 8888)

server.newClient = newClient
server.gotData = gotMessage

asyncio.run( server.start() )
```

When the chunk of code shown above is executed it will start a server on `localhost` (at port `8888`) and execute the `gotMessage` function when ever it receives data from a client. For every client that connects, the `newClient` function will be executed.

Interchangeable functions for a server:
* `lostClient(client)`
* `newClient(client)`
* `gotData(client, data, metaData)`
* `loggedIn(client, user)`
* `downloadStarted(client)`
* `downloadStopped(client)`

Interchangeable functions for a client:
* `madeConnection()`
* `lostConnection()`
* `loggedIn()`
* `gotData(client, data, metaData)`
* `downloadStarted()`
* `downloadStopped()`



### Meta-Data
Alvaro has the ability to transfer `metaData` between nodes. This allows you to send extra chunks of information about data _with_ the data you are sending.

MetaData comes in the form of a dictionary variable and lets you describe what type of information you are sending and/or send extra bits of information alongside your data. This helps immensely with efficiency.

```
import alvaro, asyncio

def gotMessage(client, data, metaData):
    print( "Message: {}".format(data) )

    if metaData["whoami"] == "client":
        print("MetaData transferred successfully!")

def newClient(client):
    print( "New connection from {}".format(client.addr) )

    client.sendData( "Hello, World!", metaData={"whoami": "server"} )

server = alvaro.Host("localhost", 8888)
server.newClient = newClient
server.gotData = gotMessage
asyncio.run( server.start() )
```

It's as easy as changing the `metaData` variable in the `sendData` function.



### Using SSL
Alvaro is capable of using SSL for added security.

```
import alvaro, asyncio


server = alvaro.Host("hostname.com", 8888)

asyncio.run( server.start(useSSL=True, sslCert="path/to/cert.crt", sslKey="path/to/key.key") )
```


#### SSL Client Usage
```
import alvaro, asyncio
from threading import Thread

client = alvaro.Client()

t = lambda: asyncio.run(
    client.connect("localhost", 8888,
        useSSL=True,
        sslCert="my_cert.crt")
    )

cThread = Thread( target = t )
cThread.start()

c = client.waitForConnection( timeout=6 )
```



### Integrated multithreading
Alvaro also has built-in multithreading support which you can take advantage of for both servers and clients.
To do so, simply run the `newLoop` function with a given task, like so:

```
import alvaro

async def testFunc():
    print("Hello, World!")

serv = alvaro.Host("localhost", 8888)
serv.newLoop(testFunc)
```
Output:
> Hello, World!

Note: The function you have assigned should have the `async` tag

The `newLoop` function will create a new asyncio loop and run which ever function you assigned to it in a separate thread. It is also possible to tell Alvaro to automatically run all callbacks, such as `gotData` and `madeConnection` in another thread by changing the `multithreading` variable to `True` in the Host class or Client class:
```
serv = alvaro.Host("localhost", 8888, multithreading=True)

cli = alvaro.Client(multithreading=True)
```
Note: The `multithreading` variable is already set as `True` for the Host and `False` for the Client by default.

This tells Alvaro to open a new thread and run the functions you've assigned for receiving data, connecting, logging in, etc.
This could potentially help with speed depending on which device you are using Alvaro on. For smaller devices (such as IoT devices like the Raspberry Pi) it is recommended to keep the `multithreading` variable to `False`. That will tell Alvaro to run all callbacks in the main thread.

The `newLoop` function for both the `Host` and `Client` classes also provides a `finishFunc` option. This function will be executed once the thread has finished its task.

```
import alvaro, asyncio

async def testFunc():
    print("Hello, World!")

async def finished():
    print("Finished test!")

serv = alvaro.Host("localhost", 8888)
serv.newLoop(testFunc, finishFunc=finished)
```


### Blacklisting
Alvaro servers also have the ability to blacklist an IP address so that all connections from that address are refused.

```
import alvaro, asyncio


def connection(client):
    client.blacklist()


serv = alvaro.Host("localhost", 8888)
serv.newLoop(testFunc, finishFunc=finished)
```
Of course it is not ideal to blacklist an IP immediately once it connects for no reason, but this function has its uses.
