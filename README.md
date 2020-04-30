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


async def gotMessage(client, data, metaData):
    print( "Message: {}".format(data) )

async def newClient(client):
    print( "New connection from {}".format(client.addr) )
    client.sendData("Hello, World!")


server = alvaro.Host("localhost", 8888)

server.newClient = newClient
server.gotData = gotMessage

asyncio.run( server.start() )
```

When the chunk of code shown above is executed it will start a server on `localhost` (at port `8888`) and execute the `gotMessage` function when ever it receives data from a client. For every client that connects, the `newClient` function will be executed.

Due to the fact that Alvaro uses asyncio, a lot of the event functions it will execute require the `async` tag with that block of code.

Interchangeable functions for a server:
* `lostClient(client)`
* `newClient(client)`
* `gotData(client, data, metaData)`

Interchangeable functions for a client:
* `madeConnection()`
* `lostConnection()`
* `gotData(data, metaData)`



### Meta-Data
Alvaro has the ability to transfer `metaData` between nodes. This allows you to send extra chunks of information about data _with_ the data you are sending.

MetaData comes in the form of a dictionary variable and lets you describe what type of information you are sending and/or send extra bits of information alongside your data. This helps immensely with efficiency.

```
import alvaro, asyncio

async def gotMessage(client, data, metaData):
    print( "Message: {}".format(data) )
    
    if metaData["whoami"] == "client":
        print("MetaData transferred successfully!")

async def newClient(client):
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
