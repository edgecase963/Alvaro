# Alvaro
---
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Updates](https://pyup.io/repos/github/edgecase963/Alvaro/shield.svg)](https://pyup.io/repos/github/edgecase963/Alvaro/) [![Downloads](https://pepy.tech/badge/alvaro)](https://pepy.tech/project/alvaro) [![CodeFactor](https://www.codefactor.io/repository/github/edgecase963/alvaro/badge)](https://www.codefactor.io/repository/github/edgecase963/alvaro)

![Logo](readme_media/logo.png)

Alvaro is a high-level, event-based networking module built to save you time on your projects without compromising on reliability, security or functionality.
It offers SSL support, user management and many more features to help you on your projects.

### A quick demo..
![Alvaro Demo](demos/demo.gif)

To learn more, check out [the wiki!](https://github.com/edgecase963/Alvaro/wiki)

Tired of spending hours, sometimes even days writing up complicated code just to get two devices to talk to one another? Alvaro is what you're looking for. All the difficult tasks of flow control, encryption and _endless_ bugs all taken care of for you! This project provides you the ability to create a fully functional server in just a few lines of code. So you can dive right into your project.

After all, time is our most valuable resource.


```bash

# clone alvaro
git clone https://github.com/edgecase963/Alvaro

cd Alvaro

# Install requirements
pip3 install -r requirements.txt

# install Alvaro
sudo python3 setup.py install

```

Alternatively, you can also use the pip command to install Alvaro:
```bash
pip3 install alvaro
```

This project is completely open source and anyone is free to use it.


Alvaro comes with some built-in features to help make data transfer not just more reliable, but easier to manage and implement into your project. One of these is the ability to monitor an ongoing download.

![Download Demo](demos/download_demo.gif)


Below is a demonstration of how to set up a minimalistic server using Alvaro:

```python
import alvaro, asyncio

server = alvaro.Host("127.0.0.1", port=8888)
asyncio.run( server.start() )
```

Alvaro uses asyncio to host/run/manage its servers. In order to start a server, it must be started with the `asyncio.run` function.

If you're already using asynchronous software and want to run Alvaro in your program's main loop, simply use `await`

```python
import alvaro, asyncio

server = alvaro.Host("127.0.0.1", port=8888)

async def start_server():
    await server.start()
```
