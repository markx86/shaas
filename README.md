# shaas
## (reverse) shell as a service

**shaas** is a little utility that lets you get reverse shell on demand on a remote machine.
The project is made up of three executables:
- a master server (`master.c`)
- a client (`client.c`)
- a payload (`payload/payload.c`)

The payload is a small executable (should be <1KB on x86_64) that connects to the master server.  
A client can make a request to the master server, with the port on which the client is listening as request data.  
The master server will forward this request to the payload along with the client's IP address, and the payload
will try to connect to client.  
On success, the payload will spawn a reverse shell with which the client can interact.  

All this mess just to evade firewalls 👍

> [!NOTE]
> **shaas** is a weekend project (more like a one-day project, but oh well :^) shit happens) so don't expect it to be pretty.

### BUILDING
```bash
$ git clone https://github.com/markx86/shaas.git
$ cd shaas
$ make [ARGS=VALUE]...
```
Build arguments for the `payload` executable
- `TARGET_CC` (defaults to `gcc`): the compiler to be used during the build process
- `TARGET_ARCH` (defaults to `x86_64`): the target architecture
- `TARGET_ARTIFACT` (defaults to `shaas.$TARGET_ARCH.payload`): the name of the resulting executable

Build arguments for the `master` server
- `MASTER_CC` (defaults to `gcc`): the compiler to be used during the build process
- `MASTER_ARCH` (defaults to `x86_64`): the target architecture
- `MASTER_IP` (defaults to `127.0.0.1`): the IP address of the server
- `MASTER_TARGET_PORT` (defaults to `1337`): the port the server listens to for the `payload` connection
- `MASTER_REQUEST_PORT` (defaults to `6969`): the port the server listens to for `client` connections
- `MASTER_ARTIFACT` (defaults to `shaas.$MASTER_ARCH.master`): the name of the resulting executable

Build arguments for the `client` executable
- `CLIENT_CC` (defaults to `gcc`): the compiler to be using during the build process
- `CLIENT_ARCH` (defaults to `x86_64`): the target architecture
- `CLIENT_PORT` (defaults to `4200`): the port the client listens to for a connection from the `payload`
- `CLIENT_ARTIFACT` (defaults to `shaas.$CLIENT_ARCH.client`): the name of the resulting executable

### TODO
- moar testing
- support shells other than GNU's /bin/sh
- support more architectures
- support for hostnames as master server address
