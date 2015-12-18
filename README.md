# Shampoo

[![Build Status](https://travis-ci.org/wendbv/shampoo.svg)](https://travis-ci.org/wendbv/shampoo)

Shampoo is a asyncio websocket protocol implementation for [Autobahn](http://autobahn.ws/python/).

Shampoo will connect incomming websockets to user defined `endpoint` classes based on their `path`. The connecting client can make calls to the endpoint using simple `JSON` messages and the endpoint can send the client push messages.

Note: Only python versions `3.5` and up are supported.

## Installation

```bash
$ pip install shampoo
```

## Example setup

First setup the Autobahn websocket server:

```python
#!/usr/bin/env python
import asyncio

from autobahn.asyncio.websocket import WebSocketServerFactory
from shampoo.shampoo import ShampooProtocol
import txaio

if __name__ == '__main__':
    txaio.use_asyncio()

    factory = WebSocketServerFactory('ws://localhost:9007', debug=False)
    factory.protocol = ShampooProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, '', 9007)
    server = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
```

This will give us a running server. Now we set up an example endpoint. We're
creating a 'number' endpoint. We can connect to the endpoint for the numbers
0 - 9 and create an endpoint to add a number. The endpoint connection will be
at `ws://localhost:9007/number/<number>/`.

```python
from shampoo import shampoo

@shampoo.websocket_endpoint('r/number/(?P<number>\d+)/?')
class NumberEndpoint():
    def __init__(self, number, protocol, peer, params, headers):
        """Connection initialization for the number endpoint"""

        self.number = int(number)

        // We only accept numbers 0 - 9.
        if self.number not in range(10):
            // Connection will be refused with http status code 404.
            raise shampoo.ShampooEndpointInitializationError(
                404, 'Number not available')

    def cleanup(self):
        """Called when the connection is closed. We can clean up here"""

    @shampoo.websocket_method()
    def add_number(self, request_data):
        """Method that can be called by the client.
        Needs to return a tuple with an `object`, `status_code` and a
        `message`. You can ommit the status code and the message.
        """
        return {
            "number": self.number + request_data['number']
        }, 200, 'ok'  ## You can ommit the status code and message
```

We registered the endpoint using a decorator. Note that we also had to use a
decorator for the add_number method. Only allowed methods can be remotely
called, this is to prevent someone from calling the `__init__` method or any
method you would not want to expose. You can manually set the method as
callable by by setting `NumberEndpoint.add_number.is_endpoint_method = True`.
You can also manually register the endpoint itself using `register_endpoint`.

```python
from shampoo.shampoo import register_endpoint

register_endpoint(r'/number/(?P<number>\d+)/?', NumberEndpoint)
```

That's it, now we can connect to this server and make calls. For example make
a connection to `ws://localhost:9007/number/3/`. The connection needs to
request the `shampoo` protocol, otherwise the connection will be refused.

When the connection is established we can make a call by sending a `JSON`
message:

```json
{
    "method": "is_prime",
    "request_data": {
        "number": 4
    },
    "request_id": 1
}
```

This will give the following response:

```json
{
    "response_data": {
        "number": 7
    },
    "message": "ok",
    "status": 200,
    "request_id": 1
}
```

For the exact specification of the request and response `JSON` see
[request.json](schemas/request.json) and
[response.json](schemas/response.json).


## Push messages

You can notifiy a connected client of any events with push messages. This is
an example using `redis pubsub`.

```python
import asyncio
import asyncio_redis

from shampoo import shampoo

@shampoo.websocket_endpoint('r/notifications/?')
class NotificationEndpoint():
    def __init__(protocol, **kwargs):
        self.protocol = protocol
        sef.protocol.register_coroutine(self.notifications)

    @asyncio.coroutine
    def notifications(self):
        self.redis = yield from asyncio_redis.Connection.create(
            host='127.0.0.1', port=6379)
        self.pubsub = yield from self.redis.start_subscribe()
        yield from self.pubsub.subscribe(['notifications'])
        while True:
            message = yield from self.pubsub.next_published()
            self._protocol.push_message({'message': message.value})
```

When you publish a message to redis with
`redis.publish('notifications', 'This is a notification!')`, the client
gets the following message:

```json
{
    "push_data": {
        "message": "This is a notification!"
    }
}
```

See for the exact specification [push_message.json](schemas/push_message.json).


## Custom JSON encoder en decoder

For JSON decoding and encoding the standard python `json` module is used. If
you want to use a custom encoder or decoder you can set them like this:

```python
from shampoo import shampoo
from custom_json import CustomJSONEncoder, CustomJSONDecoder

shampoo.set_json_encoder(CustomJSONEncoder)
shampoo.set_json_decoder(CustomerJSONDecoder)
```
