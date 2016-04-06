import json
import logging
import os
import re

from autobahn.asyncio.websocket import WebSocketServerProtocol
from autobahn.websocket.types import ConnectionDeny
from schemavalidator import SchemaValidator, SchemaValidationError


logger = logging.getLogger('shampoo')

# Initiate JSON Schema Validator.
schema_path = os.path.join(os.path.dirname(__file__), 'schemas/')
validator = SchemaValidator(schema_path)

PROTOCOL_VIOLATION_CODE = 3012


# This is where registered endpoints are stored as
# {'re': <endpoint-regex>, 'class': <endpoint-class>}'.
endpoints = []


json_coders = {
    'JSONDecoder': json.JSONDecoder,
    'JSONEncoder': json.JSONEncoder
}


def set_json_decoder(cls):
    json_coders['JSONDecoder'] = cls


def set_json_encoder(cls):
    json_coders['JSONEncoder'] = cls


def register_endpoint(endpoint_re, endpoint_cls):
    """Register an endpoint to use with ShampooProtocol."""
    endpoints.append({
        're': re.compile(endpoint_re), 'class': endpoint_cls})


def get_endpoint(path):
    """Get the endpoint that matches the given path.

    Returns a tuple containing the first matching endpoint class and
    a dict with any named groups and their value from the regular
    expression.

    Raises `ShampooNoEndpointMatchError` when no match is found.
    """
    for endpoint in endpoints:
        result = endpoint['re'].search(path)
        if result:
            return endpoint['class'], result.groupdict()

    raise ShampooNoEndpointMatchError


def get_endpoint_instance(path, **kwargs):
    """Get an instance of the first matching registered endpoint.

    `kwargs` will be merged with any named groups from the regular
    expression and used to initiate the endpoint class.
    """
    endpoint_class, endpoint_kwargs = get_endpoint(path)
    return endpoint_class(**{**kwargs, **endpoint_kwargs})


def websocket_endpoint(endpoint_re):
    """Decorator to register a class as endpoint for ShampooProtocol.

    Usage: ``@websocket_endpoint(r'/path/to/endpoint/(?P<id>\d+)/?')``
    """
    def outer_wrapper(cls):
        register_endpoint(endpoint_re, cls)
        return cls
    return outer_wrapper


def websocket_method(fn):
    """Decorator to mark a function as valid endpoint method."""
    fn.is_endpoint_method = True
    return fn


class ShampooError(Exception):
    """General error for the shampoo module."""


class ShampooNoEndpointMatchError(ShampooError):
    """No endpoint matches the given path."""


class ShampooEndpointInitializationError(ShampooError):
    """Can be raised by the endpoint during initialization.

    This can be used to refuse a connection to the endpoint during
    initialization. `code` and `reason` are used in the `HTTP` response.
    So when a connecting client does not have the correct authorization
    one could do this:
    ``raise ShampooEndpointInitializationError(code=403, 'Access denied')``
    """
    def __init__(self, code=400, reason='Endpoint initialization failed'):
        self.code = code
        self.reason = reason
        super().__init__(reason)


class ShampooInvalidEndpointMethodError(ShampooError):
    """Requested endpoint method does not exist or is not registered."""


class ShampooPayloadError(ShampooError):
    """Raised when the connected clients sends an invalid request.

    This is used internally. When this exception is raised the connection
    is closed with status code 400 and the given `reason`. The message is
    only used to log and may include debug information.
    """
    def __init__(self, message, reason):
        self.message = message
        self.reason = reason
        super().__init__(message)


class ShampooProtocol(WebSocketServerProtocol):
    """Shampoo protocol implementation."""
    _request = None
    _endpoint = None
    _tasks = None

    def register_coroutine(self, coroutine):
        """Register an asyncio coroutine on the event loop."""
        logger.info({
            'message': 'Registering coroutine',
            'coroutine': coroutine.__name__, 'peer': self._request.peer,
            'path': self._request.path})
        task = self.factory.loop.create_task(coroutine())

        if self._tasks is None:
            self._tasks = [task]
        else:
            self._tasks.append(task)

    def cancel_tasks(self):
        """Cancel all registered tasks for this connection"""
        logger.info({
            'messages': 'Cancelling tasks', 'peer': self._request.peer,
            'path': self._request.path, 'tasks': self._tasks})
        if self._tasks:
            for task in self._tasks:
                task.cancel()

    def push_message(self, event, data):
        """Push a message to the connected client."""
        # If there is a custom encoder, encode the data and decode
        # with the default decoder, so jsonschema can handle the result.
        if json_coders['JSONEncoder'] is not json.JSONEncoder:
            data = json.loads(json.dumps(data, cls=json_coders['JSONEncoder']))

        push_request = {"type": "push", "push_event": event, "push_data": data}

        logger.debug(push_request)

        try:
            validator.validate(push_request, 'push_message.json')
            self._send(push_request)
        except SchemaValidationError as e:
            logger.error({
                'message': 'Invalid push message', 'peer': self._request.peer,
                'path': self._request.path},
                exc_info=e)

    def _send(self, response):
        """Send a response to the connected client.

        `response` will be json encoded.
        """
        try:
            json_data = json.dumps(response, cls=json_coders['JSONEncoder'])
            raw_response = json_data.encode('utf8')
        except Exception as e:
            logger.error({
                'message': 'JSON serialization error while sending response',
                'peer': self._request.peer,
                'path': self._request.path}, exc_info=e)
            raw_response =\
                b'{"response_data": {}, "status": 500, "message": '\
                b'"An error occured while processing the response."}'

        self.sendMessage(raw_response, False)

    @staticmethod
    def _get_call_data(payload, isBinary):
        """Get the request info from an incomming message."""
        if isBinary:
            reason = 'Protocol violation: binary messages not supported'
            raise ShampooPayloadError(message=reason, reason=reason)

        try:
            message = json.loads(
                payload.decode('utf8'), cls=json_coders['JSONDecoder'])
        except json.decoder.JSONDecodeError as e:
            reason = 'Protocol violation: invalid json'
            raise ShampooPayloadError(message=str(e), reason=reason)

        try:
            validator.validate(message, 'request.json')
            method = message['method']
            request_data = message['request_data']
            request_id = message['request_id']
        except SchemaValidationError as e:
            reason = 'Protocol violation: {}'.format(str(e))
            raise ShampooPayloadError(message=reason, reason=reason)

        return method, request_data, request_id

    def _call_endpoint(self, method, request_data):
        """Call a method on the registered endpoint and return it's response.

        Calls the requested method with the request data and
        returns a tuple with response_data, status and message.
        """
        logger.info({
            'peer': self._request.peer, 'method': method,
            'message': 'Calling endpoint method',
            'path': self._request.path})
        logger.debug({'request_data': request_data})

        try:
            try:
                fn = getattr(self._endpoint, method)
            except AttributeError:
                raise ShampooInvalidEndpointMethodError(
                    'Method is not defined')

            if (not hasattr(fn, 'is_endpoint_method')
                    or fn.is_endpoint_method is not True):
                raise ShampooInvalidEndpointMethodError(
                    'Method has not been registered')
        except ShampooInvalidEndpointMethodError as e:
            logger.warning(
                {'peer': self._request.peer, 'method': method,
                 'message': str(e), 'path': self._request.path})
            return {}, 404, 'Method {} does not exist'.format(method)

        try:
            response = fn(request_data)
            if type(response) == tuple:
                response_data, status, message = response
            else:
                response_data = response
                status, message = 200, 'ok'
            return response_data, status, message
        except Exception as e:
            message = 'Uncaught exception during method call'
            logger.error(
                {'peer': self._request.peer, 'method': method,
                 'message': message, 'path': self._request.path},
                exc_info=e)
            return {}, 500, message

    def _get_response(self, method, request_data, request_id):
        response_data, status, message =\
            self._call_endpoint(method, request_data)

        # If there is a custom encoder, encode the response and decode
        # with the default decoder, so jsonschema can handle the result.
        if json_coders['JSONEncoder'] is not json.JSONEncoder:
            response_data = json.loads(
                json.dumps(response_data, cls=json_coders['JSONEncoder']))

        response = {'type': 'response', 'response_data': response_data,
                    'status': status, 'message': message,
                    'request_id': request_id}
        logger.debug({'response': response})

        try:
            validator.validate(response, 'response.json')
        except SchemaValidationError as e:
            logger.error({
                'message': 'Invalid response', 'peer': self._request.peer,
                'method': method, 'path': self._request.path})
            raise e

        return response

    def sendMessage(self, payload, isBinary, **kwargs):
        """Send payload to the client.

        This is only a wrapper for the super object so we
        can log all sent messages.
        """
        logger.info({'message': 'Sending payload', 'isBinary': isBinary,
                     'peer': self._request.peer,
                     'path': self._request.path})
        logger.debug({'payload': payload})

        super().sendMessage(payload, isBinary, **kwargs)

    def onConnect(self, request):
        """Set up connection and handle endpoint initialization."""
        logger.info(
            {'request': request, 'message': 'Client connected',
             'peer': request.peer, 'path': request.path})

        self._request = request

        if 'shampoo' not in self._request.protocols:
            logger.warn(
                {'peer': self._request.peer, 'path': self._request.path,
                 'message': 'Client needs to request shampoo protocol'})
            raise ConnectionDeny(
                code=400, reason='No matching protocol, shampoo protocol '
                                 'needs to be requested.')

        try:
            self._endpoint = get_endpoint_instance(
                self._request.path, protocol=self, peer=self._request.peer,
                params=self._request.params, headers=self._request.headers)
        except ShampooNoEndpointMatchError:
            logger.warn(
                {'peer': self._request.peer, 'path': self._request.path,
                 'message': 'No matching endpoint'})
            raise ConnectionDeny(
                code=404, reason='No matching endpoint found.')
        except ShampooEndpointInitializationError as e:
            logger.warn(
                {'peer': self._request.peer,
                 'message': 'Initilization of endpoint failed',
                 'error_message': str(e), 'path': self._request.path})
            raise ConnectionDeny(code=e.code, reason=e.reason)
        except Exception as e:
            logger.error(
                {'peer': self._request.peer,
                 'message': 'Initilization of endpoint exception',
                 'error_message': str(e), 'path': self._request.path},
                exc_info=e)
            raise e

    def onOpen(self):
        """Connection is established.

        Only for logging purposes.
        """
        logger.info(
            {'message': 'Connection open', 'peer': self._request.peer,
             'path': self._request.path})

    def onMessage(self, payload, isBinary):
        """Message received.

        Gets request data from the message, calls endpoint method
        and returns the response.
        """
        logger.info({
            'message': 'Payload received', 'isBinary': isBinary,
            'peer': self._request.peer, 'path': self._request.path})
        logger.debug({'payload': payload})

        try:
            method, request_data, request_id = self._get_call_data(
                payload, isBinary)
        except ShampooPayloadError as e:
            logger.warn({
                'peer': self._request.peer, 'message': e.reason,
                'error_message': e.message,
                'path': self._request.path})
            self.sendClose(code=PROTOCOL_VIOLATION_CODE, reason=e.reason)
            return

        response = self._get_response(method, request_data, request_id)

        self._send(response)

    def onClose(self, wasClean, code, reason):
        """Connection closed.

        Call the `cleanup()` function on the endpoint so it can clean up.
        """
        logger.info({
            'action': 'onClose', 'wasClean': wasClean,
            'message': 'Connection closed', 'reason': reason,
            'peer': self._request.peer, 'path': self._request.path})

        self.cancel_tasks()

        if self._endpoint:
            try:
                self._endpoint.cleanup()
            except AttributeError:
                pass
