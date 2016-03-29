import json
import re

from autobahn.websocket.types import ConnectionDeny
import pytest
import txaio

from shampoo import shampoo


txaio.use_asyncio()


@pytest.fixture(scope='function')
def ws_request():
    class Request:
        peer = ''
        path = 'path'
        protocols = ['shampoo']
        params = []
        headers = []
    return Request()


@pytest.fixture(scope='function')
def protocol(ws_request):
    p = shampoo.ShampooProtocol()
    p._request = ws_request
    return p


def test_set_json_decoder(monkeypatch):
    monkeypatch.setattr(shampoo, 'json_coders', {})
    shampoo.set_json_decoder('decoder')

    assert shampoo.json_coders['JSONDecoder'] == 'decoder'


def test_set_json_encoder(monkeypatch):
    monkeypatch.setattr(shampoo, 'json_coders', {})
    shampoo.set_json_encoder('encoder')

    assert shampoo.json_coders['JSONEncoder'] == 'encoder'


def test_register_endpoint(monkeypatch):
    monkeypatch.setattr(shampoo, 'endpoints', [])

    shampoo.register_endpoint(r'regexp', 'class')

    assert shampoo.endpoints == [
        {'re': re.compile(r'regexp'), 'class': 'class'}
    ]


def test_get_endpoint():
    shampoo.endpoints = [
        {
            're': re.compile(r'/test/(?P<id>\d+)/'),
            'class': 'class'
        }
    ]

    result = shampoo.get_endpoint('/test/6/')

    assert result == ('class', {'id': '6'})

    with pytest.raises(shampoo.ShampooNoEndpointMatchError):
        shampoo.get_endpoint('/test/')


def test_get_endpoint_instance(monkeypatch):
    endpoint_kwargs = {'item_id': 3}

    def get_endpoint(path):
        def endpoint_class(**kwargs):
            return kwargs
        return endpoint_class, endpoint_kwargs
    monkeypatch.setattr(shampoo, 'get_endpoint', get_endpoint)

    protocol_kwargs =\
        {'protocol': {}, 'peer': 'peer', 'params': [], 'headers': []}

    result = shampoo.get_endpoint_instance(path='/path/', **protocol_kwargs)

    assert result == {**protocol_kwargs, **endpoint_kwargs}


def test_on_connect_success(monkeypatch, mocker, ws_request):
    monkeypatch.setattr(shampoo, 'WebSocketServerProtocol', object)
    mocker.patch(
        'shampoo.shampoo.get_endpoint_instance', return_value='endpoint')
    p = shampoo.ShampooProtocol()

    p.onConnect(ws_request)
    assert p._request == ws_request
    assert p._endpoint == 'endpoint'
    shampoo.get_endpoint_instance.assert_called_once_with(
        ws_request.path, protocol=p, peer=ws_request.peer,
        params=ws_request.params, headers=ws_request.headers)


def test_on_connect_missing_shampoo_protocol(monkeypatch, mocker, ws_request):
    monkeypatch.setattr(shampoo, 'WebSocketServerProtocol', object)
    mocker.patch(
        'shampoo.shampoo.get_endpoint_instance', return_value='endpoint')
    monkeypatch.setattr(ws_request, 'protocols', [])
    p = shampoo.ShampooProtocol()

    with pytest.raises(ConnectionDeny) as exc_info:
        p.onConnect(ws_request)
    assert exc_info.value.code == 400
    assert 'No matching protocol' in exc_info.value.reason


def test_on_connect_no_matching_endpoint(monkeypatch, mocker, ws_request):
    monkeypatch.setattr(shampoo, 'WebSocketServerProtocol', object)
    mocker.patch(
        'shampoo.shampoo.get_endpoint_instance',
        side_effect=shampoo.ShampooNoEndpointMatchError)
    p = shampoo.ShampooProtocol()

    with pytest.raises(ConnectionDeny) as exc_info:
        p.onConnect(ws_request)
    assert exc_info.value.code == 404
    assert 'No matching endpoint found.' in exc_info.value.reason


def test_on_connect_endpoint_init_error(monkeypatch, mocker, ws_request):
    monkeypatch.setattr(shampoo, 'WebSocketServerProtocol', object)
    mocker.patch(
        'shampoo.shampoo.get_endpoint_instance',
        side_effect=shampoo.ShampooEndpointInitializationError(
            code=403, reason='Verboten'))
    p = shampoo.ShampooProtocol()

    with pytest.raises(shampoo.ConnectionDeny) as exc_info:
        p.onConnect(ws_request)
    assert exc_info.value.code == 403
    assert 'Verboten' in exc_info.value.reason


def test_on_message_success(mocker, protocol):
    call_data = ('method', 'request_data', 'request_id')
    mocker.patch.object(protocol, '_get_call_data', return_value=call_data)
    mocker.patch.object(protocol, '_get_response', return_value='response')
    mocker.patch.object(protocol, '_send')

    protocol.onMessage('payload', False)
    protocol._get_call_data.assert_called_once_with('payload', False)
    protocol._get_response.assert_called_once_with(*call_data)
    protocol._send.assert_called_once_with('response')


def test_on_message_payload_error(mocker, protocol):
    mocker.patch.object(
        protocol, '_get_call_data',
        side_effect=shampoo.ShampooPayloadError('message', 'reason'))
    mocker.patch.object(protocol, 'sendClose')
    mocker.patch.object(
        protocol, '_get_response',
        side_effect=Exception('_get_response should not be called!'))
    mocker.patch.object(
        protocol, '_send',
        side_effect=Exception('_send should not be called!'))

    protocol.onMessage('payload', False)
    protocol.sendClose.assert_called_once_with(
        code=shampoo.PROTOCOL_VIOLATION_CODE, reason='reason')


def test_on_close(mocker, protocol):
    endpoint = mocker.stub()
    endpoint.cleanup = mocker.stub()
    mocker.patch.object(protocol, '_endpoint', endpoint)
    mocker.patch.object(protocol, 'cancel_tasks')

    protocol.onClose(True, 101, 'test')

    endpoint.cleanup.assert_called_once_with()
    protocol.cancel_tasks.assert_called_once_with()


def test_on_close_no_endpoint(protocol):
    protocol.onClose(True, 101, 'test')


def test_on_close_cleanup_error(mocker, protocol):
    endpoint = mocker.stub()
    endpoint.cleanup = mocker.stub()
    mocker.patch.object(protocol, '_endpoint', endpoint)
    mocker.patch.object(endpoint, 'cleanup', side_effect=AttributeError)

    protocol.onClose(True, 101, 'test')


def test_on_open(protocol):
    protocol.onOpen()


def test_register_coroutine(mocker, monkeypatch, protocol):
    coroutine = mocker.stub()
    protocol.factory = mocker.stub()
    protocol.factory.loop = mocker.stub()
    protocol.factory.loop.create_task = mocker.stub()

    protocol.register_coroutine(coroutine)
    coroutine.assert_called_once_with()
    protocol.factory.loop.create_task.assert_called_once_with(coroutine())


def test_register_coroutine_store_tasks(mocker, monkeypatch, protocol):
    coroutine = mocker.stub()
    protocol.factory = mocker.stub()
    protocol.factory.loop = mocker.stub()
    protocol.factory.loop.create_task = mocker.stub()
    mocker.patch.object(
        protocol.factory.loop, 'create_task', return_value='task')
    monkeypatch.setattr(protocol, '_tasks', None)

    protocol.register_coroutine(coroutine)
    assert protocol._tasks == ['task']

    protocol.register_coroutine(coroutine)
    assert protocol._tasks == ['task', 'task']


def test_websocket_endpoint(mocker):
    endpoint_re = r'endpoint_re'
    cls = mocker.stub()
    mocker.patch.object(shampoo, 'register_endpoint')

    outer_wrapper = shampoo.websocket_endpoint(endpoint_re)
    wrapper = outer_wrapper(cls)

    shampoo.register_endpoint.assert_called_once_with(endpoint_re, cls)

    wrapper('arg', kwargs='kwargs')

    cls.assert_called_once_with('arg', kwargs='kwargs')


def test_websocket_method(mocker):
    fn = mocker.stub()

    result = shampoo.websocket_method(fn)

    assert result == fn
    assert result.is_endpoint_method is True


def test_send(mocker, protocol):
    mocker.patch.object(protocol, 'sendMessage')

    protocol._send({})
    protocol.sendMessage.assert_called_once_with(b'{}', False)


def test_send_uses_json_encoder(mocker, protocol):
    mocker.patch.object(protocol, 'sendMessage')
    mocker.patch('json.dumps')

    protocol._send({})
    shampoo.json.dumps.assert_called_once_with(
        {}, cls=shampoo.json_coders['JSONEncoder'])


def test_send_serialization_exception(mocker, protocol):
    mocker.patch.object(protocol, 'sendMessage')
    mocker.patch('json.dumps', side_effect=Exception)

    protocol._send({})

    protocol.sendMessage.assert_called_once_with(
        b'{"response_data": {}, "status": 500, "message": "An error occured '
        b'while processing the response."}', False)


def test_send_encoding_exception(mocker, protocol):
    mocker.patch.object(protocol, 'sendMessage')
    json_mock = mocker.stub()
    json_mock.encode = mocker.stub()
    mocker.patch.object(json_mock, 'encode', side_effect=Exception)
    mocker.patch('json.dumps', return_value=json_mock)

    protocol._send({})

    protocol.sendMessage.assert_called_once_with(
        b'{"response_data": {}, "status": 500, "message": "An error occured '
        b'while processing the response."}', False)


def test_get_call_data_binary(protocol):
    with pytest.raises(shampoo.ShampooPayloadError) as exc_info:
        protocol._get_call_data(b'payload', True)
    assert 'binary messages not supported' in exc_info.value.reason
    assert 'binary messages not supported' in exc_info.value.message


def test_get_call_data_invalid_json(protocol):
    with pytest.raises(shampoo.ShampooPayloadError) as exc_info:
        protocol._get_call_data(b'{', False)
    assert 'invalid json' in exc_info.value.reason


def test_get_call_data_validation_error(mocker, protocol):
    mocker.patch.object(
        shampoo.validator, 'validate',
        side_effect=shampoo.SchemaValidationError('message'))

    with pytest.raises(shampoo.ShampooPayloadError) as exc_info:
        protocol._get_call_data(b'{}', False)
    assert 'message' in exc_info.value.message
    assert 'message' in exc_info.value.reason


def test_get_call_data_success(mocker, protocol):
    mocker.patch.object(shampoo.validator, 'validate')

    result = protocol._get_call_data(
        b'{"method": "m", "request_data": "r", "request_id": "i"}', False)

    assert result == ('m', 'r', 'i')


def test_get_call_data_uses_json_encoder(mocker, protocol):
    mocker.patch.object(shampoo.validator, 'validate')
    mocker.patch('json.loads')

    msg = b'{"method": "m", "request_data": "r", "request_id": "i"}'
    protocol._get_call_data(msg, False)

    shampoo.json.loads.assert_called_once_with(
        msg.decode('utf8'), cls=shampoo.json_coders['JSONDecoder'])


def test_call_endpoint_method_does_not_exist(mocker, protocol):
    response = protocol._call_endpoint('method', 'request_data')

    assert response == ({}, 404, 'Method method does not exist')


def test_call_endpoint_method_exception(mocker, protocol):
    protocol._endpoint = mocker.stub()
    protocol._endpoint.method = mocker.stub()
    mocker.patch.object(protocol._endpoint, 'method', side_effect=Exception)
    protocol._endpoint.method.is_endpoint_method = True

    response = protocol._call_endpoint('method', 'request_data')

    assert response == ({}, 500, 'Uncaught exception during method call')


def test_get_call_endpoint_not_marked_valid(mocker, protocol):
    protocol._endpoint = mocker.stub()
    protocol._endpoint.method = mocker.stub()

    response = protocol._call_endpoint('method', 'request_data')

    assert response == ({}, 404, 'Method method does not exist')


def test_call_endpoint_success(mocker, protocol):
    protocol._endpoint = mocker.stub()
    protocol._endpoint.method = mocker.stub()
    mocker.patch.object(
        protocol._endpoint, 'method',
        return_value=('response_data', 'status', 'message'))
    protocol._endpoint.method.is_endpoint_method = True

    response = protocol._call_endpoint('method', 'request_data')

    assert response == ('response_data', 'status', 'message')


def test_call_endpoint_success_only_reponse_data(mocker, protocol):
    protocol._endpoint = mocker.stub()
    protocol._endpoint.method = mocker.stub()
    mocker.patch.object(
        protocol._endpoint, 'method', return_value='response_data')
    protocol._endpoint.method.is_endpoint_method = True

    response = protocol._call_endpoint('method', 'request_data')

    assert response == ('response_data', 200, 'ok')


def test_get_response(mocker, protocol):
    mocker.patch.object(
        protocol, '_call_endpoint',
        return_value=({}, 201, 'created'))

    response = protocol._get_response('test_method', 'data', 1)

    assert response == {'type': 'response', 'response_data': {}, 'status': 201,
                        'message': 'created', 'request_id': 1}
    protocol._call_endpoint.assert_called_once_with(
        'test_method', 'data')


def test_get_response_validate(mocker, protocol):
    mocker.patch.object(
        protocol, '_call_endpoint',
        return_value=('not valid', 201, 'created'))

    with pytest.raises(shampoo.SchemaValidationError):
        protocol._get_response('test_method', 'data', 1)


def test_send_message_custom_encoder(mocker, protocol):
    mocker.patch.object(
        protocol, '_call_endpoint',
        return_value=({}, 201, 'created'))

    class JSONEncoder(json.JSONEncoder):
        def encode(self, obj):
            return '{"decoded": true}'

    shampoo.json_coders['JSONEncoder'] = JSONEncoder

    response = protocol._get_response('test_method', 'data', 1)

    assert response == {'type': 'response', 'response_data': {'decoded': True},
                        'status': 201, 'message': 'created', 'request_id': 1}

    shampoo.json_coders['JSONEncoder'] = json.JSONEncoder


def test_send_message(mocker, ws_request):
    sendMessage = mocker.stub()
    mocker.patch(
        'autobahn.asyncio.websocket.WebSocketServerProtocol.sendMessage',
        sendMessage)

    protocol = shampoo.ShampooProtocol()
    protocol._request = ws_request
    protocol.sendMessage('payload', 'isBinary', kwarg='kwarg')

    sendMessage.assert_called_once_with('payload', 'isBinary', kwarg='kwarg')


def test_push_message(mocker, protocol):
    mocker.patch.object(shampoo.validator, 'validate')
    mocker.patch.object(protocol, '_send')

    protocol.push_message('event', {'data': 'data'})
    protocol._send.assert_called_once_with(
        {'type': 'push', 'push_event': 'event', 'push_data': {'data': 'data'}})

    shampoo.validator.validate.assert_called_once_with(
        {'type': 'push', 'push_event': 'event', 'push_data': {'data': 'data'}},
        'push_message.json')


def test_push_message_invalid_schema(mocker, protocol):
    mocker.patch.object(
        shampoo.validator, 'validate',
        side_effect=shampoo.SchemaValidationError('Invalid schema'))
    mocker.patch.object(protocol, '_send')

    protocol.push_message('event', 'data')

    protocol._send.assert_not_called()


def test_push_message_custom_encoder(mocker, protocol):
    mocker.patch.object(shampoo.validator, 'validate')
    mocker.patch.object(protocol, '_send')

    class JSONEncoder(json.JSONEncoder):
        def encode(self, obj):
            return '{"decoded": true}'

    shampoo.json_coders['JSONEncoder'] = JSONEncoder

    protocol.push_message('event', {'data': 'data'})
    protocol._send.assert_called_once_with(
        {'type': 'push', 'push_event': 'event', 'push_data':
         {'decoded': True}})

    shampoo.validator.validate.assert_called_once_with(
        {'type': 'push', 'push_event': 'event', 'push_data':
         {'decoded': True}},
        'push_message.json')

    shampoo.json_coders['JSONEncoder'] = json.JSONEncoder


def test_cancel_tasks(mocker, monkeypatch, protocol):
    monkeypatch.setattr(protocol, '_tasks', None)

    protocol.cancel_tasks()

    task = mocker.stub()
    task.cancel = mocker.stub()
    monkeypatch.setattr(protocol, '_tasks', [task])

    protocol.cancel_tasks()

    task.cancel.assert_called_once_with()
