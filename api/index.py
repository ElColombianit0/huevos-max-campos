from api.app import application
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.wrappers import Response

application = DispatcherMiddleware(application)

def handler(event, context):
    from wsgiref.handlers import BaseHandler
    from io import BytesIO

    environ = {
        'REQUEST_METHOD': event['httpMethod'],
        'PATH_INFO': event['path'],
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'wsgi.version': (1, 0),
        'wsgi.url_scheme': 'http',
        'wsgi.input': BytesIO(event['body'].encode('utf-8') if event['body'] else b''),
        'wsgi.errors': BytesIO(),
        'wsgi.multithread': False,
        'wsgi.multiprocess': False,
        'wsgi.run_once': False,
    }

    if event.get('queryStringParameters'):
        environ['QUERY_STRING'] = '&'.join(
            f"{k}={v}" for k, v in event['queryStringParameters'].items()
        )

    headers = {}
    response_body = BytesIO()

    def start_response(status, response_headers):
        headers['status'] = status
        headers['headers'] = response_headers

    handler = BaseHandler()
    handler.wsgi_app = application
    handler.run(environ, start_response, response_body)

    return {
        'statusCode': int(headers['status'].split()[0]),
        'headers': dict(headers['headers']),
        'body': response_body.getvalue().decode('utf-8')
    }