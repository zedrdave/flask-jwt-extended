import pytest
from flask import Flask, jsonify, json

from flask_jwt_extended import JWTManager, jwt_required, create_access_token


@pytest.fixture(scope='function')
def app():
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'foobarbaz'
    JWTManager(app)

    @app.route('/protected1', methods=['GET'])
    @jwt_required
    def access_protected1():
        return jsonify(foo='bar')

    @app.route('/protected2', methods=['GET'])
    @jwt_required
    def access_protected2():
        return jsonify(foo='bar')

    @app.route('/protected3', methods=['GET'])
    @jwt_required(decode_key='banana')
    def access_protected3():
        return jsonify(foo='bar')

    return app


# TODO need tests for all view decorators. Probably test for cookies too, as
#      that goes to a different decode path.


def test_override_decode_key(app):
    test_client = app.test_client()

    with app.test_request_context():
        access_token = create_access_token('username')

    access_headers = {'Authorization': 'Bearer {}'.format(access_token)}

    response = test_client.get('/protected1', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    response = test_client.get('/protected2', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 200
    assert json_data == {'foo': 'bar'}

    response = test_client.get('/protected3', headers=access_headers)
    json_data = json.loads(response.get_data(as_text=True))
    assert response.status_code == 422
    assert json_data == {'msg': 'Signature verification failed'}
