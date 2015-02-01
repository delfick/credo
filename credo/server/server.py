from credo.structure.credential_path import CredentialPath
from credo.errors import CredoError, SamlNotAuthorized
from credo.amazon import IamSaml

from datetime import datetime, timedelta
from boto.utils import parse_ts
import logging
import pickle
import sys
import os

log = logging.getLogger("credo.server")

class Server(object):
    def __init__(self, host, port, credo):
        self.host = host
        self.port = port
        self.credo = credo

    def start(self):
        try:
            from tornado.httpserver import HTTPServer
            from tornado.wsgi import WSGIContainer
            from tornado.ioloop import IOLoop
        except ImportError:
            raise CredoError("Please pip install tornado")
        http_server = HTTPServer(WSGIContainer(self.app))
        http_server.listen(self.port, self.host)
        IOLoop.instance().start()

    @property
    def credentials(self):
        return getattr(self, "_credentials", None)

    @credentials.setter
    def credentials(self, val):
        self._credentials = val

    @property
    def basic_auth(self):
        if datetime.utcnow() > getattr(self, "_basic_auth_time", datetime.utcnow()) + timedelta(hours=4):
            self._basic_auth = None
        return getattr(self, "_basic_auth", None)

    @basic_auth.setter
    def basic_auth(self, val):
        self._basic_auth = val
        self._basic_auth_time = datetime.utcnow()

    @property
    def keys(self):
        keys = getattr(self, "_keys", None)
        if keys is not None:
            expiration = parse_ts(keys["Expiration"])
            if datetime.utcnow() > expiration:
                log.info("Keys expired, recreating them")
                keys = None

        if keys is None:
            log.info("Assuming role")
            pair = IamSaml(self.credentials.keys.provider, self.credentials.keys.idp_username, "")
            pair.basic_auth = self.basic_auth
            keys = pair.get_result(self.credentials.keys.role).credentials.to_dict()

            self._keys = {
                  "Code": "Success"
                , "LastUpdated": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S:00Z")
                , "AccessKeyId": keys["access_key"]
                , "SecretAccessKey": keys["secret_key"]
                , "Token": keys["session_token"]
                , "Expiration": keys["expiration"]
                }
        return self._keys

    @keys.setter
    def keys(self, val):
        self._keys = val

    @property
    def app(self):
        try:
            from flask import Flask
        except ImportError:
            raise CredoError("Please pip install flask")

        if getattr(self, "_app", None) is None:
            self._app = Flask("credo.server")
            self.register_routes(self._app)
        return self._app

    def register_routes(self, app):
        from flask import jsonify, abort, make_response, request

        @app.route('/', methods = ['GET'])
        def index():
            return 'latest'

        @app.route('/latest/', methods = ['GET'])
        def latest():
            return 'meta-data'

        @app.route('/latest/meta-data/', methods = ['GET'])
        def meta_data():
            return 'iam\nswitch'

        @app.route('/latest/meta-data/switch/', methods = ["POST"])
        def switch():
            if not request.data:
                return make_response(jsonify({"error": "Need post data"}), 500)
            obj = pickle.loads(request.data)
            basic_auth = obj.get("basic_auth", self.basic_auth)
            credentials = obj["credentials"]

            if basic_auth is None:
                return make_response(jsonify({"error": "NEED_AUTH"}), 500)
            else:
                self.basic_auth = basic_auth
                self.credentials = credentials
                self.keys = None

                # keys is a property that actually gets the credentials
                try:
                    self.keys
                except SamlNotAuthorized:
                    return make_response(jsonify({"error": "BAD_PASSWORD"}), 500)
                return "success"

        @app.route('/latest/meta-data/iam/', methods = ['GET'])
        def iam():
            return 'security-credentials'

        @app.route('/latest/meta-data/iam/security-credentials/', methods = ['GET'])
        def security_credentials():
            return 'BaseIAMRole'

        @app.route('/latest/meta-data/iam/security-credentials/BaseIAMRole', methods = ['GET'])
        def base_iam_role():
            if self.credentials is None or self.basic_auth is None:
                return make_response(jsonify({"error": "DO SWITCH"}), 500)
            return jsonify(self.keys)

        @app.errorhandler(400)
        def not_found(error):
            return make_response(jsonify({'error': 'bad request'}), 400)

        @app.errorhandler(404)
        def not_found(error):
            return make_response(jsonify({'error': 'not found'}), 404)

        @app.errorhandler(500)
        def not_found(error):
            return make_response(jsonify({'error': 'internal server error'}), 500)

