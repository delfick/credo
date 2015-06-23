from credo.structure.credential_path import CredentialPath
from credo.errors import CredoError, SamlNotAuthorized
from credo.amazon import IamSaml
from credo import explorer

from six.moves.urllib.parse import urlencode
from datetime import datetime, timedelta
from six.moves import http_cookies
from boto.utils import parse_ts
from uuid import uuid1
import requests
import logging
import pickle
import time
import pytz
import sys
import os
import re

log = logging.getLogger("credo.server")

class Server(object):
    def __init__(self, host, port, credo):
        self.host = host
        self.port = port
        self.credo = credo
        self.stored_keys = {}
        self.stored_assertions = {}

    def start(self):
        try:
            from tornado.httpserver import HTTPServer
            from tornado.wsgi import WSGIContainer
            from tornado.ioloop import IOLoop
        except ImportError:
            raise CredoError("Please pip install tornado")
        http_server = HTTPServer(WSGIContainer(self.app))
        http_server.listen(self.port, self.host)
        log.info("Starting server on http://%s:%s", self.host, self.port)
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
        keys, _ = self.set_keys(self.credentials)
        return keys

    def set_keys(self, credentials, timeout=None):
        keys = self.stored_keys.get(credentials.path)
        if keys is not None:
            expiration = parse_ts(keys["Expiration"])
            if timeout:
                expiration = keys["LastUpdated"] + timeout
            if datetime.utcnow() > expiration:
                log.info("Keys expired, recreating them")
                keys = None

        if keys is None:
            log.info("Assuming role")
            pair = IamSaml(credentials.provider, credentials.idp_username, "")
            pair.basic_auth = self.basic_auth
            keys = pair.get_result(credentials.role).credentials.to_dict()

            _keys = {
                  "Code": "Success"
                , "LastUpdated": datetime.utcnow()
                , "AccessKeyId": keys["access_key"]
                , "SecretAccessKey": keys["secret_key"]
                , "Token": keys["session_token"]
                , "Expiration": keys["expiration"]
                }
            self.stored_keys[credentials.path] = _keys
            self.stored_assertions[credentials.path] = pair.assertion
        return self.stored_keys[credentials.path], self.stored_assertions[credentials.path]

    def get_cookies(self, credentials):
        s = requests.Session()
        cookies = []
        def add_cookies(resp):
            for name, header in resp.headers.items():
                if name.lower() == 'set-cookie' and header not in cookies:
                    cookie = http_cookies.SimpleCookie()
                    cookie.load(header)
                    for value in cookie.values():
                        url = "https://.amazon.com/"
                        if value['domain']:
                            url = "https://{0}{1}".format(value['domain'], value['path'])
                        cookie = {"url": url, "name": value.key, "value": value.value}

                        gmt = pytz.timezone("GMT")
                        if value['expires']:
                            date = datetime.strptime(value['expires'], "%a, %d-%b-%Y %H:%M:%S GMT")
                            gmtd = gmt.localize(date)
                            cookie["expirationDate"] = gmtd.astimezone(pytz.timezone("UTC"))
                        else:
                            cookie["expirationDate"] = datetime.utcnow() + timedelta(days=365)
                        cookie["expirationDate"] = time.mktime(cookie['expirationDate'].timetuple())
                        cookies.append(cookie)

        resp = s.get("https://{0}".format(credentials.provider))
        add_cookies(resp)

        nxt = "https://{0}{1}".format(credentials.provider, re.findall('href="[^"]+"', resp.text)[0][6:-1])
        resp2 = s.get(nxt, allow_redirects=False)
        add_cookies(resp2)

        keys, assertion = self.set_keys(credentials, timeout=timedelta(minutes=5))
        nxt = "https://signin.aws.amazon.com/saml"
        data2 = urlencode({"SAMLResponse": assertion, "name": "", "roleIndex": credentials.role.role_arn, "RelayState": ""})
        headers2 = {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": len(data2)}
        final_resp = s.post(nxt, data=data2, headers=headers2, allow_redirects=False)
        add_cookies(final_resp)

        return cookies

    def find_credentials(self, account):
        directory_structure, shortened = explorer.find_repo_structure(self.credo.root_dir, levels=3)
        explorer.narrow(shortened, ["Repository", "Account", "User"], None, want_new=False, forced_vals=[None, account, None])
        chains = explorer.flatten(directory_structure, shortened, want_new=False)
        chosen = list(self.credo.credentials_from(directory_structure, chains, complain_if_missing=True))[0]
        chosen.keys
        return chosen

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
            self._app.secret_key = uuid1()
            self.register_routes(self._app)
        return self._app

    def register_routes(self, app):
        from flask import jsonify, abort, make_response, request, redirect, session

        @app.route('/', methods = ['GET'])
        def index():
            return 'latest'

        @app.route('/latest/', methods = ['GET'])
        def latest():
            return 'meta-data'

        @app.route('/latest/meta-data/', methods = ['GET'])
        def meta_data():
            return 'iam\nswitch'

        @app.route('/latest/meta-data/switch/', methods = ["GET"])
        def switch_get():
            return 'to'

        @app.route('/latest/meta-data/switch/to/', methods = ["GET"])
        def switch_list():
            directory_structure, shortened = explorer.find_repo_structure(self.credo.root_dir, levels=3)
            html = []
            html.append("<body>")
            for repository, values in shortened.items():
                html.append("<h1>Repository: {0}</h1>".format(repository))
                html.append("<ul>")

                for account, values in sorted(values.items()):
                    html.append('<li><a href="/latest/meta-data/switch/to/{0}">{0}</a></li>'.format(account))

                html.append("</ul>")
            html.append("</body>")
            return '\n'.join(html)

        @app.route('/latest/meta-data/switch/to/<account>', methods = ["GET"])
        def switch_to(account):
            credentials = self.find_credentials(account)

            try:
                cookies = self.get_cookies(credentials)
            except SamlNotAuthorized:
                return make_response(jsonify({"error": "NEED_AUTH"}), 500)

            response = {"Location": "https://console.aws.amazon.com/console?region=ap-southeast-2", "Cookies": cookies}
            return make_response(jsonify(response))

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

