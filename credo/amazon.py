from credo.errors import BadSamlProvider, CredoError, SamlNotAuthorized
from credo.asker import ask_user_for_half_life
from credo.cred_types.saml import SamlRole

from boto.iam.connection import IAMConnection
from boto.sts.connection import STSConnection
from boto.sts.credentials import AssumedRole
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from textwrap import dedent
import requests
import xml.sax
import httplib
import logging
import base64
import time
import uuid
import boto
import os

log = logging.getLogger("credo.amazon")

########################
###   BASE
########################

class IamBase(object):
    def __init__(self, create_epoch=None, half_life=None):
        self.setup(create_epoch=create_epoch, half_life=half_life)

    def setup(self, create_epoch=None, half_life=None):
        """Setup the pair"""
        self._half_life = half_life
        self._create_epoch = create_epoch
        self._changed = False
        self.deleted = False

    @property
    def changed(self):
        """Get us value of _changed"""
        return self._changed

    def unchanged(self):
        """Set _changed to False"""
        self._changed = False

    def mark_as_invalid(self):
        """Mark the key as invalid"""
        self.invalidated = True

    @property
    def works(self):
        """Says whether this key is valid enough to get iam informations"""
        if self.deleted:
            return True
        if getattr(self, "_works", None) is False:
            return self._works

        get_cached = hasattr(self, "_last_asked") and (time.time() - self._last_asked) < 6
        self._last_asked = time.time()
        self._get_info(get_cached=get_cached)

        return self._works

    def wait_till_works(self):
        """Wait till this iam pair works"""
        # Give amazon time to think about this
        start = time.time()
        while time.time() - start < 20:
            self._get_info(quiet=True)
            if self._works:
                break
            time.sleep(2)

    def ask_amazon_for_account(self):
        """Get the account id for this key"""
        self._get_info(get_cached=True)
        return getattr(self, "account_id", None)

    def ask_amazon_for_account_aliases(self):
        """Get the account aliases for this key"""
        self._get_info(get_cached=True)
        return getattr(self, "account_aliases", None)

    def ask_amazon_for_username(self):
        """Get the username for this key"""
        self._get_info(get_cached=True)
        return getattr(self, "username", None)

    @property
    def create_epoch(self):
        """Use our create_epoch or ask amazon for it"""
        if self._create_epoch:
            return self._create_epoch
        elif self.works:
            self._create_epoch = self.ask_amazon_for_create_epoch()
            self._changed = True
            return self._create_epoch
        else:
            return 0

    @property
    def half_life(self):
        """Use our half_life or ask user for one"""
        if not self._half_life:
            self._half_life = ask_user_for_half_life(self.aws_access_key_id)
            self._changed = True
        return self._half_life

    def set_half_life(self, half_life):
        """Record a new half_life"""
        if half_life != self._half_life:
            self._half_life = half_life
            self._changed = True

    def is_root_credentials(self):
        """
        Return whether these credentials are possibly root credentials
        I.e. Amazon say they don't exist and it has the same name as an account alias
        """
        username = self.ask_amazon_for_username()
        try:
            self.connection.get_all_access_keys(username)
        except boto.exception.BotoServerError as error:
            if error.status == 404 and error.code == "NoSuchEntity":
                if username in self.ask_amazon_for_account_aliases():
                    return True
            else:
                raise
        return False

    def amazon_date_to_epoch(self, create_date):
        """Convert create_date from amazon into a create_epoch"""
        dt = boto.utils.parse_ts(create_date)
        return (dt - datetime(1970, 1, 1)).total_seconds()

    def expired(self):
        """Say whether the age of this key is past twice it's half life or marked as invalid"""
        return getattr(self, "invalidated", False) or self.half_life > 0 and self.age > self.half_life * 2

    def past_half_life(self):
        """Say whether the age of this key is past it's half life"""
        return self.half_life > 0 and self.age > self.half_life

    @property
    def age(self):
        """Age is time since it's create_epoch"""
        return time.time() - self.create_epoch

########################
###   USER CREDS
########################

class IamPair(IamBase):
    def __init__(self, aws_access_key_id, aws_secret_access_key, aws_security_token=None, create_epoch=None, half_life=None):
        self.aws_access_key_id = aws_access_key_id
        self.aws_security_token = aws_security_token
        self.aws_secret_access_key = aws_secret_access_key
        super(IamPair, self).__init__(create_epoch=create_epoch, half_life=half_life)

    @property
    def connection(self):
        """Get a connection for these keys"""
        if not getattr(self, "_connection", None):
            self._connection = IAMConnection(self.aws_access_key_id, self.aws_secret_access_key, security_token=self.aws_security_token)
        return self._connection

    def _get_info(self, get_cached=False, quiet=False):
        """
        Get user details from this key and set
        self._works
        self.username
        self.account_id
        """
        try:
            if getattr(self, "_got_user", None) is None or not get_cached:
                log.info("Asking amazon for account id and username\taccess_key=%s", self.aws_access_key_id)
                details = self.connection.get_user()["get_user_response"]["get_user_result"]["user"]
                aliases = self.connection.get_account_alias()["list_account_aliases_response"]["list_account_aliases_result"]["account_aliases"]
                self._invalid = False
                self._works = True
                self._got_user = True
                self.username = details["user_name"]

                # arn is arn:aws:iam::<account_id>:<other>
                self.account_id = details["arn"].split(":")[4]
                self.account_aliases = aliases
        except boto.exception.BotoServerError as error:
            self._works = False
            self._got_user = False
            self._connection = None
            if error.status == 403 and error.code in ("InvalidClientTokenId", "SignatureDoesNotMatch"):
                self._invalid = True
                if not quiet:
                    log.info("Found invalid access key and secret key combination\taccess_key=%s\terror_code=%s\terror=%s", self.aws_access_key_id, error.code, error.message)
                return
            raise

    def find_other_access_keys(self):
        """Find all the access_keys for this user"""
        keys = self.connection.get_all_access_keys(self.ask_amazon_for_username())["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        return [str(key["access_key_id"]) for key in keys]

    def ask_amazon_for_create_epoch(self):
        """Return our create_epoch"""
        if self.is_root_credentials():
            result = self.connection.get_response('ListAccessKeys', {}, list_marker='AccessKeyMetadata')
        else:
            username = self.ask_amazon_for_username()
            result = self.connection.get_all_access_keys(username)

        access_keys = result["list_access_keys_response"]["list_access_keys_result"]["access_key_metadata"]
        create_date = [key for key in access_keys if key["access_key_id"] == self.connection.aws_access_key_id][0]['create_date']
        return self.amazon_date_to_epoch(create_date)

    def create_new(self):
        """Create a new iam pair to use"""
        log.info("Creating a new key")
        response = self.connection.create_access_key(self.ask_amazon_for_username())["create_access_key_response"]["create_access_key_result"]["access_key"]
        log.info("Created %s", response["access_key_id"])
        iam_pair = IamPair(str(response["access_key_id"]), str(response["secret_access_key"]), create_epoch=self.amazon_date_to_epoch(response["create_date"]))
        iam_pair.wait_till_works()
        return iam_pair

    def delete(self):
        """Delete this key pair from amazon"""
        return self.delete_access_key(self.aws_access_key_id)

    def delete_access_key(self, access_key):
        log.info("Deleting a key\taccess_key_id=%s", access_key)
        if access_key == self.aws_access_key_id:
            self.deleted = True
            self._changed = True
        return self.connection.delete_access_key(access_key)

    @classmethod
    def from_environment(kls, create_epoch=None, half_life=None):
        """Get an IAMPair from our environment variables"""
        pair = kls(os.environ["AWS_ACCESS_KEY_ID"], os.environ["AWS_SECRET_ACCESS_KEY"], os.environ.get("AWS_SECURITY_TOKEN"), create_epoch, half_life)
        pair._connection = IAMConnection()
        return pair

    def synchronize_with(self, other):
        """Synchronise non key information with another key"""
        self.set_half_life(other._half_life)

########################
###   SAML CREDS
########################

class FixedSTSConnection(STSConnection):
    """
    assume_role_with_saml seems broken because it puts the assertion in the query parameters.
    awscli puts it in the POST data and isn't broken, so lets do that here as well.
    """
    def assume_role_with_saml(self, role_arn, principal_arn, saml_assertion, policy=None, duration_seconds=None):
        data = {
            'RoleArn': role_arn,
            'PrincipalArn': principal_arn,
            'SAMLAssertion': saml_assertion,
        }
        if policy is not None:
            data['Policy'] = policy
        if duration_seconds is not None:
            data['DurationSeconds'] = duration_seconds

        params = {"Action": "AssumeRoleWithSAML", "Version": self.APIVersion}
        response = requests.post("https://{0}".format(self.host), headers={"User-Agent": boto.UserAgent}, params=params, data=data)

        if response.status_code == 200:
            obj = AssumedRole(self)
            h = boto.handler.XmlHandler(obj, self)
            xml.sax.parseString(response.content, h)
            return obj
        else:
            boto.log.error('%s %s' % (response.status_code, response.reason))
            boto.log.error('%s' % response.content)
            raise self.ResponseError(response.status_code, response.reason, response.content)

class IamSaml(IamBase):
    def __init__(self, provider, username, password, connection=None, create_epoch=None, half_life=None):
        self.provider = provider
        self.basic_auth = base64.b64encode("{0}:{1}".format(username, password))
        self.username = username
        self._connection = connection
        super(IamSaml, self).__init__(create_epoch=create_epoch, half_life=half_life)

    @property
    def connection(self):
        """Get a connection"""
        if not getattr(self, "_connection", None):
            self._connection = FixedSTSConnection(anon=True)
        return self._connection

    @property
    def arns(self):
        if not getattr(self, "_arns", None):
            self._get_info()
        return self._arns

    @property
    def assertion(self):
        if not getattr(self, "_assertion", None):
            self._get_info()
        return self._assertion

    def _get_info(self, get_cached=False, quiet=False):
        """
        Authenticate against the provided username and password

        Create some variables:
            idpid = your idp entity id
            rpid = a valid SP entityId that is configured for ECP
            acsurl,ascurlbinding = an AssertionConsumerService URL and binding
                this will match the values in the 'relying party' and associated metadata

        And then make a soap request with base64 encoded ldap username and password
        and get back the authentication string
        """
        idpid = "https://{0}/idp/shibboleth".format(self.provider)
        rpid = "urn:amazon:webservices"
        acsurl = "https://signin.aws.amazon.com/saml"
        acsurlbinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

        tree = None
        tree_body = None
        for _ in range(5):
            now = (datetime.utcnow() - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
            ident = uuid.uuid1().hex
            envelope = dedent("""
            <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
                <S:Body>
                    <samlp:AuthnRequest
                        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        AssertionConsumerServiceURL="{acsurl}"
                        ID="_{ident}"
                        IssueInstant="{now}"
                        ProtocolBinding="{acsurlbinding}"
                        Version="2.0"
                    >
                        <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{rpid}</saml:Issuer>
                        <samlp:NameIDPolicy AllowCreate="1"/>
                        <samlp:Scoping>
                            <samlp:IDPList>
                                <samlp:IDPEntry ProviderID="{idpid}"/>
                            </samlp:IDPList>
                        </samlp:Scoping>
                    </samlp:AuthnRequest>
                </S:Body>
            </S:Envelope>
            """).format(acsurl=acsurl, acsurlbinding=acsurlbinding, ident=ident, now=now, idpid=idpid, rpid=rpid)

            headers = {"Accept": "*/*", "Authorization": "Basic {0}".format(self.basic_auth), "Content-Type": "application/x-www-form-urlencoded", "Content-Length": len(envelope)}
            connection = httplib.HTTPSConnection(self.provider, 443)
            connection.request("POST", "/idp/profile/SAML2/SOAP/ECP", envelope, headers)
            resp = connection.getresponse()

            if resp.status == 401:
                log.info("Not authorized, perhaps you entered the wrong password")
                self._works = False
                raise SamlNotAuthorized()
            elif resp.status != 200:
                log.info("Failed to authenticate, trying again in 5 seconds")
                time.sleep(5)
                self._works = False
            else:
                body = resp.read()
                tree = ET.fromstring(body)
                tree_body = tree.find("{http://schemas.xmlsoap.org/soap/envelope/}Body")
                if tree_body is None:
                    log.info("Failed to authenticate, saml provider didn't return any soap. Trying again in 5 seconds")
                    time.sleep(5)
                    self._works = False
                else:
                    self._works = True
                    break

        if tree is None:
            raise BadSamlProvider("Failed to authenticate", provider=self.provider, username=self.username)

        arns = tree.findall(".//*[@FriendlyName='Role']/*")
        self._works = True
        body_start = "<soap11:Body>"
        body_end = "</soap11:Body>"
        self._assertion = base64.b64encode(body[body.find(body_start)+len(body_start):body.find(body_end)])
        self._arns = sorted([SamlRole(*arn.text.split(",")) for arn in arns], key = lambda a: a.role_arn)

    def exports(self, role):
        """Get exports for this account"""
        if role.role_arn not in [r.role_arn for r in self.arns]:
            raise CredoError("Your user doesn't have specified account anymore"
                , username=self.keys.idp_username, provider=self.keys.provider, wanted=self.keys.role.role_arn
                )

        result = self.get_result(role)
        creds = result.credentials
        return [
              ("AWS_ACCESS_KEY_ID", creds.access_key)
            , ("AWS_SECRET_ACCESS_KEY", creds.secret_key)

            , ("AWS_SESSION_TOKEN", creds.session_token)
            , ("AWS_SECURITY_TOKEN", creds.session_token)
            ]

    def get_result(self, role):
        """Get back the sts assume result"""
        return self.connection.assume_role_with_saml(role.role_arn, role.principal_arn, self.assertion, duration_seconds=3600)

    def synchronize_with(self, other):
        """Nothing to synchronize"""

