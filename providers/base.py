from authlib.integrations.requests_client import OAuth2Session

class BaseOAuth:
    def __init__(self, client_id, client_secret, redirect_uri, scope, authorize_url, token_url):
        self.session = OAuth2Session(client_id, client_secret, scope=scope, redirect_uri=redirect_uri)
        self.authorize_url = authorize_url
        self.token_url = token_url

    def get_authorize_url(self):
        return self.session.create_authorization_url(self.authorize_url)

    def fetch_token(self, authorization_response):
        return self.session.fetch_token(self.token_url, authorization_response=authorization_response)
