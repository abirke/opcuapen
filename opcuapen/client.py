"""
Module for OPC UA client-related classes
"""

import logging
import os

from opcua import Client
from opcua.crypto import uacrypto

from opcuapen import crypto


logger = logging.getLogger(__name__)

class OpcuaPenClient:
    """ Wrapper class for OPC UA client handling endpoint configuration and certificates """
    def __init__(self, config):
        self._config = config
        self._client = None
        self._cert = None

    def get_config(self):
        """ Get the client configuration """
        return self._config

    def get_client(self):
        """ Singleton getter for client object """
        if not self._client:
            self._client = Client(self._config.get_connection_string(),
                                  timeout=2)
        return self._client

    def get_server_certificate(self):
        """ Request the server for its certificate or just return if already known

        :returns: server certificate
        """
        if self._cert:
            return self._cert

        self.get_client().connect()
        matching_endpoints = [ep for ep in self.get_client().get_endpoints()
                              if ep.SecurityPolicyUri == self._config.security_policy.URI]
        self.get_client().disconnect()

        if matching_endpoints:
            self._cert = uacrypto.x509_from_der(matching_endpoints[0].ServerCertificate)
            return self._cert

        logger.error('Could not find matching endpoint for URI %s',
                     self._config.server['security_policy'].URI)
        return None

    @staticmethod
    def _gen_and_config_cert():
        """ Generate self-signed certificate for the client side """
        logger.debug('Generating self-signed certificate')

        private_key_path = os.path.join(os.path.dirname(__file__), "key.pem")
        certificate_path = os.path.join(os.path.dirname(__file__), "certificate.pem")

        private_key = crypto.generate_private_key(private_key_path)
        crypto.generate_certificate(certificate_path, private_key)

        return certificate_path, private_key_path

    def set_security_policy(self):
        """ Generate certificates if necessary and set the security policy for the channel """
        if not self._config.client.get('cert') or \
           not self._config.client.get('key') or \
           not os.path.isfile(self._config.client['cert']) or \
           not os.path.isfile(self._config.client['key']):
            self._config.client['cert'], self._config.client['key'] = self._gen_and_config_cert()
            logger.warning('Using self-signed certificate on client-side')
            logger.warning(self._config.client['cert'])

        # sends a get endpoint request!
        self.get_client().set_security(self._config.security_policy,
                                       self._config.client['cert'],
                                       self._config.client['key'])
