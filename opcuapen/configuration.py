"""
Configurations for OpcuaPen
"""

import importlib
import json
import logging
import os

from opcua.ua import SecurityPolicy

import opcuapen


LOGGER = logging.getLogger(__name__)

def _get_relative_path(base_path, rel_path):
    return os.path.abspath(os.path.join(base_path, rel_path))


class DefaultOpcuaPenConfig:
    """
    Default configuration for OpcuaPen
    """
    BASEDIR = os.path.abspath(os.path.dirname(opcuapen.__file__))

    def __init__(self, basedir=None):
        if not basedir:
            self.basedir = self.BASEDIR
        else:
            self.basedir = basedir
        self.docker = _get_relative_path(self.basedir, 'docker-opcfoundation-server')

        self.client = {}
        self.client['cert'] = _get_relative_path(self.basedir, 'certificates/client-cert.pem')
        self.client['key'] = _get_relative_path(self.basedir, 'certificates/client-key.pem')

        self.server = {}
        self.server['protocol'] = 'opc.tcp'
        self.server['host'] = 'localhost'
        self.server['port'] = 8666
        self.server['path'] = 'UAExample'

        self.server['security_policy'] = 'SecurityPolicyBasic128Rsa15'
        try:
            self.security_policy = \
                getattr(importlib.import_module('opcua.crypto.security_policies'),
                        self.server['security_policy'])
        except AttributeError:
            LOGGER.warning('Security policy %s unknown', self.server['security_policy'])
            self.security_policy = SecurityPolicy

        LOGGER.debug('Endpoint configuration')
        LOGGER.debug(self.get_connection_string())
        LOGGER.debug(self.security_policy.URI)

    def get_connection_string(self):
        """ Get OPC UA connection string including protocol, host, port, path

        :return: formatted connection string
        """
        return '{}://{}:{}/{}'.format(self.server['protocol'],
                                      self.server['host'],
                                      self.server['port'],
                                      self.server['path'])

    def to_json(self):
        """ Get serialized version of the configuration

        :return: comprehensive JSON-formatted configuration
        """
        return {'docker': {'Dockerfile': self.docker},
                'client': self.client,
                'server': self.server}

    def __repr__(self):
        return json.dumps(self.to_json(), sort_keys=True, indent=4)

    @staticmethod
    def from_file(json_file):
        """ Create configuration from file

        :param json_file: file path
        :return: configuration object
        """
        with open(json_file, 'r') as json_in:
            json_config = json.loads(json_in.read())
        return DefaultOpcuaPenConfig.from_json(json_config)

    @staticmethod
    def from_json(json_config, basedir=None):
        """ Create configuration from JSON string

        :param json_config: JSON-formatted configuration
        :param basedir: base directory of the configuration
        :return: configuration object
        """
        config = DefaultOpcuaPenConfig(basedir=basedir)

        if 'client' in json_config:
            config.client.update(json_config['client'])
        if 'server' in json_config:
            config.server.update(json_config['server'])

        if 'docker' in json_config:
            config.docker = json_config['docker'].get('Dockerfile')

        return config
