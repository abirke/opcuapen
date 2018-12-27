"""
Module for attack executors on OPC UA implementations
"""

from datetime import datetime
import json
import logging
import os
import time

import docker

from opcuapen import constants
from opcuapen.attacks.bleichenbacher import Bleichenbacher


logger = logging.getLogger(__name__)

class Executor():
    """ Abstract  base class for executors of attacks on OPC UA """
    def __init__(self):
        raise NotImplementedError(constants.AbstractClassNotImplementedError)

class BatchExecutor(Executor):
    """ Executor to gather statistics from multiple runs of the attack """
    def __init__(self, config, batch_size, result_directory):
        self.config = config
        self.batch_size = batch_size
        self.result_directory = result_directory
        self.results = []

    def _save_result(self, result):
        filen = 'report-{}.json'.format(datetime.now().strftime(constants.DATE_FORMAT))
        with open(os.path.join(self.result_directory, filen), 'w') as f_out:
            f_out.write(json.dumps(result.get_json_report(), indent=4))
            f_out.write('\n')

    def execute(self):
        """ Execute the configure number of attacks sequentially """
        for _ in range(self.batch_size):
            docker_executor = DockerExecutor(self.config)
            result = docker_executor.execute()
            self._save_result(self)
            self.results.append(result)

    def get_progress(self):
        """ Get percentage of finished attacks """
        return len(self.results)/self.batch_size

class DockerExecutor(Executor):
    """ Executor to test or attack a server running in Docker """
    def __init__(self, config):
        self.container = None
        self.config = config

    # according to https://docker-py.readthedocs.io/
    def get_container(self):
        """ Get an instance of the configured Dockerfile, create it if necessary """
        if not self.container:
            client = docker.client.from_env()
            logger.debug('Building container using Dockerfile %s', self.config.docker)
            image, _ = client.images.build(path=self.config.docker)
            self.container = client.containers.create(image.id, ports={'8666/tcp': 8666})

        return self.container

    def execute(self):
        """ Start the container and perform the attack against it """
        self.get_container().start()
        time.sleep(5)
        blb = Bleichenbacher(self.config)
        result = blb.attack_signature()
        return result

    def __del__(self):
        self.container.stop()
        self.container.remove()
