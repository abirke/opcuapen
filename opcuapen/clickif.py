"""
Click CLI interface to OpcuaPen
"""

import json
import logging
import os

import click

from opcuapen import constants
from opcuapen.attacks.bleichenbacher import Bleichenbacher, BleichenbacherOracleTest
from opcuapen.executors import BatchExecutor
from opcuapen.client import OpcuaPenClient
from opcuapen.configuration import DefaultOpcuaPenConfig


logger = logging.getLogger(__name__)

@click.group()
@click.option('--config',
              type=click.File('r'),
              help='JSON configuration file')
@click.option('-v', '--verbose', count=True)
@click.pass_context
def cli(ctx, config, verbose):
    """ OPCUApen - Testing tool for Chosen Ciphertext Attacks against implementations of OPC UA

    OPCUApen  Copyright (C) 2018  André Birke
    This program comes with absolutely no warranty.
    This is free software, and you are welcome to redistribute it
    under the conditions of GNU General Public License v3.0.
    """
    # set log level
    log_level = logging.ERROR
    if verbose == 1:
        log_level = logging.WARNING
    elif verbose == 2:
        log_level = logging.INFO
    elif verbose >= 3:
        log_level = logging.DEBUG
    logging.basicConfig(format=constants.LOG_FORMAT, level=log_level)

    # load configuration
    if config:
        logger.debug('Loading configuration from file %s', config.name)
        ctx.obj = DefaultOpcuaPenConfig.from_json(json.loads(config.read()),
                                                  basedir=os.path.abspath(
                                                      os.path.dirname(config.name)))
    else:
        logger.debug('Using default configuration')
        ctx.obj = DefaultOpcuaPenConfig()

    # TODO consider switching the logic, instead of basicConfig only configure our own modules
    logging.getLogger('opcua.client.ua_client').setLevel(logging.ERROR)
    logging.getLogger('opcua.client.ua_client.Socket').setLevel(logging.ERROR)
    logging.getLogger('opcua.uaprotocol').setLevel(logging.ERROR)

@click.command()
@click.pass_obj
def endpoints(cfg):
    """ List endpoints of a server """
    all_endpoints = OpcuaPenClient(cfg).get_client().connect_and_get_server_endpoints()
    for endpoint in all_endpoints:
        print(endpoint.Server.ApplicationUri,
              endpoint.SecurityMode,
              endpoint.SecurityPolicyUri)

@click.command()
@click.pass_obj
def test(cfg):
    """ Test vulnerability of a server """
    logger.info('Test mode')
    bot = BleichenbacherOracleTest(cfg)
    bot.generic_testing()

@click.command()
@click.pass_obj
def attack(cfg):
    """ Perform a single attack on a server """
    logger.info('Attack mode (signature)')
    blb = Bleichenbacher(cfg)
    blb.attack_signature()

@click.command()
@click.option('--count',
              default=10,
              help='number of attacks (default: 10)')
@click.option('--result-directory',
              type=click.Path(exists=True))
@click.pass_obj
def batch(cfg, count, result_directory):
    """ Perform a series of attacks """
    logger.info('Batch mode')

    batch_exec = BatchExecutor(config=cfg, batch_size=count, result_directory=result_directory)
    batch_exec.execute()

@click.command()
def config():
    """ Output a default configuration """
    cfg = DefaultOpcuaPenConfig()
    click.echo(json.dumps(cfg.to_json(),
                          sort_keys=True,
                          indent=4))


cli.add_command(attack)
cli.add_command(batch)
cli.add_command(endpoints)
cli.add_command(test)
cli.add_command(config)

if __name__ == '__main__':
    cli() # pylint: disable=no-value-for-parameter
