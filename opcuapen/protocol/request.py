"""
Module for operating on requests, be it binary or request objects
"""
import logging
import math

import gmpy2

from opcua import ua
from opcua.common import utils
from opcua.common.connection import MessageChunk
from opcua.ua.ua_binary import struct_to_binary, header_to_binary

from opcuapen.attacks import paddings


logger = logging.getLogger(__name__)

def to_binary(chunk, cert, padding=None, ciphertext_manipulator=None):
    """ Convert chunk to binary

    :param chunk: chunk to convert
    :param cert: server certificate to use for ciphertext manipulation
    :param padding: padding function
    :param ciphertext_manipulator: manipulation function for the ciphertext
    :return: bytes to send to the server
    """
    security = struct_to_binary(chunk.SecurityHeader)
    encrypted_part = struct_to_binary(chunk.SequenceHeader) + chunk.Body
    encrypted_part += chunk.security_policy.padding(len(encrypted_part))

    chunk.MessageHeader.body_size = len(security) + chunk.encrypted_size(len(encrypted_part))
    header = header_to_binary(chunk.MessageHeader)
    signature = chunk.security_policy.signature(header + security + encrypted_part)
    encrypted_part += signature

    # if no padding is given, use the default PKCS #1 v1.5 padding
    if not padding:
        plaintext = paddings.pad_pkcs1v15(encrypted_part)
    else:
        plaintext = padding(encrypted_part)

    # extract modulus and exponent from the server certificate
    N = cert.public_key().public_numbers().n
    e = cert.public_key().public_numbers().e

    modulus_bits = int(math.ceil(math.log(N, 2)))
    modulus_bytes = (modulus_bits + 7) // 8

    plaintext_bytes = int.from_bytes(plaintext, byteorder='big')
    ciphertext = int(gmpy2.powmod(plaintext_bytes, e, N)).to_bytes(modulus_bytes, byteorder="big")
    if ciphertext_manipulator:
        ciphertext = ciphertext_manipulator(ciphertext)

    return header + security + ciphertext

def pad_and_encrypt(message, connection, cert, padding=None, ciphertext_manipulator=None):
    """ Make a message sendable by applying padding and encryption

    :param message: message object to send
    :param connection: connection to the OPC UA server
    :param cert: server certificate to use for manipulations
    :param padding: padding function
    :param ciphertext_manipulator:  manipulation function for the ciphertext
    :return: binary request that can be send to the server
    """
    token_id = connection.channel.SecurityToken.TokenId
    chunks = MessageChunk.message_to_chunks(connection.security_policy,
                                            message,
                                            connection._max_chunk_size,
                                            message_type=ua.MessageType.SecureOpen,
                                            channel_id=connection.channel.SecurityToken.ChannelId,
                                            request_id=1,
                                            token_id=token_id)
    chunk = chunks[0]

    chunk.SequenceHeader.SequenceNumber = 1
    return to_binary(chunk, cert, padding=padding, ciphertext_manipulator=ciphertext_manipulator)

def get_request(client):
    """ Assemble an OpenSecureChannelRequest for the specified client

    :param client: client object containing the channel parameters
    :return: binary OpenSecureChannelRequest
    """
    params = ua.OpenSecureChannelParameters()
    params.ClientProtocolVersion = 0
    params.RequestType = ua.SecurityTokenRequestType.Issue
    params.SecurityMode = client.security_policy.Mode
    params.RequestedLifetime = client.secure_channel_timeout

    nonce = utils.create_nonce(client.security_policy.symmetric_key_size)
    params.ClientNonce = nonce

    request = ua.OpenSecureChannelRequest()
    request.Parameters = params
    request.RequestHeader = client.uaclient._uasocket._create_request_header()

    try:
        binreq = struct_to_binary(request)
    except Exception:
        # reset request handle if any error
        # see self._create_request_header
        client.uaclient._uasocket._request_handle -= 1
        raise

    return binreq
