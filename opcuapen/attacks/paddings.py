"""
Padding and manipulation functions, either extending the length or manipulating full-length
"""
import logging


logger = logging.getLogger(__name__)

def pad_pkcs1v15(msg, length=256):
    """ Pad message according to PKCS #1 v1.5 except for non-random padding string

    :param msg: message shorter than one block
    :param length: block length
    :return: message padded to byte-length given
    """
    return b'\x00\x02' + (length-len(msg)-3)*b'\x01' + b'\x00' + msg

# functions that take a full message

def three_func(msg):
    """ Replace the first two bytes of the message by 0x0003 """
    return b'\x00\x03' + msg[2:]

def in_first_ten_func(msg):
    """ Replace the fifth byte of the message by 0x00 """
    return msg[:5] + b'\x00' + msg[6:]

def after_first_ten_func(msg):
    """ Replace the fifteenth byte of the message by 0x00 """
    if msg[15] == b'\x00':
        logger.warning('Replacement useless')
    return msg[:15] + b'\x00' + msg[16:]

def short_func(msg):
    """ Truncate the message after 239 bytes """
    return msg[:239]

def one_func(msg):
    """ Replace the first two bytes of the message by 0x0001 """
    return b'\x00\x01' + msg[2:]

def no_stop_byte_func(msg):
    """ Replace the tenth byte by 0xff to remove the stop byte """
    return msg[:10] + b'\xff' + msg[11:]

# functions that wrap the message with padding (usually from 245 Bytes to 256 Bytes)

def pkcs1v15_three(msg):
    return b'\x00\x03' + 8*b'\x01' + b'\x00' + msg

def pkcs1v15_five(msg):
    return b'\x00\x05' + 8*b'\x01' + b'\x00' + msg

def pkcs1v15_block(msg):
    return b'\x0f\xd7' + 8*b'\x01' + b'\x00' + msg

def pkcs1v15_zeros_in_rnd_padding(msg):
    return b'\x00\x02' + 3*b'\x01' + b'\x00' + 4*b'\x01' + b'\x00' + msg

def pkcs1v15_only_rnd(msg):
    return b'\x00\x02' + 8*b'\x01' + b'\x00' + 245*b'\x02'

def pkcs1v15_late_zeros(msg):
    return b'\x00\x02' + 8*b'\x01' + b'\x01' + msg

def pkcs1v15_overlong_plaintext(msg):
    return b'\x00\x02' + 8*b'\x01' + b'\x00' + msg + b'\xff'

def pkcs1v15_short_plaintext(msg):
    return b'\x00\x02' + 8*b'\x01' + b'\x00' + msg[:-1]

def pkcs1v15_zeros_in_rnd_padding_no_stop(msg):
    return b'\x00\x02' + 3*b'\x01' + b'\x00' + 4*b'\x01' + b'\xde' + msg

def pkcs1v15_short_plaintext_and_three(msg):
    return b'\x00\x02' + 8*b'\x01' + b'\x00' + msg[:-1]

def pkcs1v15_number_too_large(msg):
    return b'\xff\xff' + 8*b'\x01' + b'\x00' + 254*b'\xff'

def pkcs1v15_hack_any_plaintext_byte(msg):
    replace_byte = 67

    p_new = msg[:replace_byte] + b'\x00' + msg[(replace_byte+1):]
    return b'\x00\x02' + b'\x01\x01\x01\x01\x01\x01\x01\x01' + b'\x00' + p_new

def pkcs1v15_wrong_first_two_bytes(msg):
    return b'\x47\x74' + b'\x01\x01\x01\x01\x01\x01\x01\x01' + b'\x00' + msg

def get_vector_bruteforce_second_byte():
    """ Get paddings for values 0 to 256 of the first two bytes """
    pads = []
    for i in range(2**8):
        pads.append(lambda msg,
                           prefix=i:
                    prefix.to_bytes(2, byteorder='big') + 8*b'\x01' + b'\x00' + msg)
    return pads
