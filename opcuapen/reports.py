"""
Module for summary-classes of Bleichenbacher tests and attacks
"""

from datetime import datetime

from opcuapen import constants


class BleichenbacherReport:
    """
    Report class for performance data, metadata and results of a Bleichenbacher attack
    """
    def __init__(self):
        self.pub_key = None
        self.messages = 0
        self.timestamp_start = None
        self.timestamp_end = None
        self.s_init = 1
        self.s_0 = None
        self.msg = None
        self.sig = None
        self.status = constants.STATUS_UNDEFINED

    def get_json_report(self):
        """ Get a formatted report of the attack in JSON """
        return {'pub_key': self.pub_key,
                'messages': self.messages,
                'time_start': self.timestamp_start.strftime(constants.DATE_FORMAT),
                'time_end': self.timestamp_end.strftime(constants.DATE_FORMAT),
                's_init': self.s_init,
                's_0': self.s_0,
                'message': self.msg,
                'signature': self.sig}

    def set_pub_key_from_cert(self, cert):
        """ Set the public key used for the attack by passing a certificate object

        :param cert: certificate to extract the public numbers from
        """
        self.pub_key = {}
        self.pub_key['N'] = cert.public_numbers().n
        self.pub_key['e'] = cert.public_numbers().e

    @staticmethod
    def from_json(js):
        """ Factory method for a report object from JSON string

        :param js: string containing the JSON-formatted report
        :return: BleichenbacherReport object with the passed data
        """
        report = BleichenbacherReport()
        if 'pub_key' in js:
            report.pub_key = {'N': js['pub_key'].get('N'),
                              'e': js['pub_key'].get('e')}
        report.messages = js.get('messages', 0)
        if 'time_start' in js:
            report.timestamp_start = datetime.strptime(js['time_start'], constants.DATE_FORMAT)
        if 'time_end' in js:
            report.timestamp_end = datetime.strptime(js['time_end'], constants.DATE_FORMAT)
        report.s_init = js.get('s_init', 1)
        report.s_0 = js.get('s_0', None)
        report.msg = js.get('message', None)
        report.sig = js.get('signature', None)

        return report

    def start(self):
        """ Note the beginning of the attack """
        self.timestamp_start = datetime.now()

    def stop(self):
        """ Note the end of the attack """
        self.timestamp_end = datetime.now()

    def get_runtime(self):
        """ Get the runtime of the attack """
        if not self.timestamp_start or \
           not self.timestamp_end:
            return None
        return self.timestamp_end - self.timestamp_start
