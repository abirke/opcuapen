"""
Module for cryptography-related classes and functions
"""
import datetime
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


logger = logging.getLogger(__name__)

# according to https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
def generate_private_key(private_key_path, key_size=1024):
    """ Generate an RSA private key

    :param private_key_path: file path to write the key to
    :param key_size: bit-size of the key
    :return: the RSA private key object
    """
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=key_size,
                                   backend=default_backend())

    with open(private_key_path, "wb") as key_file:
        key_file.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.TraditionalOpenSSL,
                                         encryption_algorithm=serialization.NoEncryption()))

    return key

# according to https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
def generate_certificate(certificate_path, key):
    """ Generate a self-signed certificate using the given RSA private key

    :param certificate_path: file path to write the certificate to
    :param key: RSA private key
    :return: the certificate object
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject) \
                                    .issuer_name(issuer) \
                                    .public_key(key.public_key()) \
                                    .serial_number(x509.random_serial_number()) \
                                    .not_valid_before(datetime.datetime.utcnow()) \
                                    .not_valid_after(datetime.datetime.utcnow() + \
                                                     datetime.timedelta(days=10)) \
                                    .add_extension(x509.SubjectAlternativeName(
                                        [x509.DNSName(u"localhost")]),
                                                   critical=False) \
                                    .sign(key, hashes.SHA256(), default_backend())

    with open(certificate_path, "wb") as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert
