"""
Constants used in OpcuaPen
"""

LOG_FORMAT = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s'
DATE_FORMAT = '%Y%m%d-%H%M%S'

STATUS_UNDEFINED = -1
STATUS_SUCCESSFUL = 0
STATUS_ABORTED = 1

SecurityPolicyBasic128Rsa15 = 'http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15'

# errors
AbstractClassNotImplementedError = 'Must be implemented by subclasses'
NotYetImplemented = 'Not yet implemented'
