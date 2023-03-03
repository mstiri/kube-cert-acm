import yaml
from logger import getJSONLogger
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import base64
import OpenSSL
from OpenSSL import crypto
import boto3

CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
CERT_END = "-----END CERTIFICATE-----"
CRD_GROUP = 'cert-manager.io'
CRD_CERT_NAME = 'certificate'
CRD_CERT_PLURAL = 'certificates'

logger = getJSONLogger('kube-cert-acm.helpers')


# Discover in cluster kubernetes configuration
config.load_incluster_config()
api_instance = client.CoreV1Api()
custom_api_instance = client.CustomObjectsApi()

session = boto3.Session()
aws_client = session.client('acm')


def read_conf_file(config_file: str) -> list:
    """Read config file and return a list of valid entries."""
    certificates = []
    with open(config_file, 'r') as f:
        try:
            confs = yaml.safe_load(f)
        except yaml.YAMLError as yerr:
            logger.error(f'Error parsing config file. Err: {yerr}')
            raise Exception
    for cert in confs:
        if all(key in cert for key in ('cert', 'namespace', 'domain_name')):
            logger.debug(f'Required keys are present in {cert}')
            certificates.append(cert)
        else:
            logger.error(f'A required key is missing in {cert}')

    return certificates


def get_certificate_secret_name(certificate: str, namespace: str) -> str:
    """Get the secret name of the provided certificate / namespace."""
    try:
        api_resp = custom_api_instance.get_namespaced_custom_object(
            group=CRD_GROUP, version='v1', namespace=namespace, name=certificate, plural=CRD_CERT_PLURAL)
    except ApiException as e:
        logger.error(
            f'Exception getting Certificate: {certificate}. Status: {e.status}. Reason: {e.reason}', exc_info=False)
        raise Exception
    try:
        cert_secret_name = api_resp['spec']['secretName']
    except Exception as e:
        logger.error(
            f'Exception extracting secretName from certificate object. Error: {e}')
        return None
    return cert_secret_name


def get_cert_and_key_from_secret(secret: str, namespace: str):
    """Get the certificate and its private key from the provided secret / namespace."""
    try:
        resp = api_instance.read_namespaced_secret(secret, namespace)
    except ApiException as e:
        logger.exception(
            f"Exception reading secret {secret} from namesapce {namespace}). Status: {e.status}, Reason: {e.reason}", exc_info=False)
        return None, None
    try:
        certificate = base64.b64decode(resp.data.get('tls.crt'))
        key = base64.b64decode(resp.data.get('tls.key'))
    except Exception as e:
        logger.error('Failed to extract data from returned secret')
        return None, None
    return certificate, key


def get_certificate_and_chain(kube_certificate: str):
    """Separate certificate from the chain."""
    try:
        crypto.load_certificate(crypto.FILETYPE_PEM, kube_certificate)
    except OpenSSL.crypto.Error as e:
        logger.error(f"OpenSSL error while loading certificate. Error: {e}")
        return None, None
    certs = kube_certificate.decode().split(CERT_BEGIN)[1:]
    certificate, chain = '', ''
    for chunk in certs:
        if CERT_BEGIN not in certificate or CERT_END not in certificate:
            certificate = CERT_BEGIN + chunk
        else:
            chain = chain + CERT_BEGIN + chunk
    return certificate, chain


def certificate_exists(domain_name: str) -> bool:
    """Check if a certificate for this domain is already in ACM"""
    logger.info(
        f'Check if there is any certificate in ACM for the domain: {domain_name}')
    try:
        resp = aws_client.list_certificates()
    except Exception as e:
        logger.error(f'Error listing certificates. Error: {e}')
        raise Exception
    for cert in resp['CertificateSummaryList']:
        if domain_name == cert.get('DomainName'):
            return True
    return False


def get_acm_certificate(domain_name: str):
    """Get ACM certificate for the provided domain name"""
    try:
        resp = aws_client.list_certificates()
    except Exception as e:
        logger.error(f'Error listing certificates. Error: {e}')
        return None, None
    for cert in resp['CertificateSummaryList']:
        if domain_name == cert.get('DomainName'):
            certificate_arn = cert.get('CertificateArn')
            acm_cert = aws_client.get_certificate(
                CertificateArn=certificate_arn)['Certificate']
            return acm_cert, certificate_arn


def compare_certificates(kube_certificate: str, acm_certificate: str) -> bool:
    """Compare a kubernetes and ACM certificates to check if they are the same"""
    try:
        kube_cert_sn = crypto.load_certificate(
            crypto.FILETYPE_PEM, kube_certificate).get_serial_number()
        acm_cert_sn = crypto.load_certificate(
            crypto.FILETYPE_PEM, acm_certificate).get_serial_number()
    except OpenSSL.crypto.Error as e:
        logger.error(f"OpenSSL error while getting certificate SN. Error: {e}")
        return False
    logger.debug(f"Cluster cert SN: {kube_cert_sn}")
    logger.debug(f"ACM cert SN: {acm_cert_sn}")
    if kube_cert_sn == acm_cert_sn:
        logger.info('These 2 certificates are the same')
        return True
    else:
        logger.info('These 2 certificates are different')
    return False


def import_certificate(certificate: str, chain: str, kube_private_key: str, certificate_arn: str = None) -> bool:
    """Improt provided certificate to ACM"""
    try:
        if certificate_arn:
            resp = aws_client.import_certificate(
                Certificate=certificate,
                CertificateArn=certificate_arn,
                CertificateChain=chain,
                PrivateKey=kube_private_key)
        else:
            resp = aws_client.import_certificate(
                Certificate=certificate,
                CertificateChain=chain,
                PrivateKey=kube_private_key)
        if resp['CertificateArn']:
            logger.info(
                f"Certificate imported with the ARN: {resp['CertificateArn']}")
            return True
        else:
            logger.error("Failed to import certificate to ACM")
    except Exception as e:
        logger.error(f'Exception during certificate import to ACM. Error: {e}')
    return False
