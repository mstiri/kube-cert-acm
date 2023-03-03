import sys
import os
import time
from logger import getJSONLogger
from helpers import read_conf_file, get_certificate_secret_name, get_cert_and_key_from_secret, get_certificate_and_chain
from helpers import certificate_exists, get_acm_certificate, compare_certificates, import_certificate

logger = getJSONLogger('kube-cert-acm')
sys.tracebacklimit = 0

CHECK_INTERVAL_SECONDS = os.getenv("CHECK_INTERVAL_SECONDS") or 60
CONFIG_FILE = "/app/config/certificates_config.yaml"


def cert_sync():
    logger.debug('Begin certificates synchronisation')
    try:
        certificates = read_conf_file(CONFIG_FILE)
    except Exception as e:
        logger.error(f"Failed to read config file: {e}")
        return
    for cert in certificates:
        logger.debug(f'Certificate to sync: {cert}')
        try:
            cert_secret_name = get_certificate_secret_name(
                cert['cert'], cert['namespace'])
        except Exception as e:
            continue
        if not cert_secret_name:
            continue
        kube_certificate, key = get_cert_and_key_from_secret(
            cert_secret_name, cert['namespace'])
        if not (kube_certificate and key):
            continue
        certificate, chain = get_certificate_and_chain(kube_certificate)
        if not (certificate and chain):
            continue
        try:
            cert_exists = certificate_exists(cert['domain_name'])
        except Exception as e:
            continue
        if cert_exists:
            acm_certificate, certificate_arn = get_acm_certificate(
                cert['domain_name'])
            if not (acm_certificate and certificate_arn):
                continue
            if compare_certificates(kube_certificate, acm_certificate):
                logger.debug(
                    'ACM and Kubernetes certificates are the same. Nothing to sync')
            else:
                logger.debug(
                    'ACM and Kubernetes certificates are different. Sync to be performed')
                resp = import_certificate(
                    certificate, chain, key, certificate_arn)
        else:
            logger.info(
                'Certificate does not exist on ACM. Certificate to be imported')
            import_certificate(certificate, chain, key)


if __name__ == '__main__':
    while True:
        cert_sync()
        logger.info(f"Coming back in {CHECK_INTERVAL_SECONDS} seconds")
        time.sleep(int(CHECK_INTERVAL_SECONDS))
