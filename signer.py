import argparse
import sys
from os import path

import authres.arc
import authres.dmarc
from authheaders import sign_message
import logging

UTF8_ENCODING = 'utf-8'

parser = argparse.ArgumentParser(
    description='Produce ARC signature and Authentication Results headers')
parser.add_argument('selector', action="store", help="selector of the domain")
parser.add_argument('domain', action="store", help="the forwarding domain name")
parser.add_argument('srvid', action="store", help="name of the receiving mail server")
parser.add_argument('privatekeyfile', action="store", help="path to private key")
parser.add_argument('messagefile', action="store", help="path to message file")
parser.add_argument('--headers', action="store",
                    help="headers to include. Default: from:to:date:subject:mime-version:dkim-signature",
                    default="from:to:date:subject:mime-version:dkim-signature")
parser.add_argument('--verbose', '-v', action="store_true", default=False, help="enable verbose logging")


def get_authres_header(srvid):
    spf_pass = authres.SPFAuthenticationResult(result='pass')
    arc_pass = authres.arc.ARCAuthenticationResult(result='pass')
    dkim_pass = authres.DKIMAuthenticationResult(result='pass')
    dmarc_pass = authres.dmarc.DMARCAuthenticationResult(result='pass')

    return str(authres.AuthenticationResultsHeader(
        authserv_id=srvid,
        results=[spf_pass, arc_pass, dkim_pass, dmarc_pass]
    )) + '\n'


if __name__ == "__main__":
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    if not path.exists(args.privatekeyfile):
        sys.exit("Private key file not found.")
    if not path.exists(args.messagefile):
        sys.exit("Message file not found.")
    if sys.version_info[0] >= 3:
        args.selector = bytes(args.selector, encoding=UTF8_ENCODING)
        args.domain = bytes(args.domain, encoding=UTF8_ENCODING)
        args.headers = bytes(args.headers, encoding=UTF8_ENCODING)

    # read file contents
    message = bytes(open(args.messagefile, 'rb').read())
    private_key = bytes(open(args.privatekeyfile, 'rb').read())

    message_with_authres = bytes(get_authres_header(args.srvid), encoding=UTF8_ENCODING) + message
    logging.debug("Message with authres: %s", message_with_authres)
    signature = sign_message(message_with_authres,
                       args.selector,
                       args.domain,
                       private_key,
                       args.headers.split(b':'),
                       'ARC',
                       bytes(args.srvid, encoding=UTF8_ENCODING))
    if len(signature) == 0:
        sys.exit("Unable to generate arc headers")
    separator = "#####"
    signature[0] = signature[0].decode(UTF8_ENCODING).replace("ARC-Seal: ",
                                                              "ARC-Seal" + separator)
    signature[1] = signature[1].decode(UTF8_ENCODING).replace("ARC-Message-Signature: ",
                                                              "ARC-Message-Signature" + separator)
    signature[2] = signature[2].decode(UTF8_ENCODING).replace("ARC-Authentication-Results: ",
                                                              "ARC-Authentication-Results" + separator)
    for sig in signature:
        print(bytes(sig, encoding=UTF8_ENCODING))
