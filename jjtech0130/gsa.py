import base64
import hashlib
import hmac
import locale
import plistlib as plist
from datetime import datetime
import logging
import requests
import srp._pysrp as srp
import urllib3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from anisette import generate_anisette
from useragent import (
    DEVICE_UDID,
    GSA_CLIENT_INFO,
    GSA_SERIAL,
    GSA_USER_AGENT,
    USER_ID,
)

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
urllib3.disable_warnings()

logger = logging.getLogger(__name__)


def gsa_authenticate(username, password):
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()

    r = gsa_authenticated_request(
        {"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"}
    )

    if "sp" not in r:
        logger.debug("Failed to authenticate: ", r)
        raise Exception("Failed to authenticate", r)

    if r["sp"] not in ["s2k", "s2k_fo"]:
        logger.debug(
            f"This implementation only supports s2k and sk2_fo. Server returned {r['sp']}"
        )
        raise Exception("Unsupported protocol")

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"], r["sp"])

    M = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if M is None:
        logger.debug("Failed to process challenge")
        raise Exception("Failed to process challenge")

    r = gsa_authenticated_request(
        {"c": r["c"], "M1": M, "u": username, "o": "complete"}
    )

    # logger.debug(r)
    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    usr.verify_session(r["M2"])
    if not usr.authenticated():
        logger.debug("Failed to verify session")
        raise Exception("Failed to verify session")

    spd = decrypt_cbc(usr, r["spd"])
    spd = plist.loads(spd, fmt=plist.FMT_XML)

    return r, spd


def gsa_authenticated_request(parameters):
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": generate_cpd()},
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": GSA_USER_AGENT,
        "X-MMe-Client-Info": GSA_CLIENT_INFO,
    }

    resp = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers=headers,
        data=plist.dumps(body),
        verify=False,
        timeout=5,
    )

    return plist.loads(resp.content)["Response"]


def generate_cpd():
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
    }

    cpd.update(generate_meta_headers())
    cpd.update(generate_anisette())
    return cpd


def generate_meta_headers():
    return {
        "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat()
        + "Z",
        "X-Apple-I-TimeZone": str(datetime.utcnow().astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
        "X-Apple-I-MD-LU": base64.b64encode(str(USER_ID).upper().encode()).decode(),
        "X-Mme-Device-Id": str(DEVICE_UDID).upper(),
        "X-Apple-I-SRL-NO": GSA_SERIAL,  # Serial number
    }


def encrypt_password(password, salt, iterations, protocol):
    assert protocol in ["s2k", "s2k_fo"]
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr, data):
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


def trigger_trusted_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": GSA_CLIENT_INFO,
    }

    headers.update(generate_meta_headers())
    headers.update(generate_anisette())

    # This will trigger the 2FA prompt on trusted devices
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    requests.get(
        "https://gsa.apple.com/auth/verify/trusteddevice",
        headers=headers,
        verify=False,
        timeout=10,
    )


def submit_trusted_factor(code, dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "User-Agent": "Xcode",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": GSA_CLIENT_INFO,
        "security-code": code,
    }

    headers.update(generate_meta_headers())
    headers.update(generate_anisette())

    # Send the 2FA code to Apple
    resp = requests.get(
        "https://gsa.apple.com/grandslam/GsService2/validate",
        headers=headers,
        verify=False,
        timeout=10,
    )
    if not resp.ok:
        logger.debug("2FA failed")
        return False
    logger.debug("2FA successful")
    return True


def trigger_sms_factor(dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    # TODO: Actually do this request to get user prompt data
    # a = requests.get("https://gsa.apple.com/auth", verify=False)
    # This request isn't strictly necessary though,
    # and most accounts should have their id 1 SMS, if not contribute ;)

    headers = {
        "User-Agent": "Xcode",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": GSA_CLIENT_INFO,
    }

    headers.update(generate_meta_headers())
    headers.update(generate_anisette())

    # TODO: Actually get the correct id, probably in the above GET
    body = {"phoneNumber": {"id": 1}, "mode": "sms"}

    # This will send the 2FA code to the user's phone over SMS
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    t = requests.put(
        "https://gsa.apple.com/auth/verify/phone/",
        json=body,
        headers=headers,
        verify=False,
        timeout=5,
    )


def submit_sms_factor(code, dsid, idms_token):
    identity_token = base64.b64encode((dsid + ":" + idms_token).encode()).decode()

    # TODO: Actually do this request to get user prompt data
    # a = requests.get("https://gsa.apple.com/auth", verify=False)
    # This request isn't strictly necessary though,
    # and most accounts should have their id 1 SMS, if not contribute ;)

    headers = {
        "User-Agent": "Xcode",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": GSA_CLIENT_INFO,
    }

    headers.update(generate_meta_headers())
    headers.update(generate_anisette())

    logger.debug(headers)

    body = {"phoneNumber": {"id": 1}, "mode": "sms"}

    body["securityCode"] = {"code": code}

    # Send the 2FA code to Apple
    resp = requests.post(
        "https://gsa.apple.com/auth/verify/phone/securitycode",
        json=body,
        headers=headers,
        verify=False,
        timeout=5,
    )
    if not resp.ok:
        logger.debug("2FA failed")
        return False
    logger.debug("2FA successful")
    return True
