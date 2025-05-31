import base64
import json
import logging
import plistlib
import random
import uuid
from datetime import datetime

import requests
import urllib3
from websockets.sync.client import connect

ANISETTE_CLIENT_INFO = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"
ANISETTE_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"

urllib3.disable_warnings()

logger = logging.getLogger(__name__)

anisette_state = {}


def generate_anisette() -> dict:
    global anisette_state
    try:
        return _local_anisette()
    except Exception:
        logger.debug("Falling back to remote Anisette")
        return _remote_anisette(anisette_state)


def _local_anisette() -> dict:
    # logger.debug("Using local anisette generation")
    """Generates anisette data using AOSKit locally"""

    import objc
    from Foundation import NSBundle, NSClassFromString  # type: ignore

    AOSKitBundle = NSBundle.bundleWithPath_(
        "/System/Library/PrivateFrameworks/AOSKit.framework"
    )
    objc.loadBundleFunctions(  # type: ignore
        AOSKitBundle, globals(), [("retrieveOTPHeadersForDSID", b"")]
    )
    util = NSClassFromString("AOSUtilities")

    h = util.retrieveOTPHeadersForDSID_("-2")

    return {
        "X-Apple-I-MD": str(h["X-Apple-MD"]),
        "X-Apple-I-MD-M": str(h["X-Apple-MD-M"]),
    }


def _gsa_url_bag():
    r = requests.get(
        "https://gsa.apple.com/grandslam/GsService2/lookup",
        verify=False,
        headers={
            # We have to provide client info so that the server knows which version of the bag to give us
            "X-Mme-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
            "User-Agent": "Xcode",
        },
    )
    return plistlib.loads(r.content)


ANISETTE_SERVER_WS = "wss://ani.sidestore.io/v3/provisioning_session"
ANISETTE_SERVER_HEADERS = "https://ani.sidestore.io/v3/get_headers"


def _remote_anisette(state: dict) -> dict:
    if "adi_pb" not in state:
        _provision(state)
    return _get_headers(state)


HEADERS = {
    "User-Agent": ANISETTE_USER_AGENT,
    "X-Apple-Baa-E": "-10000",
    "X-Apple-I-MD-LU": "0",
    "X-Mme-Device-Id": str(uuid.uuid4()).upper(),
    "X-Apple-Baa-Avail": "2",
    "X-Mme-Client-Info": ANISETTE_CLIENT_INFO,
    "X-Apple-I-Client-Time": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    "Accept-Language": "en-US,en;q=0.9",
    "X-Apple-Client-App-Name": "akd",
    "Accept": "*/*",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Apple-Baa-UE": "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000",
    "X-Apple-Host-Baa-E": "-7066",
}


def _start_provisioning() -> str:  # spim
    body = {"Header": {}, "Request": {}}
    body = plistlib.dumps(body)
    r = requests.post(
        _gsa_url_bag()["urls"]["midStartProvisioning"],
        verify=False,
        data=body,
        headers=HEADERS,
    )
    b = plistlib.loads(r.content)
    logger.debug(b)
    return b["Response"]["spim"]


def _end_provisioning(cpim: str) -> tuple:  # ptm, tk, rinfo
    body = {
        "Header": {},
        "Request": {
            "cpim": cpim,
        },
    }
    body = plistlib.dumps(body)
    r = requests.post(
        _gsa_url_bag()["urls"]["midFinishProvisioning"],
        verify=False,
        data=body,
        headers=HEADERS,
    )
    b = plistlib.loads(r.content)
    logger.debug(b)
    return (
        b["Response"]["ptm"],
        b["Response"]["tk"],
        b["Response"]["X-Apple-I-MD-RINFO"],
    )


def _provision(state: dict):
    identifier = base64.b64encode(random.randbytes(16)).decode()

    rinfo = None
    adi_pb = None

    with connect(ANISETTE_SERVER_WS) as websocket:
        spim = _start_provisioning()
        # Handle messages as the server sends them
        while True:
            message = json.loads(websocket.recv())
            logger.debug(f"Received: {message}")

            if message["result"] == "GiveIdentifier":
                websocket.send(
                    json.dumps(
                        {
                            "identifier": identifier,
                        }
                    )
                )
            elif message["result"] == "GiveStartProvisioningData":
                websocket.send(
                    json.dumps(
                        {
                            "spim": spim,
                        }
                    )
                )
            elif message["result"] == "GiveEndProvisioningData":
                cpim = message["cpim"]
                ptm, tk, rinfo = _end_provisioning(cpim)
                rinfo = rinfo

                logger.debug(f"Provisioning data: {ptm}, {tk}, {rinfo}")
                websocket.send(
                    json.dumps(
                        {
                            "ptm": ptm,
                            "tk": tk,
                        }
                    )
                )
            elif message["result"] == "ProvisioningSuccess":
                adi_pb = message["adi_pb"]
                logger.debug("Provisioning success")
                break
            elif message["result"] == "Timeout":
                logger.debug("TIMEOUT")
                break
            else:
                logger.debug(f"Unknown message: {message}")

    state["rinfo"] = rinfo
    state["identifier"] = identifier
    state["adi_pb"] = adi_pb


def _get_headers(state: dict):
    adi_pb = state["adi_pb"]
    rinfo = state["rinfo"]
    identifier = state["identifier"]

    r = requests.post(
        ANISETTE_SERVER_HEADERS,
        verify=False,
        json={
            "adi_pb": adi_pb,
            "identifier": identifier,
        },
    )
    # logger.debug(r.content)
    return {
        "X-Apple-I-MD": r.json()["X-Apple-I-MD"],
        "X-Apple-I-MD-M": r.json()["X-Apple-I-MD-M"],
    }
