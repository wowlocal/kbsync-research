import uuid

# TODO: We should probably save these or pull them from the device
DEVICE_UDID = str(uuid.uuid4()).upper()
USER_ID = str(uuid.uuid4()).upper()

PRODUCT = "MacBookPro18,3"
OS_VERSION = "14.3.1"

GSA_SERIAL = "0"
GSA_USER_AGENT = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
GSA_CLIENT_INFO = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>"

ANISETTE_USER_AGENT = GSA_USER_AGENT
ANISETTE_CLIENT_INFO = GSA_CLIENT_INFO

ICLOUD_USER_AGENT = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
ICLOUD_CLIENT_INFO = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"

FINDMY_VERSION = "7.0"
FINDMY_USER_AGENT = "Find%20My/373.11 CFNetwork/1492.0.1 Darwin/23.3.0"
FINDMY_CLIENT_INFO = "<MacBookPro18,3> <macOS;14.3.1;23D60> <com.apple.AuthKit/1 (com.apple.findmy/373.11)>"
