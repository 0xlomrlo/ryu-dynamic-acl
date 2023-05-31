import os

INSTANCE_NAME = "dynamic_acl"
URL_PREFIX = "/api/v1"
TMP_PATH = "/root/tmp/"

LEARN_PRI = int(os.environ.get("LEARN_PRI", 3))
LEARN_IDLE_TIMEOUT = int(os.environ.get("LEARN_IDLE_TIMEOUT", 3))

PROTECTED_SRV_PRI = int(os.environ.get("PROTECTED_SRV_PRI", 5))
PROTECTED_SRV_COOKIE_ID = int(os.environ.get("PROTECTED_SRV_COOKIE_ID", 5)) # cookie id will be converted to hex

ISOLATION_PRI = int(os.environ.get("ISOLATION_PRI", 10))
ISOLATION_HARD_PRI = int(os.environ.get("ISOLATION_HARD_PRI", 40))
ISOLATION_COOKIE_ID = int(os.environ.get("ISOLATION_COOKIE_ID", 10)) # cookie id will be converted to hex
ISOLATION_IDLE_TIMEOUT = int(os.environ.get("ISOLATION_IDLE_TIMEOUT", 30))
ISOLATION_HARD_TIMEOUT = int(os.environ.get("ISOLATION_HARD_TIMEOUT", 15))

ARP_PRI = int(os.environ.get("ARP_PRI", 50))
