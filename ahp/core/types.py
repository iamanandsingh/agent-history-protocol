"""AHP enums and constants — matches Appendix A protobuf schema."""

from enum import IntEnum


class RecordType(IntEnum):
    ACTION = 1
    GAP = 2
    CHECKPOINT = 3
    BOOT = 4
    RECOVERY = 5
    KEY = 6
    WITNESS = 7


class ResultStatus(IntEnum):
    SUCCESS = 1
    FAILURE = 2
    TIMEOUT = 3
    ERROR = 4


class Protocol(IntEnum):
    MCP = 1
    HTTP = 2
    GRPC = 3
    A2A = 4
    SHELL = 5
    CUSTOM = 6


class ActionType(IntEnum):
    TOOL_CALL = 1
    INFERENCE = 2
    DELEGATION = 3
    MESSAGE = 4
    CUSTOM = 5


class AuthorizationType(IntEnum):
    AUTH_NONE = 1
    AUTH_HUMAN = 2
    AUTH_AGENT = 3
    AUTH_POLICY = 4
    AUTH_MULTI_PARTY = 5


class AuthorizerType(IntEnum):
    AUTHORIZER_HUMAN = 1
    AUTHORIZER_AGENT = 2
    AUTHORIZER_POLICY_ENGINE = 3


class AuthorizationDecision(IntEnum):
    APPROVED = 1
    REJECTED = 2
    CONDITIONAL = 3


class GapReason(IntEnum):
    CRASH = 1
    DISK_FULL = 2
    DISK_CORRUPT = 3
    ROTATION = 4
    INTERCEPTOR_FAILURE = 5
    BACKPRESSURE = 6
    MANUAL_PURGE = 7


class ChainLevel(IntEnum):
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3


class FsyncMode(IntEnum):
    EVERY = 1
    BATCH = 2
    NONE = 3


class RecoveryMethod(IntEnum):
    CHECKPOINT_FILE = 1
    CHAIN_SCAN = 2
    FRESH_START = 3


# Sentinel for 32 zero bytes (genesis prev_hash)
ZERO_HASH_32 = b"\x00" * 32
ZERO_HASH_16 = b"\x00" * 16
ZERO_UUID = b"\x00" * 16

SCHEMA_VERSION = 1
