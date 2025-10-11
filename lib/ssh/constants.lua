local constants = {}

----------------------------------------

local function makeEnumSerializator(enum)
    return function(enumValue)
        for key, value in pairs(enum) do
            if value == enumValue then
                return key
            end
        end

        return "Unknown"
    end
end

---------------------------------------- Message IDs

constants.SSH_MESSAGE = {
    DISCONNECT                =   1,
    IGNORE                    =   2,
    UNIMPLEMENTED             =   3,
    DEBUG                     =   4,
    SERVICE_REQUEST           =   5,
    SERVICE_ACCEPT            =   6,
    KEXINIT                   =  20,
    NEWKEYS                   =  21,
    KEX_ECDH_INIT             =  30,
    KEX_ECDH_REPLY            =  31,
    USERAUTH_REQUEST          =  50,
    USERAUTH_FAILURE          =  51,
    USERAUTH_SUCCESS          =  52,
    USERAUTH_BANNER           =  53,
    USERAUTH_PK_OK            =  60,
    GLOBAL_REQUEST            =  80,
    REQUEST_SUCCESS           =  81,
    REQUEST_FAILURE           =  82,
    CHANNEL_OPEN              =  90,
    CHANNEL_OPEN_CONFIRMATION =  91,
    CHANNEL_OPEN_FAILURE      =  92,
    CHANNEL_WINDOW_ADJUST     =  93,
    CHANNEL_DATA              =  94,
    CHANNEL_EXTENDED_DATA     =  95,
    CHANNEL_EOF               =  96,
    CHANNEL_CLOSE             =  97,
    CHANNEL_REQUEST           =  98,
    CHANNEL_SUCCESS           =  99,
    CHANNEL_FAILURE           = 100
}

constants.strMessageId = makeEnumSerializator(constants.SSH_MESSAGE)

---------------------------------------- Disconnect codes

constants.SSH_DISCONNECT = {
    HOST_NOT_ALLOWED_TO_CONNECT     =  1,
    PROTOCOL_ERROR                  =  2,
    KEY_EXCHANGE_FAILED             =  3,
    RESERVED                        =  4,
    MAC_ERROR                       =  5,
    COMPRESSION_ERROR               =  6,
    SERVICE_NOT_AVAILABLE           =  7,
    PROTOCOL_VERSION_NOT_SUPPORTED  =  8,
    HOST_KEY_NOT_VERIFIABLE         =  9,
    CONNECTION_LOST                 = 10,
    BY_APPLICATION                  = 11,
    TOO_MANY_CONNECTIONS            = 12,
    AUTH_CANCELLED_BY_USER          = 13,
    NO_MORE_AUTH_METHODS_AVAILABLE  = 14,
    ILLEGAL_USER_NAME               = 15
}

constants.strDisconnectCode = makeEnumSerializator(constants.SSH_DISCONNECT)

---------------------------------------- Channel open failure codes

constants.SSH_OPEN = {
    ADMINISTRATIVELY_PROHIBITED = 1,
    CONNECT_FAILED              = 2,
    UNKNOWN_CHANNEL_TYPE        = 3,
    RESOURCE_SHORTAGE           = 4
}

constants.strOpenFailureCode = makeEnumSerializator(constants.SSH_OPEN)

---------------------------------------- Extended data type codes

constants.SSH_EXTENDED_DATA = {
    STDERR = 1
}

constants.strExtendedDataCode = makeEnumSerializator(constants.SSH_EXTENDED_DATA)

---------------------------------------- Supported algorithms

constants.ALGORITHMS = {
    keyExchange = {
        "curve25519-sha256"
    },

    serverHostKey = {
        "ssh-ed25519"
    },

    encryptionClientToServer = {
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr"
    },

    encryptionServerToClient = {
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr"
    },

    macClientToServer = {
        "hmac-sha2-224",
        "hmac-sha2-256",
        "hmac-sha2-384",
        "hmac-sha2-512"
    },

    macServerToClient = {
        "hmac-sha2-224",
        "hmac-sha2-256",
        "hmac-sha2-384",
        "hmac-sha2-512"
    },

    compressionClientToServer = {
        "none"
    },

    compressionServerToClient = {
        "none"
    },

    -- languages_client_to_server = {},
    -- languages_server_to_client = {}
}

constants.ALGORITHMS_ORDER = {
    "keyExchange",
    "serverHostKey",
    "encryptionClientToServer",
    "encryptionServerToClient",
    "macClientToServer",
    "macServerToClient",
    "compressionClientToServer",
    "compressionServerToClient",
    "languageClientToServer",
    "languageServerToClient"
}

---------------------------------------- Other constants

constants.DEFAULT_PORT = 22

constants.SEQNO_MAX = 2^32

constants.PACKET_PADDING = 16

constants.CHANNEL_SESSION_PACKET_SIZE = 16 * 1024
constants.CHANNEL_SESSION_WINDOW_SIZE = 64 * constants.CHANNEL_SESSION_PACKET_SIZE

----------------------------------------

return constants