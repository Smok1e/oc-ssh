local streamlib = require("ssh/stream")
local curve25519 = require("crypto/curve25519")
local encoding = require("crypto/encoding")
local sha2 = require("crypto/sha2")

local lib = {}

----------------------------------------

local function ed25519GeneratePublicKey(key)
    return lib.new("ssh-ed25519", curve25519.ed25519.generatePublicKey(key.data))
end

local function ed25519Fingerprint(key)
    return "SHA256:" .. encoding.base64Encode(sha2.sha256(key.data), true)
end

local function ed25519Sign(key, message)
    local stream = streamlib.bufferedStream()
    stream:writeString("ssh-ed25519")
    stream:writeString(curve25519.ed25519.sign(key.data, message))

    return stream.buffer
end

local function ed25519Verify(key, message, signature)
    return curve25519.ed25519.verify(key.data, message, signature)
end

local function ed25519Encode(key, stream)
    stream:writeString(key.data)
end

local function ed25519Decode(key, stream)
    key.data = stream:readString()
end

local function ed25519New(key, data)
    key.data = data
end

----------------------------------------

function lib.generatePublicKey(key)
    return ed25519GeneratePublicKey(key)
end

function lib.fingerprint(key)
    return ed25519Fingerprint(key)
end

function lib.sign(key, message)
    return ed25519Sign(key, message)
end

function lib.verify(key, message, signature)
    return ed25519Verify(key, message, signature)
end

function lib.encode(key)
    local stream = streamlib.bufferedStream()
    stream:writeString(key.type)

    ed25519Encode(key, stream)
    return stream.buffer
end

function lib.decode(blob)
    local key = {}

    local stream = streamlib.bufferedStream(blob)
    key.type = stream:readString()

    assert(key.type == "ssh-ed25519", "unknown key algorithm " .. key.type)

    ed25519Decode(key, stream)
    return key
end

function lib.new(keyType, ...)
    assert(keyType == "ssh-ed25519")
    local key = {}
    key.type = keyType

    ed25519New(key, ...)
    return key
end

----------------------------------------

return lib