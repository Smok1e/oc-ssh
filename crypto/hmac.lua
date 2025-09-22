local padding = require("crypto/padding")
local array = require("crypto/array")
local sha2 = require("crypto/sha2")

local lib = {}

---------------------------------------- Generic HMAC

-- HMAC(K, m) = H((K' xor opad) .. H((K' xor ipad) .. m))
-- H is a cryptographic hash function
-- m is the message to be authenticated
-- K is the very secret key
-- K' is a block-sized key derived from the very secret key K;
-- either by padding to the right with 0s, or by hashing down
-- to <= block size and then padding to the right with zeros
-- opad and ipad are respectively 0x36 and 0x5C repeated 
-- block-size times

local OPAD_CONSTANT = string.char(0x5C)
local IPAD_CONSTANT = string.char(0x36)

function lib.hmac(hashFunction, blockSize, key, message)
    if #key ~= blockSize then
        key = padding.zeroPad(#key > blockSize and hashFunction(key) or key, blockSize)
    end

    return hashFunction(
        array.xorBytes(
            key, 
            OPAD_CONSTANT:rep(blockSize)
        ) .. hashFunction(
            array.xorBytes(
                key, 
                IPAD_CONSTANT:rep(blockSize)
            ) .. message
        )
    )
end

---------------------------------------- Predefined HMAC variants

function lib.hmac_sha256(message, key)
    return lib.hmac(sha2.sha256, 64, key, message)
end

function lib.hmac_sha224(message, key)
    return lib.hmac(sha2.sha224, 64, key, message)
end

----------------------------------------

return lib