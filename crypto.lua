local aes = require("crypto/aes")
local padding = require("crypto/padding")
local block = require("crypto/block")

local lib = {}

----------------------------------------

lib.paddingMethods = {
    PKCS7 = 1,
    zero = 2,
    none = 3
}

local function pad(method, text, size)
    if method == lib.paddingMethods.PKCS7 then
        return padding.PKCS7Pad(text, size)
    elseif method == lib.paddingMethods.zero then
        return padding.zeroPad(text, size)
    elseif method == lib.paddingMethods.none then
        return text
    end
end

local function unpad(method, text)
    if method == lib.paddingMethods.PKCS7 then
        return padding.PKCS7Unpad(text)
    elseif method == lib.paddingMethods.zero or method == lib.paddingMethods.none then
        return text
    end
end

----------------------------------------

lib.blockModes = {
    ECB = 1,
    CBC = 2,
    CTR = 3
}

local function encryptBlocks(mode, callback, blocks, blockSize, ivec)
    if mode == lib.blockModes.ECB then
        return block.ECBEncrypt(callback, blocks, blockSize)
    elseif mode == lib.blockModes.CBC then
        return block.CBCEncrypt(ivec, callback, blocks, blockSize)
    elseif mode == lib.blockModes.CTR then
        return block.CTREncrypt(ivec, callback, blocks, blockSize)
    end
end

local function decryptBlocks(mode, callback, cipher, blockSize, ivec)
    if mode == lib.blockModes.ECB then
        return block.ECBDecrypt(callback, cipher, blockSize)
    elseif mode == lib.blockModes.CBC then
        return block.CBCDecrypt(ivec, callback, cipher, blockSize)
    elseif mode == lib.blockModes.CTR then
        return block.CTRDecrypt(ivec, callback, cipher, blockSize)
    end
end

----------------------------------------

lib.encryptionAlgorithms = {
    AES_128 = 1,
    AES_192 = 2,
    AES_256 = 3
}

local aesKeyLength = {
    [lib.encryptionAlgorithms.AES_128] = 128,
    [lib.encryptionAlgorithms.AES_192] = 192,
    [lib.encryptionAlgorithms.AES_256] = 256
}

-- Options:
-- [1]:       Plaintext
-- algorithm: crypto.encryptionAlgorithms enum entry; defaults to AES_128
-- padding:   crypto.paddingMethods enum entry; defaults to PKCS#7
-- mode:      crypto.blockModes enum entry; defaults to ECB
-- key:       Encryption key
-- ivec:      Optional, an initialization vector for CBC and CTR block modes

function lib.encrypt(options)
    options.algorithm = options.algorithm or lib.encryptionAlgorithms.AES_128
    options.padding   = options.padding   or lib.paddingMethods.PKCS7
    options.mode      = options.mode      or lib.blockModes.ECB

    local keyLength = aesKeyLength[options.algorithm]
    local roundKeys = aes.expandKey(keyLength, options.key)

    return encryptBlocks(
        options.mode,
        function(block)
            return aes.encrypt(keyLength, block, roundKeys)
        end,
        pad(options.padding, options[1], 16),
        16,
        options.ivec
    )
end

-- Options:
-- [1]:       Cipher
-- algorithm: crypto.encryptionAlgorithms enum entry; defaults to AES_128
-- padding:   crypto.paddingMethods enum entry; defaults to PKCS#7
-- mode:      crypto.blockModes enum entry; defaults to ECB
-- key:       Encryption key
-- ivec:      Optional, an initialization vector for CBC and CTR block modes

function lib.decrypt(options)
    options.algorithm = options.algorithm or lib.encryptionAlgorithms.ECB
    options.padding   = options.padding   or lib.paddingMethods.PKCS7
    options.mode      = options.mode      or lib.blockModes.ECB

    local keyLength = aesKeyLength[options.algorithm]
    local roundKeys = aes.expandKey(keyLength, options.key)

    local callback
    if options.mode == lib.blockModes.CTR then
        callback = function(block)
            return aes.encrypt(keyLength, block, roundKeys)
        end
    else
        callback = function(block)
            return aes.decrypt(keyLength, block, roundKeys)
        end
    end

    return unpad(
        options.padding,
        decryptBlocks(
            options.mode,
            callback,
            options[1],
            16,
            options.ivec
        )
    )
end

----------------------------------------

return lib