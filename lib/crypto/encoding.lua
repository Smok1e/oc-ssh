local array = require("crypto/array")
local padding = require("crypto/padding")

local lib = {}

----------------------------------------

local LOG_2 = math.log(2)

local function log2(x)
    return math.floor(math.log(x) / LOG_2)
end

local MAX_BITS = log2(math.maxinteger)

local function bitmask(n)
    return ~0 >> (MAX_BITS - n + 1)
end

---------------------------------------- 2^n base

-- Converts string into any 2^n (n <= 8) based number
function lib.encodeBytes(bytes, base, alphabet)
    local power = log2(base)
    local mask = bitmask(power)
    local bit = 0
    local count = math.ceil(8 * #bytes / power)
    local result = ""

    local function byte(bit)
        return bytes:byte(bit // 8 + 1)
    end

    for i = 1, count do
        local digit = byte(bit) << 8

        local offset = bit % 8
        if offset ~= 0 then
            digit = digit | (byte(bit + power) or 0)
        end

        digit = (digit >> (16 - power - offset)) & mask
        result = result .. alphabet[digit + 1]

        bit = bit + power
    end

    return result
end

-- Converts any 2^n (n <= 8) based number into a string
function lib.decodeBytes(number, base, inverseAlphabet)
    local power = log2(base)
    local buffer = 0
    local offset = 0
    local result = ""

    for i = 1, #number do
        local digit = inverseAlphabet[number:sub(i, i)] - 1

        buffer = buffer | digit << (8 - power - offset)
        offset = offset + power

        if offset >= 8 then
            result = result .. string.char(buffer)

            offset = offset % 8
            buffer = (digit << (8 - offset)) & 0xFF
        end
    end

    --[[
    if offset ~= 0 then
        result = result .. string.char(buffer >> (8 - offset))
    end]]

    return result
end

---------------------------------------- Base64

local BASE64_ALPHABET = array.fromString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
local BASE64_INVERSE_ALPHABET = array.inverse(BASE64_ALPHABET)

function lib.base64Encode(text, noPadding)
    local result = lib.encodeBytes(text, 64, BASE64_ALPHABET)
    return (noPadding and result) or padding.base64Pad(result)
end

function lib.base64Decode(text)
    return lib.decodeBytes(padding.base64Unpad(text), 64, BASE64_INVERSE_ALPHABET)
end

---------------------------------------- Hex

local HEX_ALPHABET = array.fromString("0123456789ABCDEF")
local HEX_INVERSE_ALPHABET = array.inverse(HEX_ALPHABET)

function lib.hexEncode(text)
    return lib.encodeBytes(text, 16, HEX_ALPHABET)
end

function lib.hexDecode(text)
    return lib.decodeBytes(text:upper(), 16, HEX_INVERSE_ALPHABET)
end

----------------------------------------

return lib