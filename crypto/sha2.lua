local array = require("crypto/array")

local lib = {}

----------------------------------------

local HASH_VALUES = {
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19
}

local ROUND_CONSTANTS = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
}

----------------------------------------

-- Prepares message for digesting
local function pad(text)
    return text .. "\x80" .. ("\x00"):rep(64 - (#text + 8) % 64 - 1) .. array.toBytes(array.fromNumber(#text * 8, 8, true))
end

-- Iterates over equally-sized chunks of a given string
local function chunks(string, chunkSize)
    local i, count = 0, #string // chunkSize
    
    return function()
        i = i + 1

        if i > count then
            return nil
        end

        return i, string:sub((i - 1) * chunkSize + 1, i * chunkSize)
    end
end

-- Iterates over 32-bit words of a given string
local function words(string)
    local iter = chunks(string, 4)
    return function()
        local i, chunk = iter()
        if not i then
            return nil
        end

        return i, array.toNumber(array.fromBytes(chunk))
    end
end

-- Rotates 32-bit word
local function rotateWord(number, direction)
    return (number >> direction) | (number << (32 - direction)) & 0xFFFFFFFF
end

function lib.sha256(message)
    local hash = array.copy(HASH_VALUES)

    for _, chunk in chunks(pad(message), 64) do
        local w = {}
        
        for i, word in words(chunk) do
            w[i] = word
        end

        for i = #w + 1, 64 do
            w[i] = 0
        end

        for i = 17, 64 do
            local s0 = rotateWord(w[i - 15],  7) ~ rotateWord(w[i - 15], 18) ~ (w[i - 15] >>  3)
            local s1 = rotateWord(w[i -  2], 17) ~ rotateWord(w[i -  2], 19) ~ (w[i -  2] >> 10)
            w[i - 16] = w[i - 16] + s0 + w[i - 7] + s1
        end

        local a, b, c, d, e, f, g, h = table.unpack(hash)
        for i = 1, 64 do
            local S1 = rotateWord(e, 6) ~ rotateWord(e, 11) ~ rotateWord(e, 25)
            local ch = (e & f) ~ ((~e) & g)
            local temp1 = h + S1 + ch + ROUND_CONSTANTS[i] + w[i]
            local S0 = rotateWord(a, 2) ~ rotateWord(a, 13) ~ rotateWord(a, 22)
            local maj = (a & b) ~ (a & c) ~ (b ~ c)
            local temp2 = S0 + maj

            h, g, f, e, d, c, b, a = g, f, e, d + temp1, c, b, a, temp1 + temp2
        end

        hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8] = hash[1] + a, hash[2] + b, hash[3] + c, hash[4] + d, hash[5] + e, hash[6] + f, hash[7] + g, hash[8] + h
    end

    local result = ""
    for i = 1, #hash do
        for byte = 0, 3 do
            result = result .. string.char((hash[i] >> (8 * byte)) & 0xFF)
        end
    end

    return result
end

----------------------------------------

return lib