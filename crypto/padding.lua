local array = require("crypto/array")

local lib = {}

----------------------------------------

-- Applies PKCS#7 (PKCS#5) padding to the given text
function lib.PKCS7Pad(text, blockSize)
    local padLength = blockSize - #text % blockSize
    return text .. (string.char(padLength):rep(padLength))
end

-- Reverses PKCS#7 padding operation
function lib.PKCS7Unpad(text)
    return text:sub(1, #text - text:byte(#text, #text))
end

-- Simply appends zeros to match the multiple of blockSize
function lib.zeroPad(text, blockSize)
    return text .. string.rep("\0", blockSize - #text % blockSize)
end

-- Applies base64 padding
function lib.base64Pad(text)
    local padLength = 4 - #text % 4
    if padLength == 4 then
        return text
    end

    return text .. ("="):rep(padLength)
end

-- Reverses base64 padding
function lib.base64Unpad(text)
    for i = #text, 1, -1 do
        if text:sub(i, i) ~= "=" then
            return text:sub(1, i)
        end
    end

    return text
end

----------------------------------------

return lib