local array = require("crypto/array")

local lib = {}

----------------------------------------

local function GF25519ToBytes(number, littleEndian)
    local result = {}

    if littleEndian then
        for i = 1, #number do
            result[i] = ("<I4"):pack(number[i])
        end
    else
        for i = 1, #number do
            result[#number - i + 1] = (">I4"):pack(number[i])
        end
    end

    return table.concat(result)
end

local function GF25519FromBytes(bytes)
    local number = {}
    for i = 1, #bytes // 4 do
        number[i] = (">I4"):unpack(bytes:sub(#bytes - 4 * i + 1, #bytes - 4 * (i - 1)))
    end

    local remain = #bytes % 4
    if remain ~= 0 then
        number[#number + 1] = (">I" .. remain):unpack(bytes:sub(1, remain + 1))
    end

    for i = #number + 1, 8 do
        number[i] = 0
    end

    return number
end

local function GF25519FromNumber(number)
    return {number & 0xFFFFFFFF, (number >> 32) & 0x7FFFFFFF, 0, 0, 0, 0, 0, 0}
end

local function GF25519ToNumber(number)
    return ((number[2] & 0x7FFFFFFF) << 32) | number[1]
end

---------------------------------------- I want to die please help me

-- Since the underlying finite field has 2^255 - 19 elements,
-- and Lua 5.3 uses 64-bit signed integers for number representation,
-- we will be using a multiple (16) of 16-bit words to store a single
-- field integer in a little-endian order.

-- p, 2^255 - 19
local FIELD_MOD = {0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF}

-- Limb limit
local LIMB_MOD = 2^32

-- Returns 1 if lhs > rhs, 0 if lhs == rhs, -1 if lhs < rhs
local function GF25519Compare(lhs, rhs)
    for i = math.max(#lhs, #rhs), 1, -1 do
        local a, b = lhs[i] or 0, rhs[i] or 0

        if a > b then
            return 1
        end

        if a < b then
            return -1
        end
    end

    return 0
end

local function GF25519Carry(number)
    local carry = 0
    for i = 1, 8 do
        local sum = number[i] + carry
        carry = sum >> 32
        number[i] = sum & 0xFFFFFFFF
    end

    return carry
end

-- This function hopefully reduces given number, up to 16 limbs, by the mod p
--
-- p = 2^255 - 19 => 2^255 = p + 19
-- 2^256 = 2^(255 + 1) = 2^255 * 2 = 2(p + 19) = 2p + 38
-- a mod p = (a0*2^0 + a1*2^32 + a2*2^64 + ... + a7*2^224 + a8*2^256     + a9*2^288          + ... + a15*2^480) mod p
--         = (a0*2^0 + a1*2^32 + a2*2^64 + ... + a7*2^224 + a8*(2p + 38) + a9*2^32*(2p + 38) + ... + a15*(2p + 38)*2^224) mod p
--         ≡ (a0*2^0 + a1*2^32 + a2*2^64 + ... + a7*2^224 + a8*38 + a9*2^32*38 + ... + a15*2^224*38) mod p
--         = (a0 + 38*a8)*2^0 + (a1 + 38*a9)*2^32 + (a2 + 38*a10)*2^64 + ... + (a7 + 38*a15)*2^224 mod p
local function GF25519Reduce(number)
    -- Folding higher limbs
    local result = {}
    for i = 1, 8 do
        result[i] = number[i] + 38 * (number[i + 8] or 0)
    end

    -- Carry propagation
    local carry = GF25519Carry(result)

    -- After previous propagation we may have left carry which is multiples of 2^256
    -- Folding it back: 2^256 = 2*((2^255 - 19) + 19) = 2*(p + 19) = 2p + 38 ≡ 38 (mod p)
    result[1] = result[1] + 38 * carry

    -- Now the least significant limb may have overflown, so performing carry propagation again
    GF25519Carry(result)

    -- Now fold the 255th bit
    local top = (result[8] >> 31) & 1
    result[8] = result[8] & 0x7FFFFFFF

    -- 2^255 ≡ 19 (mod p)
    result[1] = result[1] + 19 * top
    GF25519Carry(result)

    -- Now we are sure that the value does not exceed 2^255 - 1, however,
    -- it can yet exceed 2^255 - 19. In that case, we should perform
    -- one final subtraction of p. Comparison and subtraction is
    -- basically the same operation, so they may and should be combined,
    -- but who cares... 
    if GF25519Compare(result, FIELD_MOD) >= 0 then
        local borrow = 0
        for i = 1, 8 do
            local diff = result[i] - FIELD_MOD[i] - borrow
            if diff < 0 then
                diff = diff + LIMB_MOD
                borrow = 1
            else
                borrow = 0
            end

            result[i] = diff
        end
    end

    return result
end

local function GF25519Add(lhs, rhs)
    local result = {}
    for i = 1, 8 do
        result[i] = lhs[i] + rhs[i]
    end

    return GF25519Reduce(result)
end

local function GF25519Sub(lhs, rhs)
    local result = {}

    for i = 1, 8 do
        result[i] = lhs[i] - rhs[i]
    end

    if GF25519Compare(result, {0, 0, 0, 0, 0, 0, 0, 0}) < 0 then
        local carry = 0
        for i = 1, 8 do
            local sum = result[i] + FIELD_MOD[i] + carry
            result[i] = sum & 0xFFFFFFFF
            carry = sum >> 32
        end
    end

    local borrow = 0
    for i = 1, 8 do
        result[i] = result[i] - borrow

        if result[i] < 0 then
            result[i] = result[i] + LIMB_MOD
            borrow = 1
        else
            borrow = 0
        end
    end

    return result
end

-- Since lua 5.3 using 64-bit signed integers, the product of 2^32 * 2*32 may
-- overflow. This function safely multiplies given 32-bit numbers and returns 
-- high and low 32-bit parts of the product
local function mul32(lhs, rhs)
    -- a * b = (a0*2^0 + a1*2^16) * (b0*2^0 + b1*2^16)
    --       = (a0 + a1*2^16) * (b0 + b1*2^16)
    --       = a0*b0 + a1*2^16*b0 + a0*b1*2^16 + a1*2^16*b1*2^16
    --       = a0*b0 + (a1*b0 + a0*b1)*2^16 + a1*b1*2^32
    --         -----    -------------         -----
    --          low         mid                high
    -- 
    -- a * b = low + mid*2^16 + high*2^32 = low + mid << 16 + high << 32

    local a0 = lhs & 0xFFFF
    local a1 = (lhs >> 16) & 0xFFFF
    local b0 = rhs & 0xFFFF
    local b1 = (rhs >> 16) & 0xFFFF

    local low  = a0 * b0
    local high = a1 * b1
    local mid  = a1 * b0 + a0 * b1

    local tmp = low + (mid << 16)

    -- For low part we are taking only lowest 32 bits
    local low32 = tmp & 0xFFFFFFFF
    
    -- All bits above 32 from low + mid*2^16 are going into high part
    local high32 = high + (tmp >> 32)

    return low32, high32
end

local function GF25519Mul(lhs, rhs)
    local product = {}

    for i = 1, 8 do
        local carry = 0

        for j = 1, 8 do
            local lo, hi = mul32(lhs[i], rhs[j])

            local sum = (product[i + j - 1] or 0) + lo + carry
            product[i + j - 1] = sum & 0xFFFFFFFF

            carry = hi + (sum >> 32)
        end

        product[i + 8] = (product[i + 8] or 0) + carry
    end

    return GF25519Reduce(product)
end

-- We want to find such a^-1 that a*a^-1 gives 1 (mod p)
-- Fermat's little theorem states that a^(p-1) ≡ 1 (mod p) when p is prime
-- Since a^(p-1) = a^(p-2)*a ≡ 1 (mod p), a^(p-2) is the multiplicative
-- inverse of a modulo p.
-- p - 2 is actually 2^255 - 21, and it has all of the bits set to 1 
-- except 2nd and 4th least significant.
local function GF25519Inverse(number)
    local result = array.copy(number)
    for i = 253, 0, -1 do
        result = GF25519Mul(result, result)

        if i ~= 2 and i ~= 4 then
            result = GF25519Mul(result, number)
        end
    end

    return result
end

---------------------------------------- Elliptic curve arithmetic

local _121665 = GF25519FromNumber(121665)
local _9      = GF25519FromNumber(9)

-- Scalar is expected to be a string of 32 bytes
local function curveScalarProduct(point, scalar)
    local clamped = array.fromBytes(scalar)

    clamped[1] = clamped[1] & 0xF8
    clamped[32] = (clamped[32] & 0x7F) | 0x40

    local a = GF25519FromNumber(1)
    local b = array.copy(point)
    local c = GF25519FromNumber(0)
    local d = GF25519FromNumber(1)
    local f, e

    for i = 254, 0, -1 do
        local bit = (clamped[(i >> 3) + 1] >> (i & 7)) & 1 == 1

        if bit then
            a, b = b, a
            c, d = d, c
        end

        e = GF25519Add(a, c)       
        a = GF25519Sub(a, c)
        c = GF25519Add(b, d)
        b = GF25519Sub(b, d)
        d = GF25519Mul(e, e)
        f = GF25519Mul(a, a)
        a = GF25519Mul(c, a)
        c = GF25519Mul(b, e)
        e = GF25519Add(a, c)
        a = GF25519Sub(a, c)
        b = GF25519Mul(a, a)
        c = GF25519Sub(d, f)
        a = GF25519Mul(c, _121665)
        a = GF25519Add(a, d)
        c = GF25519Mul(c, a)
        a = GF25519Mul(d, f)
        d = GF25519Mul(b, point)
        b = GF25519Mul(e, e)

        if bit then
            a, b = b, a
            c, d = d, c
        end
    end

    c = GF25519Inverse(c)
    a = GF25519Mul(a, c)

    return a
end

----------------------------------------

-- Computes 9^privateKey
function lib.generatePublicKey(privateKey)
    return GF25519ToBytes(curveScalarProduct(_9, privateKey))
end

-- Computes shared secret based on your secret key and counter party public key
function lib.x25519(privateKey, publicKey)  
    return GF25519ToBytes(curveScalarProduct(GF25519FromBytes(publicKey), privateKey))
end

-- Generates random private key and derives public key
function lib.generateKeypair()
    local privateKey = {}
    for i = 1, 32 do
        privateKey[i] = string.char(math.random(0x00, 0xFF))
    end

    privateKey = table.concat(privateKey)
    return privateKey, lib.generatePublicKey(privateKey)
end

----------------------------------------

return lib