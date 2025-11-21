local array = require("crypto/array")
local sha2 = require("crypto/sha2")

local lib = {
    x25519 = {},
    ed25519 = {}
}

---------------------------------------- I want to die please help me

-- Since the underlying finite field has 2^255 - 19 elements,
-- and Lua 5.3 uses 64-bit signed integers for number representation,
-- we will be using a multiple (16) of 16-bit words to store a single
-- field integer in a little-endian order.

local LIMB_MOD = 2^32
local LIMB_MASK = LIMB_MOD - 1

-- p, 2^255 - 19
local FIELD_MOD     = { 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF }

-- p - 2
local INVERSE_POWER = { 0xFFFFFFEB, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF }

-- (p + 3) / 8
local SQRT_POWER    = { 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0FFFFFFF }

-- sqrt(-1) mod p
local SQRT_CONSTANT = { 0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806, 0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480 }

---------------------------------------- Field elements conversion

-- Converts 32-byte string into number (string is treated as little-endian)
local function GF25519FromBytes(bytes, littleEndian)
    local x = {("<I4"):rep(#bytes // 4):unpack(bytes)}
    x[#x] = nil
    x[#x] = x[#x] & 0x7FFFFFFF
    
    return x
end

-- Converts number into 32-byte string (string is formed as little-endian)
local function GF25519ToBytes(x, littleEndian)
    return ("<I4"):rep(#x):pack(table.unpack(x))
end

-- Converts lua number into a field elem
local function GF25519FromNumber(number)
    return {number & LIMB_MASK, (number >> 32) & 0x7FFFFFFF, 0, 0, 0, 0, 0, 0}
end

-- Converts field elem into a lua number (up to 63th bit)
local function GF25519ToNumber(number)
    return ((number[2] & 0x7FFFFFFF) << 32) | number[1]
end

---------------------------------------- Arithmetic

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

local function GF25519Carry(number, carry)
    carry = carry or 0
    for i = 1, #number do
        local sum = number[i] + carry
        carry = sum >> 32
        number[i] = sum & LIMB_MASK
    end

    return carry
end

-- This function (hopefully) reduces given number, up to 16 limbs, by the mod p
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
            result[i] = sum & LIMB_MASK
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
    local low32 = tmp & LIMB_MASK
    
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
            product[i + j - 1] = sum & LIMB_MASK

            carry = hi + (sum >> 32)
        end

        product[i + 8] = (product[i + 8] or 0) + carry
    end

    return GF25519Reduce(product)
end

-- Computes number^power mod p using square-and-multiply method
local function GF25519Pow(number, power)
    local result = GF25519FromNumber(1)

    for i = 254, 0, -1 do
        result = GF25519Mul(result, result)

        if (power[(i // 32) + 1] >> (i % 32)) & 1 == 1 then
            result = GF25519Mul(result, number)
        end
    end

    return result
end

local function GF25519Inverse(number)
    -- We want to find such a^-1 that a*a^-1 gives 1 (mod p)
    -- Fermat's little theorem states that a^(p-1) ≡ 1 (mod p) when p is prime
    -- Since a^(p-1) = a^(p-2)*a ≡ 1 (mod p), a^(p-2) is the multiplicative
    -- inverse of a modulo p

    return GF25519Pow(number, INVERSE_POWER)
end

local function GF25519Sqrt(number)
    -- x = (x^2)^((p + 3) / 8) mod p
    local x = GF25519Pow(number, SQRT_POWER)

    if GF25519Compare(GF25519Mul(x, x), number) ~= 0 then
        return GF25519Mul(x, SQRT_CONSTANT)
    end

    return x
end

local function GF25519Div(lhs, rhs)
    return GF25519Mul(lhs, GF25519Inverse(rhs))
end

---------------------------------------- x25519 (RFC 7789)

-- x25519 uses Montgomery curve y^2 = x^3 + 486662*x^2 + x

local _121665 = GF25519FromNumber(121665)
local _9      = GF25519FromNumber(9)

-- Scalar is expected to be a 32-byte LE string
local function x25519ScalarProduct(scalar, point)
    local clamped = array.fromBytes(scalar)

    clamped[1] = clamped[1] & 0xF8
    clamped[32] = (clamped[32] & 0x7F) | 0x40

    local a = GF25519FromNumber(1)
    local b = array.copy(point)
    local c = GF25519FromNumber(0)
    local d = GF25519FromNumber(1)
    local e = GF25519FromNumber(0)
    local f = GF25519FromNumber(0)

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

local function randomBytes(n)
    local bytes = {}
    for i = 1, n do
        bytes[i] = math.random(0, 0xFF)
    end

    return string.char(table.unpack(bytes))
end

-- Computes 9^privateKey
function lib.x25519.generatePublicKey(privateKey)
    return GF25519ToBytes(x25519ScalarProduct(privateKey, _9))
end

-- Generates random private key and derives public key
function lib.x25519.generateKeypair()
    privateKey = randomBytes(32)
    return privateKey, lib.x25519.generatePublicKey(privateKey)
end

-- Computes shared secret based on your secret key and counter party public key
function lib.x25519.generateSharedSecret(privateKey, publicKey)  
    return GF25519ToBytes(x25519ScalarProduct(privateKey, GF25519FromBytes(publicKey)))
end

---------------------------------------- Ed25519 (RFC 8032)

-- Ed25519 uses the same curve, but in twisted Edwards form: -x^2 + y^2 = 1 - d*x^2*y^2

-- Curve constant, d = (-121665 / 121666) mod p
local d = { 0x135978A3, 0x75EB4DCA, 0x4141D8AB, 0x00700A4D, 0x7779E898, 0x8CC74079, 0x2B6FFE73, 0x52036CEE }

-- Group order, q = 2^252 + c, c = 27742317777372353535851937790883648493
local q = { 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000, 0x00000000, 0x10000000 }

-- c = 27742317777372353535851937790883648493
local c = { 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE }

-- c^2
local c2 = { 0xAB128969, 0xE2EDF685, 0x2298A31D, 0x68039276, 0xD217F5BE, 0x3DCEEC73, 0x1B7C309A, 0x01B39941 }

local _0 = GF25519FromNumber(0)
local _1 = GF25519FromNumber(1)
local _2 = GF25519FromNumber(2)

-- Ed25519 base point G, y = 4/5
local ED25519_BASE_POINT = { 
    X = { 0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760, 0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE, 0x216936D3 },
    Y = { 0x66666658, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666, 0x66666666 },
    Z = _1,
    T = { 0xA5B7DDA3, 0x6DDE8AB3, 0x775152F5, 0x20F09F80, 0x64ABE37D, 0x66EA4E8E, 0xD78B7665, 0x67875F0F }
}

local function addCShifted(dst, shiftBits)
    local wordShift = shiftBits // 32
    local bitShift = shiftBits % 32

    local cShifted = {}
    for i = 1, wordShift do
        cShifted[i] = 0
    end
    
    for i = 1, #c do
        cShifted[i + wordShift] = (cShifted[i + wordShift] or 0) | ((c[i] << bitShift) & LIMB_MASK)
        cShifted[i + wordShift + 1] = c[i] >> (32 - bitShift)
    end

    local carry = 0
    for i = 1, math.max(#dst, #cShifted) do
        local sum = (dst[i] or 0) + (cShifted[i] or 0) + carry
        dst[i] = sum & LIMB_MASK

        carry = (sum >> 32)
    end

    if carry ~= 0 then
        dst[#dst + 1] = (dst[#dst + 1] or 0) + carry
    end
end

local function mulLimbs32(a, b)
    local product = {}
    for i = 1, #a do
        local carry = 0

        for j = 1, #b do
            local lo, hi = mul32(a[i], b[j])

            local sum = (product[i + j - 1] or 0) + lo + carry
            product[i + j - 1] = sum & LIMB_MASK

            carry = hi + (sum >> 32)
        end

        if carry ~= 0 then
            product[i + #b] = (product[i + #b] or 0) + carry
        end
    end

    return product
end

local function mulLimbsByConstant32(x, constant)
    local product = {}
    local carry = 0
    for i = 1, #x do
        local lo, hi = mul32(constant, x[i])

        local sum = (product[i] or 0) + lo + carry
        product[i] = sum & LIMB_MASK

        carry = hi + (sum >> 32)
    end

    if carry ~= 0 then
        product[#product + 1] = carry
    end

    return product
end

local function addLimbs32(a, b)
    local result = {}
    local carry = 0
    for i = 1, math.max(#a, #b) do
        local sum = (a[i] or 0) + (b[i] or 0) + carry
        result[i] = sum & LIMB_MASK
        carry = (sum >> 32)
    end

    if carry ~= 0 then
        result[#result + 1] = carry
    end

    return result
end

local function subLimbs32(a, b)
    local result = {}
    local borrow = 0
    for i = 1, math.max(#a, #b) do
        local diff = (a[i] or 0) - (b[i] or 0) - borrow
        if diff < 0 then
            diff = diff + LIMB_MOD
            borrow = 1
        else
            borrow = 0
        end

        result[i] = diff
    end

    return result, borrow
end

local function packLimbs32LE(x)
    return ("<I4"):rep(#x):pack(table.unpack(x))
end

local function unpackLimbs32LE(str)
    local x = {("<I4"):rep(#str // 4):unpack(str)}
    x[#x] = nil

    return x
end

-- Reduces given 512-bit number, expressed as 16 32-bit limbs, by the modulo q (i swear i want to die please help)
local function Ed25519ReduceModQ(x)
    -- Normalize input
    for i = #x + 1, 16 do
        x[i] = 0
    end

    -- Represent given 512-bit number as a = a0 + a1*2^252 + a2*2^504
    -- q = 2^252 + c
    -- 2^252 = q - c ≡ -c (mod q)
    -- 2^504 = (2^252)^2 = (-c)^2 = c^2
    -- a = a0 + a1*(-c) + a2*c^2 = a0 - a1*c + a2*c^2

    -- r = r0 + r1*2^252

    -- First 224 bits of a0
    local a0 = {}
    for i = 1, 7 do
        a0[i] = x[i]
    end

    -- Last 28 bits of a0 (remaining 4 bits go to a1)
    a0[8] = x[8] & 0x0FFFFFFF

    -- First 224 bits of a1
    local a1 = {}
    for i = 1, 7 do
        a1[i] = (x[i + 7] >> 28) | ((x[i + 8] & 0x0FFFFFFF) << 4)
    end

    -- Last 28 bits of a1 (remaining 8 bits go to a2)
    a1[8] = (x[15] >> 28) | (x[16] & 0x00FFFFFF) << 4

    -- Remaining 8 bits is a2
    a2 = x[16] >> 24

    local a1c = mulLimbs32(a1, c)
    local a2c2 = mulLimbsByConstant32(c2, a2)

    -- r = a0 + a2c^2
    local r = addLimbs32(a0, a2c2)

    -- r -= a1c
    local borrow
    r, borrow = subLimbs32(r, a1c)

    -- If borrow > 0, then r is negative (e. g. shifted by 2^32N):
    -- R = r + 2^(32*N) = r + 2^252 * 2^(32*N − 252) ≡ r − c*2^(32*N − 252) (mod q)
    -- To compensate this, we should add c*2^(32*N − 252) to the result, which is
    -- c << (32*N - 252)
    if borrow ~= 0 then
        addCShifted(r, 32 * #r - 252)
    end
    
    for i = 1, 2 do
        -- Now that the original number is folded into r, r may count ~384 bits.
        -- Folding r again: r = r0 + r1*2^252 ≡ r0 - c*r1
        
        -- r0 is first 252 bits
        local r0 = {}
        for i = 1, 7 do
            r0[i] = r[i]
        end
        
        r0[8] = r[8] & 0x0FFFFFFF
        
        -- r1 is all the remaining bits
        local r1 = {}
        for i = 8, #r do
            r1[i - 7] = (r[i] >> 28) | (((r[i + 1] or 0) & 0x0FFFFFFF) << 4)
        end

        local r1c = mulLimbs32(r1, c)

        -- r = r0 - r1*c
        r, borrow = subLimbs32(r0, r1c)
        if borrow ~= 0 then
            addCShifted(r, 32 * #r - 252)
        end
    end

    return r
end

-- Computes x-coordinate
local function Ed25519RecoverX(y, sign)
    -- -x^2 + y^2 = 1 + d*x^2*y^2
    -- -x^2 - d*x^2*y^2 = 1 - y^2
    -- (d*y^2 + 1)*x^2 = y^2 - 1
    -- x^2 = (y^2 - 1) / (d*y^2 + 1) mod p

    local ySquare = GF25519Mul(y, y)
    local xSquare = GF25519Div(GF25519Sub(ySquare, _1), GF25519Add(GF25519Mul(d, ySquare), _1))

    local x = GF25519Sqrt(xSquare)
    if (x[1] & 1) ~= sign then
        x = GF25519Sub(_0, x)
    end

    return x
end

-- Decodes 32-bit Ed25519 point into its projective coordinates
local function Ed25519DecodePoint(bytes)
    local y = GF25519FromBytes(bytes)
    local x = Ed25519RecoverX(y, bytes:byte(-1) >> 7)
    
    return {
        X = x,
        Y = y,
        Z = GF25519FromNumber(1),
        T = GF25519Mul(x, y)
    }
end

-- Encodes Ed25519 point into 32-bit string
local function Ed25519EncodePoint(point)
    local zInv = GF25519Inverse(point.Z)
    local x = GF25519Mul(point.X, zInv)
    local y = GF25519Mul(point.Y, zInv)

    local bytes = GF25519ToBytes(y)
    if x[1] & 1 == 0 then
        return bytes
    end

    -- Set the most significant bit if X % 2 == 1
    return bytes:sub(1, -2) .. string.char(bytes:byte(-1) | 0x80)
end

local function Ed25519Equal(P, Q)
    return 
        GF25519Compare(GF25519Sub(GF25519Mul(P.X, Q.Z), GF25519Mul(Q.X, P.Z)), _0) == 0 and
        GF25519Compare(GF25519Sub(GF25519Mul(P.Y, Q.Z), GF25519Mul(Q.Y, P.Z)), _0) == 0
end

-- Computes P + Q
local function Ed25519Add(P, Q)
    local A = GF25519Mul(GF25519Sub(P.Y, P.X), GF25519Sub(Q.Y, Q.X))
    local B = GF25519Mul(GF25519Add(P.Y, P.X), GF25519Add(Q.Y, Q.X))
    local C = GF25519Mul(GF25519Mul(P.T, _2), GF25519Mul(d, Q.T))
    local D = GF25519Mul(GF25519Mul(P.Z, _2), Q.Z)
    local E = GF25519Sub(B, A)
    local F = GF25519Sub(D, C)
    local G = GF25519Add(D, C)
    local H = GF25519Add(B, A)

    return {
        X = GF25519Mul(E, F),
        Y = GF25519Mul(G, H),
        Z = GF25519Mul(F, G),
        T = GF25519Mul(E, H)
    }
end

-- Computes scalar * point; Scalar should be 32-byte LE string
-- Again, square & multiply
local function Ed25519ScalarProduct(scalar, point)
    scalar = {scalar:byte(1, -1)}

    -- Neutral element
    local result = {
        X = _0,
        Y = _1,
        Z = _1,
        T = _0
    }

    for i = 0, 255 do
        if (scalar[(i // 8) + 1] >> (i % 8)) & 1 == 1 then
            result = Ed25519Add(result, point)
        end

        point = Ed25519Add(point, point)
    end

    return result
end

local function Ed25519ExpandSecret(secret)
    local hash = sha2.sha512(secret)
    local bytes = {hash:byte(1, 32)}

    -- Clear 3 lowest bits of the first octet
    bytes[1] = bytes[1] & 0xF8

    -- Clear the highest bit and set second highest bit of the last octet
    bytes[32] = (bytes[#bytes] & 0x7F) | 0x40

    return string.char(table.unpack(bytes)), hash:sub(33, -1)
end

-- Computes SHA2-512 hash of the input message and reduces it by modulo q
local function sha512ModQ(message)
    return Ed25519ReduceModQ(unpackLimbs32LE(sha2.sha512(message)))
end

function lib.ed25519.generatePublicKey(privateKey)
    local scalar = Ed25519ExpandSecret(privateKey)
    return Ed25519EncodePoint(Ed25519ScalarProduct(scalar, ED25519_BASE_POINT))
end

function lib.ed25519.generateKeypair()
    privateKey = randomBytes(32)
    return privateKey, lib.ed25519.generatePublicKey(privateKey)
end

function lib.ed25519.sign(privateKey, message)
    local a, prefix = Ed25519ExpandSecret(privateKey)
    local A = Ed25519EncodePoint(Ed25519ScalarProduct(a, ED25519_BASE_POINT))
    local r = sha512ModQ(prefix .. message)
    local R = Ed25519EncodePoint(Ed25519ScalarProduct(packLimbs32LE(r), ED25519_BASE_POINT))
    local h = sha512ModQ(R .. A .. message)
    local s = Ed25519ReduceModQ(addLimbs32(r, mulLimbs32(h, unpackLimbs32LE(a))))

    return R .. packLimbs32LE(s)
end

function lib.ed25519.verify(publicKey, message, signature)
    local A = Ed25519DecodePoint(publicKey)
    local Rs = signature:sub(1, 32)
    local R = Ed25519DecodePoint(Rs)
    local h = packLimbs32LE(sha512ModQ(Rs .. publicKey .. message))
    local sB = Ed25519ScalarProduct(signature:sub(33, -1), ED25519_BASE_POINT)
    local hA = Ed25519ScalarProduct(h, A)

    return Ed25519Equal(sB, Ed25519Add(R, hA))
end

----------------------------------------

return lib