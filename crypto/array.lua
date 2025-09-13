local lib = {}

---------------------------------------- Arrays

-- Performs n left circular shifts of the elements of the array
function lib.rotate(array, n)
    local result, n = {}, n or 1
    for i = 1, #array do
        result[i] = array[1 + (i + n - 1) % #array]
    end

    return result
end

-- Replaces each array entry with the corresponding substitution value in the table
function lib.substitute(array, lookupTable)
    local result = {}
    for i = 1, #array do
        result[i] = lookupTable[array[i] + 1]
    end

    return result
end

function lib.slice(array, begin, count)
    if not count then
        if begin < 0 then
            begin, count = #array + begin + 1, 1 - begin
        else
            begin, count = 1, begin
        end
    end

    return {table.unpack(array, begin, begin + count - 1)}
end

-- Returns copy of given array
function lib.copy(array)
    return {table.unpack(array)}
end

-- Performs basic split of the given data into the blocks of certain size
function lib.split(array, size)
    local blocks, currentBlock = {}, {}
    for i = 1, #array do
        currentBlock[#currentBlock + 1] = array[i]
        
        if #currentBlock == size then
            blocks[#blocks + 1] = currentBlock
            currentBlock = {}
        end
    end

    if #currentBlock > 0 then
        blocks[#blocks + 1] = currentBlock
    end

    return blocks
end

-- Appends a with values of b
function lib.append(a, b)
    for i = 1, #b do
        a[#a + 1] = b[i]
    end

    return a
end

-- Same as array.append, but produces new table
function lib.concat(a, b)
    local c = lib.copy(a)
    return lib.append(c, b)
end

-- Swaps indices with their values
function lib.inverse(table)
    local result = {}
    for key, value in pairs(table) do
        result[value] = key
    end
    
    return result
end

---------------------------------------- Conversions

-- Converts string into a byte array
function lib.fromBytes(bytes)
    return {bytes:byte(1, #bytes)}
end

-- Converts byte array into a string
function lib.toBytes(array)
    return string.char(table.unpack(array))
end

-- Converts string into character array
function lib.fromString(str)
    local array = {}
    for i = 1, #str do
        array[i] = str:sub(i, i)
    end

    return array
end

-- Converts character array into a string
function lib.toString(array)
    return table.concat(array, "")
end

-- Procuces array of bytes of a given number
function lib.fromNumber(number, size, bigEndian)
    local result = {}

    for i = 1, size do
        result[bigEndian and i or (size - i + 1)] = (number >> 8 * (size - i)) & 0xFF
    end

    return result
end

-- Converts bytes array into a number
function lib.toNumber(array)
    local number = 0
    for i = 1, #array do
        number = number | (array[i] << 8 * (#array - i))
    end

    return number
end

---------------------------------------- Long arithmetics

-- Returns element-wise XOR result of two arrays
-- Performs XOR only to the first value of lhs if rhs is a number
function lib.xor(lhs, rhs)
    if type(rhs) == "number" then
        rhs = { rhs }
    end
    
    local result = {}
    for i = 1, #lhs do
        result[i] = (i <= #rhs and rhs[i] or 0) ~ lhs[i]
    end

    return result
end

-- Initializes new counter with zero value
function lib.counter(size)
    local counter = {}
    for i = 1, size do
        counter[i] = 0
    end

    return counter
end

-- Increments counter by 1
function lib.incrementCounter(counter)
    local carry = 1
    for i = 1, #counter do
        local digit = counter[#counter - i + 1] + carry
        carry = digit >> 8

        counter[#counter - i + 1] = digit % 0x100
    end

    return counter
end

----------------------------------------

return lib