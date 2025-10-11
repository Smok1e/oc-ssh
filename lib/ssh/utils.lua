local lib = {}

----------------------------------------

function lib.randBytes(count)
    local bytes = {}
    for i = 1, count do
        bytes[i] = math.random(0x00, 0xFF)
    end

    return string.char(table.unpack(bytes))
end

function lib.dumpHex(bytes, message, from, to, lineSize)
    from = from or 1
    to = to or #bytes
    lineSize = lineSize or 16

    if message then
        print(message)
    end
    
    for offset = from - 1, to - 1, lineSize do
        io.write(("%04d: "):format(offset))

        local ascii = " "
        for i = 1, lineSize do
            local byte = bytes:byte(offset + i)
            if byte then
                -- from ' ' to '~'
                ascii = ascii .. ((0x20 <= byte and byte <= 0x7E) and string.char(byte) or ".")
                io.write(("%02x "):format(byte))
            else
                io.write("   ")
            end
        end

        print(ascii)
    end
end

----------------------------------------

return lib