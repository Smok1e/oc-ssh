local lib = {}

---------------------------------------- Buffered stream reading methods

-- Reads count unprocessed bytes from the buffer
local function bufferedStreamReadRaw(self, count)
    if self:remain() < count then
        return
    end

    local data = self.buffer:sub(self.offset + 1, self.offset + count)
    self:seek(count)

    return data
end

-- Reads unprocessed bytes until CLRF
local function bufferedStreamReadLineRaw(self)
    local line = self.buffer:sub(self.offset + 1, -1):match("^([^\r\n]*)\r\n$")
    if not line then
        return nil
    end

    self:seek(#line + 2)
    return line
end

-- Reads count bytes, may be overrided to add data processing
local function bufferedStreamRead(self, count)
    return self:readRaw(count)
end

-- Reads byte according to the section 5 of RFC 4251
local function bufferedStreamReadByte(self)
    local byte = self:read(1)
    if not byte then
        return
    end
    
    return byte:byte()
end

-- Reads uint32 according to the section 5 of RFC 4251
local function bufferedStreamReadUint32(self)
    local data = self:read(4)
    if not data then
        return
    end

    return (">I4"):unpack(data)
end

-- Reads string according to the section 5 of RFC 4251
local function bufferedStreamReadString(self)
    local length = self:readUint32()
    if not length then
        return nil
    end

    return self:read(length)
end

-- Reads name-list according to the section 5 of RFC 4251
local function bufferedStreamReadList(self)
    local string = self:readString()
    if not string then
        return nil
    end
   
    local list = {}
    for name in string:gmatch("([^,]+)") do
        table.insert(list, name)
    end

    return list
end

-- Reads boolean according to the section 5 of RFC 4251251
local function bufferedStreamReadBoolean(self)
    local byte = self:readByte()
    if byte == nil then
        return
    end

    return byte ~= 0
end

-- Reads mpint according to the section 5 of RFC 4251
local function bufferedStreamReadMpint(self)
    local data = self:readString()
    if not data then
        return
    end

    if data:byte() == 0 then
        return data:sub(2, -1)
    end

    return data
end

---------------------------------------- Buffered stream writing methods

-- Writes unprocessed bytes
local function bufferedStreamWriteRaw(self, data)
    self.buffer = self.buffer .. data
    return self
end

-- Writes unprocessed line, appending CLRF
local function bufferedStreamWriteLineRaw(self, line)
    return self:writeRaw(line .. "\r\n")
end

-- Writes bytes to the buffer, may be overrided to add data processing
local function bufferedStreamWrite(self, data)
    return self:writeRaw(data)
end

-- Writes byte according to the section 5 of RFC 4251
local function bufferedStreamWriteByte(self, byte)
    return self:write(string.char(byte))
end

-- Writes uint32 according to the section 5 of RFC 4251
local function bufferedStreamWriteUint32(self, integer)
    return self:write((">I4"):pack(integer))
end

-- Writes string according to the section 5 of RFC 4251
local function bufferedStreamWriteString(self, string)
    self:writeUint32(#string)
    self:write(string)

    return self
end

-- Writes name-list according to the section 5 of RFC 4251
local function bufferedStreamWriteList(self, list)
    return self:writeString(table.concat(list, ","))
end

-- Writes boolean according to the section 5 of RFC 4251
local function bufferedStreamWriteBoolean(self, boolean)
    return self:writeByte(boolean and 1 or 0)
end

-- Writes mpint according to the section 5 of RFC 4251
local function bufferedStreamWriteMpint(self, integer)
    integer = integer:match("^\x00*(.*)$")
    if (integer:byte(1) or 0) & 0x80 ~= 0 then
        integer = "\x00" .. integer
    end

    return self:writeString(integer)
end

---------------------------------------- Buffered stream 

-- Clears buffer
local function bufferedStreamClear(self, data)
    self.buffer = data or ""
    self.offset = 0
    return self
end

-- Skips count bytes of the buffer
local function bufferedStreamSeek(self, count, absolute)
    if absolute then
        self.offset = count
    else
        self.offset = self.offset + count
    end

    return self
end

local function bufferedStreamRemain(self)
    return #self.buffer - self.offset
end

local function bufferedStreamDiscard(self)
    return self:clear(self.buffer:sub(self.offset + 1, -1))
end

function lib.bufferedStream(data)
    local self = {}

    self.readRaw      = bufferedStreamReadRaw
    self.readLineRaw  = bufferedStreamReadLineRaw
    self.read         = bufferedStreamRead
    self.readByte     = bufferedStreamReadByte
    self.readUint32   = bufferedStreamReadUint32
    self.readString   = bufferedStreamReadString
    self.readList     = bufferedStreamReadList
    self.readBoolean  = bufferedStreamReadBoolean
    self.readMpint    = bufferedStreamReadMpint

    self.writeRaw     = bufferedStreamWriteRaw
    self.writeLineRaw = bufferedStreamWriteLineRaw
    self.write        = bufferedStreamWrite
    self.writeByte    = bufferedStreamWriteByte
    self.writeUint32  = bufferedStreamWriteUint32
    self.writeString  = bufferedStreamWriteString
    self.writeList    = bufferedStreamWriteList
    self.writeBoolean = bufferedStreamWriteBoolean
    self.writeMpint   = bufferedStreamWriteMpint
 
    self.clear        = bufferedStreamClear
    self.seek         = bufferedStreamSeek
    self.remain       = bufferedStreamRemain
    self.discard      = bufferedStreamDiscard

    return self:clear(data)
end

---------------------------------------- Encrypted stream

local function encryptedStreamRead(self, count)
    local data = self:readRaw(count)
    if not data then
        return nil
    end

    return self.cipher(data)
end

local function encryptedStreamWrite(self, data)
    return self:writeRaw(self.cipher(data))
end

function lib.encryptedStream(cipher, data)
    local self = lib.bufferedStream(data)
    self.cipher = cipher

    self.read  = encryptedStreamRead
    self.write = encryptedStreamWrite

    return self
end

----------------------------------------

return lib