local sha2 = require("crypto/sha2")
local curve25519 = require("crypto/curve25519")
local aes = require("crypto/aes")
local ctr = require("crypto/ctr")
local hmac = require("crypto/hmac")

local constants = require("ssh/constants")
local streamlib = require("ssh/stream")
local utils = require("ssh/utils")

local transport = {}
local transportMessageHandlers = {}

local SSH_MESSAGE = constants.SSH_MESSAGE

---------------------------------------- Socket communic0tion

local function transportReceive(self, data)
    self.inputStream:writeRaw(data)

    if not self.serverVersion then
        self:versionExchange()
        return
    end

    -- Previous packet was partially received
    if self.pendingPacketLength then
        if self.inputStream:remain() >= self.pendingPacketLength then
            self:receivePacket(self.pendingPacketLength)
            self.pendingPacketLength = nil
        else
            return
        end
    end

    -- Handle remaining data
    while self.inputStream:remain() >= 4 do
        local packetLength = self.inputStream:readUint32()

        if self.inputStream:remain() >= packetLength then
            self:receivePacket(packetLength)
        else
            self.pendingPacketLength = packetLength
        end
    end
end

local function transportSend(self)
    self.sendCallback(self.outputStream.buffer)
    self.outputStream:clear()
end

---------------------------------------- Packet processing

local function transportVersionExchange(self)
    local serverVersion = self.inputStream:readLineRaw()
    if not serverVersion then
        error("version exchange failed")
        return
    end

    self.inputStream:discard()

    if self.verbose then
        print("[ssh-transport] Server version: " .. serverVersion)
    end

    self.serverVersion = serverVersion
    self.outputStream:writeLineRaw(self.clientVersion)
    self:send()
end

local function transportReceivePacket(self, packetLength)
    local packet = streamlib.bufferedStream()
    packet:writeUint32(packetLength)
    packet:write(self.inputStream:read(packetLength))

    -- Validate MAC
    if self.cipher.engaged then
        local serverMac = self.inputStream:readRaw(self.cipher.macSizeServerToClient // 8)
        local mac = hmac.hmac_sha2(
            self.cipher.macSizeServerToClient,
            self.cipher.integrityKeyServerToClient,
            (">I4"):pack(self.sequenceNumberServerToClient) .. packet.buffer
        )

        if mac ~= serverMac then
            error("message authentication code incorrect")
        end
    end

    packet:seek(4)
    local paddingLength = packet:readByte()
    local messagePayload = packet:read(packetLength - paddingLength - 1)
    local messageStream = streamlib.bufferedStream(messagePayload)

    -- Processing message
    local messageId = messageStream:readByte()

    if self.verbose then
        print("[ssh-transport] Received " .. constants.strMessageId(messageId))
    end

    for _, handlers in pairs(self.messageHandlers) do
        local handler = handlers[1][messageId]

        if handler then
            messageStream:seek(1, true)

            local instance = handlers[2]
            if instance then
                handler(instance, messageStream)
            else
                handler(messageStream)
            end
        end
    end

    -- Update sequence number
    self.sequenceNumberServerToClient = (self.sequenceNumberServerToClient + 1) % constants.SEQNO_MAX
    self.inputStream:discard()
end

local function transportSendPacket(self, payload)
    -- (uint32) packet_length + (byte) payload_length + payload size should be multiple of 16 bytes
    local paddingLength = constants.PACKET_PADDING - (4 + 1 + #payload) % constants.PACKET_PADDING

    -- Also, padding should be at least 4 bytes
    if paddingLength < 4 then
        paddingLength = paddingLength + constants.PACKET_PADDING
    end

    local packet = streamlib.bufferedStream()
    packet:writeUint32(1 + #payload + paddingLength)
    packet:writeByte(paddingLength, 1)
    packet:write(payload)
    packet:write(utils.randBytes(paddingLength))

    self.outputStream:write(packet.buffer)

    -- Append MAC
    if self.cipher.engaged then
        local mac = hmac.hmac_sha2(
            self.cipher.macSizeClientToServer,
            self.cipher.integrityKeyClientToServer,
            (">I4"):pack(self.sequenceNumberClientToServer) .. packet.buffer
        )

        self.outputStream:writeRaw(mac)
    end

    -- Flush data
    self:send()

    -- Update sequence number
    self.sequenceNumberClientToServer = (self.sequenceNumberClientToServer + 1) % constants.SEQNO_MAX
end

---------------------------------------- Packet factory

local function packetSend(self)
    self.transport:sendPacket(self.buffer)
end

local function transportPacket(self)
    local packet = streamlib.bufferedStream()
    packet.transport = self
    packet.send = packetSend

    return packet
end

---------------------------------------- Key exchange

transportMessageHandlers[SSH_MESSAGE.KEXINIT] = function(self, stream)
    self.keyExchange = {}
    self.keyExchange.serverPayload = stream.buffer

    -- Cookie
    stream:seek(16)
    
    local serverSupportedAlgorithms = {}
    for _, key in pairs(constants.ALGORITHMS_ORDER) do
        serverSupportedAlgorithms[key] = stream:readList()
    end

    -- Reply
    self:keyExchangeInit()
    
    -- Guess algorithms
    self.algorithms = {}

    for key, clientList in pairs(constants.ALGORITHMS) do
        for _, clientAlgorithm in pairs(clientList) do
            for _, serverAlgorithm in pairs(serverSupportedAlgorithms[key]) do
                if clientAlgorithm == serverAlgorithm then
                    self.algorithms[key] = clientAlgorithm
                    goto guessed
                end
            end
        end

        error("can't agree on " .. key .. " algorithm")
        ::guessed::
    end

    if self.verbose then
        local list = {}
        for key, algorithm in pairs(self.algorithms) do
            table.insert(list, algorithm)
        end

        print("[ssh-transport] Using algorithms: " .. table.concat(list, ", "))
    end

    -- Initiate key exchange (ECDH is the only option so far)
    self:keyExchangeECDHInit()    
end

transportMessageHandlers[SSH_MESSAGE.KEX_ECDH_REPLY] = function(self, stream)
    local serverPublicHostKey = stream:readString()
    local serverPublicKey = stream:readString()
    local serverHostSignature = stream:readString()

    assert(self.algorithms.keyExchange == "curve25519-sha256")
    local sharedSecret = curve25519.x25519.generateSharedSecret(self.privateKey, serverPublicKey)

    stream:clear()
    stream:writeMpint(sharedSecret)
    local encodedSharedSecret = stream.buffer

    stream:clear()
    stream:writeString(self.clientVersion)
    stream:writeString(self.serverVersion)
    stream:writeString(self.keyExchange.clientPayload)
    stream:writeString(self.keyExchange.serverPayload)
    stream:writeString(serverPublicHostKey)
    stream:writeString(self.publicKey)
    stream:writeString(serverPublicKey)
    stream:writeMpint(sharedSecret)

    local exchangeHash = sha2.sha256(stream.buffer)
    self.sessionId = exchangeHash

    -- Verify server host key
    if not self:verifyHostKey(serverPublicHostKey, serverHostSignature) then
        error("host key verification failed")
    end

    if self.verbose then
        print("[ssh-transport] Host key signature is valid")
    end

    if self.hostKeyHandler then
        if not self:hostKeyHandler(serverPublicHostKey) then
            error("server host key refused")
        end

        if self.verbose then
            print("[ssh-transport] Host key legitimacy confirmed")
        end
    else
        if self.verbose then
            print("[ssh-transport] Host key handler not set, could not verify host key legitimacy!")
        end
    end

    -- Determine encryption key sizes
    local function cipherKeySize(cipher)
        local keySize = tonumber(cipher:match("aes(%d+)%-ctr"))
        assert(keySize)

        return keySize
    end

    self.cipher.keySizeClientToServer = cipherKeySize(self.algorithms.encryptionClientToServer)
    self.cipher.keySizeServerToClient = cipherKeySize(self.algorithms.encryptionServerToClient)
    
    -- Derive keys as described in RFC 5656
    local function deriveKey(x)
        local key = sha2.sha256(
            table.concat {
                encodedSharedSecret,
                exchangeHash,
                x,
                self.sessionId
            }
        )

        if self.verbose then
            utils.dumpHex(key, "[ssh-transport] Key '" .. x .. "':")
        end

        return key
    end
    
    self.cipher.ivClientToServer           = deriveKey("A")
    self.cipher.ivServerToClient           = deriveKey("B")
    self.cipher.keyClientToServer          = deriveKey("C")
    self.cipher.keyServerToClient          = deriveKey("D")
    self.cipher.integrityKeyClientToServer = deriveKey("E")
    self.cipher.integrityKeyServerToClient = deriveKey("F")

    -- Client->server encryption
    self.cipher.clientToServer = ctr.new(
        self.cipher.ivClientToServer,
        aes.encryptor(self.cipher.keyClientToServer, self.cipher.keySizeClientToServer),
        16
    )

    -- Server->client decryption
    self.cipher.serverToClient = ctr.new(
        self.cipher.ivServerToClient,
        aes.encryptor(self.cipher.keyServerToClient, self.cipher.keySizeServerToClient),
        16
    )

    -- Determine MAC sizes
    local function macSize(method)
        local size = method:match("hmac%-sha2%-(%d+)")
        assert(size)

        return tonumber(size)
    end

    self.cipher.macSizeClientToServer = macSize(self.algorithms.macClientToServer)
    self.cipher.macSizeServerToClient = macSize(self.algorithms.macServerToClient)
end

local function transportKeyExchangeInit(self)
    local packet = self:packet()
    packet:writeByte(SSH_MESSAGE.KEXINIT)
    packet:write(utils.randBytes(16))

    for _, key in pairs(constants.ALGORITHMS_ORDER) do
        packet:writeList(constants.ALGORITHMS[key] or {})
    end

    packet:writeBoolean(false)
    packet:writeUint32(0)

    self.keyExchange.clientPayload = packet.buffer
    packet:send()
end

-- Elliptic-curve Diffie-Hellman key exchange (RFC 5656)
local function transportKeyExchangeECDHInit(self)
    assert(self.algorithms.keyExchange == "curve25519-sha256")
    
    self.privateKey, self.publicKey = curve25519.x25519.generateKeypair()
    
    local packet = self:packet()
    packet:writeByte(SSH_MESSAGE.KEX_ECDH_INIT)
    packet:writeString(self.publicKey)
    packet:send()
end

-- Ed25519 (RFC 8709)
local function transportVerifyHostKey(self, serverPublicHostKey, serverHostSignature)
    assert(self.algorithms.serverHostKey == "ssh-ed25519")

    local stream = streamlib.bufferedStream(serverPublicHostKey)
    local keyType = stream:readString()
    local key = stream:readString()

    if self.algorithms.serverHostKey ~= keyType then
        if self.verbose then
            print("[ssh-transport] Server host key type " .. keyType .. " does not match expected " .. self.algorithms.sereverHostKey)
        end

        return false
    end

    stream:clear(serverHostSignature)
    local signatureType = stream:readString()
    local signature = stream:readString()

    assert(signatureType == keyType)

    return curve25519.ed25519.verify(key, self.sessionId, signature)
end

transportMessageHandlers[SSH_MESSAGE.NEWKEYS] = function(self, stream)
    local packet = self:packet()
    packet:writeByte(SSH_MESSAGE.NEWKEYS)
    packet:send()

    -- Taking new keys into use
    self.inputStream = streamlib.encryptedStream(self.cipher.serverToClient)
    self.outputStream = streamlib.encryptedStream(self.cipher.clientToServer)
    self.cipher.engaged = true

    if self.verbose then
        print("[ssh-transport] Key exchange done")
    end

    -- Key exchange done
    self.keyExchange = nil

    self.ready = true
    for _, callback in pairs(self.readyCallbacks) do
        callback()
    end

    self.readyCallbacks = nil
end

---------------------------------------- Callbacks

-- Schedules callback to be called when the transport layer is ready
local function transportOnReady(self, callback)
    if self.ready then
        callback()
        return
    end

    table.insert(self.readyCallbacks, callback)
end

-- Registers message handlers to be called when certain message arrives.
-- arrives. Handlers should be a table in format {id = handler, ...}.
-- Additional instance argument may be supplied to pass it to the underlying handler
-- as the first argument.
local function transportListen(self, handlers, instance)
    table.insert(self.messageHandlers, {handlers, instance})
end

---------------------------------------- Service requests

local function transportRequestService(self, serviceName, acceptCallback)
    assert(self.ready, "can't make service request before connection is established")

    local packet = self:packet()
    packet:writeByte(SSH_MESSAGE.SERVICE_REQUEST)
    packet:writeString(serviceName)
    packet:send()

    if self.verbose then
        print("[ssh-transport] Service " .. serviceName .. " requested")
    end

    self.serviceRequestCallbacks[serviceName] = acceptCallback
end

transportMessageHandlers[SSH_MESSAGE.SERVICE_ACCEPT] = function(self, stream)
    local serviceName = stream:readString()
    if self.verbose then
        print("[ssh-transport] Service " .. serviceName .. " request accepted")
    end

    local acceptCallback = self.serviceRequestCallbacks[serviceName]
    if acceptCallback then
        acceptCallback(self)
    end
end

---------------------------------------- Disconnection 

local function transportDisconnect(self, reasonCode, description)
    local packet = self:packet()
    packet:write(SSH_MESSAGE.DISCONNECT)
    packet:writeUint32(reasonCode)
    packet:writeString(description)
    packet:writeString("")
    packet:send()
end

transportMessageHandlers[SSH_MESSAGE.DISCONNECT] = function(self, stream)
    local reasonCode = stream:readUint32()
    local description = stream:readString()
    
    if self.verbose then
        print(
            ("[ssh-transport] Disconnected: %s (%d), %s"):format(
                constants.strDisconnectCode(reasonCode), 
                reasonCode,
                description
            )
        )
    end

    if self.disconnectHandler then
        self.disconnectHandler(reasonCode, description)
    else
        print("[ssh-transport] transport.disconnectHandler not set, throwing error")
        error("disconnected")
    end
end

----------------------------------------

function transport.new(sendCallback, clientVersion)
    local self = {}
    
    self.clientVersion = clientVersion
    self.sendCallback  = sendCallback

    self.receive = transportReceive
    self.send = transportSend

    self.versionExchange = transportVersionExchange
    self.receivePacket = transportReceivePacket
    self.sendPacket = transportSendPacket
    
    self.packet = transportPacket
    
    self.keyExchangeInit = transportKeyExchangeInit
    self.keyExchangeECDHInit = transportKeyExchangeECDHInit
    self.verifyHostKey = transportVerifyHostKey
    
    self.readyCallbacks = {}
    self.onReady = transportOnReady

    self.messageHandlers = {}
    self.listen = transportListen
    
    self.serviceRequestCallbacks = {}
    self.requestService = transportRequestService

    self.disconnect = transportDisconnect

    self.cipher = {}
    self.inputStream = streamlib.bufferedStream()
    self.outputStream = streamlib.bufferedStream()
    self.sequenceNumberClientToServer = 0
    self.sequenceNumberServerToClient = 0

    self:listen(transportMessageHandlers, self)
    return self
end

----------------------------------------

return transport