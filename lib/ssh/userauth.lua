local constants = require("ssh/constants")
local streamlib = require("ssh/stream")
local keylib = require("ssh/key")
local utils = require("ssh/utils")

local userauth = {}

local SSH_MESSAGE = constants.SSH_MESSAGE

---------------------------------------- Authentication request

local function userauthRequestConnection(self)
    assert(self.user, "userauth.user not set")
    assert(self.method, "userauth.method not set")

    if self.verbose then
        print(
            ("[ssh-userauth] Requesting %s authentication for user %s"):format(
                self.method.name,
                self.user
            )
        )
    end

    local packet = self.transport:packet()
    packet:writeByte(SSH_MESSAGE.USERAUTH_REQUEST)
    packet:writeString(self.user)
    packet:writeString("ssh-connection")
    packet:writeString(self.method.name)
    self.method:populateRequest(packet)
    
    packet:send()
end

---------------------------------------- Messge handlers

local userauthMessageHandlers = {
    [SSH_MESSAGE.USERAUTH_SUCCESS] = function(self, stream)
        if self.verbose then
            print("[ssh-userauth] Authentication succeeded")
        end

        if self.successHandler then
            self.successHandler()
        end
    end,

    [SSH_MESSAGE.USERAUTH_FAILURE] = function(self, stream)
        local possibleMethods = stream:readList()

        if self.verbose then
            print("[ssh-userauth] Authentication failed; possible methods: " .. table.concat(possibleMethods, ", "))
        end

        if self.failureHandler then
            self.failureHandler(possibleMethods)
        end
    end,

    [SSH_MESSAGE.USERAUTH_BANNER] = function(self, stream)
        if self.verbose then
            print("[ssh-userauth] Banner received")
        end

        if self.bannerHandler then
            self.bannerHandler(stream:readString())
        end         
    end,

    [SSH_MESSAGE.USERAUTH_PK_OK] = function(self, stream)
        local keyType = stream:readString()
        local publicKey = stream:readString()

        if self.verbose then
            print("[ssh-userauth] " .. keyType .. " key accepted")
        end

        if self.method.onKeyAccepted then
            self.method:onKeyAccepted(self, keyType, publicKey)
        end
    end
}

----------------------------------------

function userauth.new(transport)
    local self = {}
    self.transport = transport

    self.requestConnection = userauthRequestConnection

    self.transport:listen(userauthMessageHandlers, self)
    
    return self
end

---------------------------------------- Public key

local function publicKeyPolulateRequest(self, packet)
    packet:writeBoolean(false)
    packet:writeString(self.key.type)
    packet:writeString(keylib.encode(self.key))

    self.requestPayload = packet.buffer
end

local function publicKeyOnKeyAccepted(self, userauthInstance, keyType, publicKey)
    assert(keyType == self.key.type)
    
    local packet = userauthInstance.transport:packet()
    packet:writeByte(SSH_MESSAGE.USERAUTH_REQUEST)
    packet:writeString(userauthInstance.user)
    packet:writeString("ssh-connection")
    packet:writeString("publickey")
    packet:writeBoolean(true)
    packet:writeString(self.key.type)
    packet:writeString(keylib.encode(self.key))

    local stream = streamlib.bufferedStream()
    stream:writeString(userauthInstance.transport.sessionId)
    stream:write(packet.buffer)
    local signature = self.signCallback(stream.buffer)

    packet:writeString(signature)
    packet:send()
end

function userauth.publicKey(key, signCallback)
    local self = {}
    self.name = "publickey"
    self.key = key
    self.signCallback = signCallback

    self.populateRequest = publicKeyPolulateRequest
    self.onKeyAccepted = publicKeyOnKeyAccepted

    return self
end

---------------------------------------- Password

local function passwordPopulateRequest(self, packet)
    packet:writeBoolean(false)
    packet:writeString(self.pass)
end

function userauth.password(pass)
    local self = {}
    self.name = "password"
    self.pass = pass

    self.populateRequest = passwordPopulateRequest

    return self
end

----------------------------------------

return userauth