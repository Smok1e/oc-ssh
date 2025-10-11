local constants = require("ssh/constants")
local streamlib = require("ssh/stream")

local connection = {}

local SSH_MESSAGE = constants.SSH_MESSAGE

---------------------------------------- Channel open requests

local function connectionOpenChannel(self, channelType, additionalData, successCallback, failureCallback)
    local request = {}
    request.type = channelType
    request.id = self.counter
    request.successCallback = successCallback
    request.failureCallback = failureCallback
    self.channelRequests[request.id] = request

    local packet = self.transport:packet()
    packet:writeByte(SSH_MESSAGE.CHANNEL_OPEN)
    packet:writeString(request.type)
    packet:writeUint32(request.id)
    packet:writeUint32(constants.CHANNEL_SESSION_WINDOW_SIZE)
    packet:writeUint32(constants.CHANNEL_SESSION_PACKET_SIZE)
    
    if additionalData then
        packet:write(additionalData)
    end

    packet:send()
    self.counter = self.counter + 1
end

local function connectionOpenSessionChannel(self, successCallback, failureCallback)
    self:openChannel("session", nil, successCallback, failureCallback)
end

---------------------------------------- Channels

local function channelRequest(self, requestType, additionalData, successCallback, failureCallback)
    local packet = self.connection.transport:packet()
    packet:writeByte(SSH_MESSAGE.CHANNEL_REQUEST)
    packet:writeUint32(self.serverId)
    packet:writeString(requestType)
    packet:writeBoolean(successCallback or failureCallback) -- want_reply

    if additionalData then
        packet:write(additionalData)
    end

    packet:send()

    if self.connection.verbose then
        print("[ssh-connection] Sending " .. requestType .. " request for channel #" .. self.id)
    end

    self.successCallback = successCallback
    self.failureCallback = failureCallback
end

local function channelRequestExec(self, command, successCallback, failureCallback)
    local stream = streamlib.bufferedStream()
    stream:writeString(command)

    self:request("exec", stream.buffer, successCallback, failureCallback)
end

local function channelRequestPty(self, terminalType, cols, rows, width, height, modes, successCallback, failureCallback)
    local stream = streamlib.bufferedStream()
    stream:writeString(terminalType)
    stream:writeUint32(cols)
    stream:writeUint32(rows)
    stream:writeUint32(width)
    stream:writeUint32(height)
    stream:writeString(modes)

    self:request("pty-req", stream.buffer, successCallback, failureCallback)
end

local function channelRequestShell(self, successCallback, failureCallback)
    self:request("shell", nil, successCallback, failureCallback)
end

local function channelSendData(self, data)
    local packet = self.connection.transport:packet()
    packet:writeByte(SSH_MESSAGE.CHANNEL_DATA)
    packet:writeUint32(self.serverId)
    packet:writeString(data)
    packet:send()
end

local function channelSendExtendedData(self, dataType, data)
    local packet = self.connection.transport:packet()
    packet:writeByte(SSH_MESSAGE.CHANNEL_EXTENDED_DATA)
    packet:writeUint32(self.serverId)
    packet:writeUint32(dataType)
    packet:writeString(data)
    packet:send()
end

---------------------------------------- Message handlers

local connectionMessageHandlers = {
    [SSH_MESSAGE.CHANNEL_OPEN_CONFIRMATION] = function(self, stream)
        local channel = {}
        channel.connection = self
        channel.id = stream:readUint32()
        channel.serverId = stream:readUint32()
        channel.windowSize = stream:readUint32()
        channel.packetSize = stream:readUint32()

        channel.request      = channelRequest
        channel.requestExec  = channelRequestExec
        channel.requestPty   = channelRequestPty
        channel.requestShell = channelRequestShell

        channel.sendData = channelSendData
        channel.sendExtendedData = channelSendExtendedData

        local request = assert(self.channelRequests[channel.id], "unknown channel")
        channel.type = request.type

        if self.verbose then
            print(
                ("[ssh-connection] Channel #%d (%s) opened; sender channel id is %d"):format(
                    channel.id, 
                    channel.type, 
                    channel.serverId
                )
            )
        end

        self.channelRequests[request.id] = nil
        self.channels[channel.id] = channel

        request.successCallback(channel)
    end,

    [SSH_MESSAGE.CHANNEL_OPEN_FAILURE] = function(self, stream)
        local request = assert(self.channelRequests[stream:readUint32()], "unknown channel")
        local reasonCode = stream:readUint32()
        local description = stream:readString()

        if self.verbose then
            print(
                ("[ssh-connection] Channel #%d (%s) open failed: %s (%d), %s"):format(
                    request.id,
                    request.type,
                    constants.strOpenFailureCode(reasonCode),
                    reasonCode,
                    description
                )
            )
        end

        self.channelRequests[request.id] = nil

        request.failureCallback(reasonCode, description)
    end,

    [SSH_MESSAGE.CHANNEL_CLOSE] = function(self, stream)
        local channel = self.channels[stream:readUint32()]
        if self.verbose then
            print("[ssh-connection] Channel #" .. channel.id .. " closed by peer")
        end

        if channel.closeHandler then
            channel.closeHandler()
        end

        self.channels[channel.id] = nil
    end,

    [SSH_MESSAGE.CHANNEL_SUCCESS] = function(self, stream)
        local channel = self.channels[stream:readUint32()]

        if self.verbose then
            print("[ssh-connection] Channel #" .. channel.id .. " request succeeded")
        end

        if channel.successCallback then
            channel.successCallback()
            channel.successCallback = nil
        end
    end,

    [SSH_MESSAGE.CHANNEL_FAILURE] = function(self, stream)
        local channel = self.channels[stream:readUint32()]

        if self.verbose then
            print("[ssh-connection] Channel #" .. channel.id .. " request failed")
        end

        if channel.failureCallback then
            channel.failureCallback()
            channel.failureCallback = nil
        end    
    end,

    [SSH_MESSAGE.CHANNEL_DATA] = function(self, stream)
        local channel = self.channels[stream:readUint32()]
        local data = stream:readString()

        if self.verbose then
            print("[ssh-connection] " .. #data .. " bytes of data received for channel #" .. channel.id)
        end

        if channel.dataHandler then
            channel.dataHandler(data)
        end
    end,

    [SSH_MESSAGE.CHANNEL_EXTENDED_DATA] = function(self, stream)
        local channel = self.channels[stream:readUint32()]
        local dataType = stream:readUint32()
        local data = stream:readString()

        if self.verbose then
            print(
                ("[ssh-connection] %d bytes of extended data (%s) received for channel #%d"):format(
                    #data,
                    constants.strExtendedDataCode(dataType),
                    channel.id
                )
            )
        end

        if channel.extendedDataHandler then
            channel.extendedDataHandler(dataType, data)
        end
    end
}

----------------------------------------

function connection.new(transport)
    local self = {}
    self.transport = transport
    self.counter = 0
    self.channelRequests = {}
    self.channels = {}

    self.openChannel = connectionOpenChannel
    self.openSessionChannel = connectionOpenSessionChannel

    self.transport:listen(connectionMessageHandlers, self)

    return self
end

----------------------------------------

return connection