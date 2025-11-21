local filesystem = require("filesystem")
local component = require("component")
local computer = require("computer")
local event = require("event")
local term = require("term")
local shell = require("shell")

local sha2 = require("crypto/sha2")
local encoding = require("crypto/encoding")
local curve25519 = require("crypto/curve25519")

local sshlib = require("ssh")
local utils = require("ssh/utils")
local transportlib = require("ssh/transport")
local userauthlib = require("ssh/userauth")
local connectionlib = require("ssh/connection")
local keylib = require("ssh/key")
local streamlib = require("ssh/stream")
local constants = require("ssh/constants")
local xterm = require("ssh/xterm")

local args, options = shell.parse(...)

---------------------------------------- Connection

local function connect(address, port, timeout)
    local socket, reason = component.internet.connect(address, port)
    if not socket then
        error(reason)
    end

    local connectionStartTime = computer.uptime()
    while not socket.finishConnect() do
        if event.pull(0) == "interrupted" then
            error("connection interrupted")
        end

        if computer.uptime() - connectionStartTime > timeout then
            error("connection timed out")
        end
    end

    return socket
end

local function recv(socket)
    local chunks = {}
    while true do
        local chunk, reason = socket.read()
        if not chunk or #chunk == 0 then
            if reason then
                error(reason)
            end

            break
        end

        table.insert(chunks, chunk)
    end

    return table.concat(chunks)
end

---------------------------------------- Host validation

local function validateHostKey(address, port, key)
    local host = sshlib.host(address, port)
    local known = sshlib.findHostKey(key.type, host)
    
    if not known then
        term.write(
            (
                "The host %s is not known.\n" .. 
                "%s key fingerprint is %s.\n" ..
                "Are you sure you want to continue connecting? [Y/n] "
            ):format(
                address, 
                key.type,
                keylib.fingerprint(key)
            )
        )

        if not (term.read() or "n"):lower():match("y.+") then
            return false
        end

        sshlib.saveHostKey(host, key)
        print("Permanently added " .. address .. " (" .. key.type .. ") to the list of known hosts.")

        return true
    end

    if keylib.encode(known) ~= keylib.encode(key) then
        print("\x1B[31mWARNING!\x1B[0m Server host key does not match previously known entry!")
        return false
    end

    return true
end

local function parseDestination(destination)
    local user, address = destination:match("^(.+)@(.+)$")
    if not user then
        return destination
    end

    return address, user
end

---------------------------------------- SSH client

local function sshEventHandler(self, eventType, ...)
    if eventType == "interrupted" then
        if not self.shellStarted then
            self.running = false
        end

    elseif eventType == "internet_ready" then
        self.transport:receive(recv(self.socket))

    elseif eventType == "key_down" then
        if not self.shellStarted then
            return
        end

        local _, byte, key = ...
        
        if byte == 0 then
            if     key == 200 then -- Arrow up
                self.channel:sendData("\x1B[A")
            elseif key == 208 then -- Arrow down
                self.channel:sendData("\x1B[B")
            elseif key == 205 then -- Arrow right
                self.channel:sendData("\x1B[C")
            elseif key == 203 then -- Arrow left
                self.channel:sendData("\x1B[D")
            end
        else
            self.channel:sendData(utf8.char(byte))
        end
    elseif eventType == "clipboard" then
        local _, data = ...
        self.channel:sendData(data)
    end
end

local function sshPrompt(self, message, pwchar)
    term.write(message)

    local response = term.read {pwchar = pwchar}
    if not response then
        self.transport:disconnect(
            constants.SSH_DISCONNECT.AUTH_CANCELLED_BY_USER,
            "aborted"
        )

        self.running = false
        return
    end

    if pwchar then
        term.write("\n")
    end

    return response:sub(1, -2)    
end

----------------------------------------

local function sshOnDisconnected(self, reasonCode, description)
    print("Disconnected: " .. description)
    self.running = false
end

local function sshOnTransportReady(self)
    self.transport:requestService(
        "ssh-userauth",
        function()
            self:onUserauthAccepted()
        end
    )
end

local function sshOnUserauthAccepted(self)
    if not self.user then
        self.user = self:prompt("user: ")

        if not self.user then
            self.running = false
            return
        end
    end

    self.userauth = userauthlib.new(self.transport)
    self.userauth.user = self.user
    self.userauth.verbose = self.verbose

    local identities = self.identities or sshlib.readIdentities()
    local function requestConnection()
        if #identities > 0 then
            local identity = table.remove(identities, 1)

            if identity.type == "ssh-ed25519" then
                self.userauth.method = userauthlib.publicKey(
                    identity.publicKey,
                    function(message)
                        return keylib.sign(identity.privateKey, message)
                    end
                )

                self.userauth:requestConnection()
            else
                requestConnection()
            end
        else
            local pass = self:prompt(self.user .. "@" .. self.address .. "'s password: ", "*")
            if not pass then
                self.running = false
                return
            end

            self.userauth.method = userauthlib.password(pass)
            self.userauth:requestConnection()
        end
    end    

    self.userauth.bannerHandler = function(banner)
        print(banner)
    end

    self.userauth.failureHandler = function()
        print("Authentication failed; please try again")
        requestConnection()
    end

    self.userauth.successHandler = function()
        self:onConnectionAccepted()
    end

    requestConnection()
end

local function sshOnConnectionAccepted(self)
    self.connection = connectionlib.new(self.transport)
    self.connection.verbose = self.verbose

    self.connection:openSessionChannel(
        function(channel)
            self:onSessionChannelOpened(channel)
        end,

        function()
            print("Session open failure")
            self.running = false
        end
    )
end

local function sshOnUserauthBanner(self, banner)
    print(banner)
end

local function sshOnSessionChannelOpened(self, channel)
    self.verbose = false
    self.transport.verbose = false
    self.connection.verbose = false
    self.userauth.verbose = false

    self.channel = channel
    self.xterm = xterm.new()

    self.xterm.responseHandler = function(data)
        self.channel:sendData(data)
    end

    channel.dataHandler = function(data)
        self.xterm:write(data)
    end

    channel.extendedDataHandler = function(code, data)
        self.xterm:write(data)
    end

    channel.closeHandler = function()
        self.running = false
    end

    if self.command then
        channel:requestExec(self.command)
    else
        channel:requestPty(
            "xterm-256color", 
            self.xterm.cols, 
            self.xterm.rows, 
            self.xterm.width, 
            self.xterm.height, 
            ""
        )

        channel:requestShell(
            function()
                self.shellStarted = true
            end,
            
            function()
                print("Shell request rejected")
                self.running = false
            end
        )
    end
end

----------------------------------------

local function sshInit(self)
    self.socket = connect(self.address, self.port, 3)
    
    self.transport = transportlib.new(self.socket.write, "SSH-2.0-Pizda_1.0")
    self.transport.verbose = self.verbose

    self.transport.hostKeyHandler = function(key)
        return validateHostKey(self.address, self.port, key)
    end
    
    self.transport:onReady(
        function()
            self:onTransportReady()
        end
    )

    self.transport.disconnectHandler = function(...)
        self:onDisconnected(...)
    end

    self.running = true
end

local function sshLoop(self)
    while self.running do
        if self.shellStarted then
            self:eventHandler(term.pull())
        else
            self:eventHandler(event.pull())
        end
    end
end

----------------------------------------

local function sshNew()
    local self = {}

    self.eventHandler = sshEventHandler
    self.prompt = sshPrompt

    self.onDisconnected         = sshOnDisconnected
    self.onTransportReady       = sshOnTransportReady
    self.onUserauthAccepted     = sshOnUserauthAccepted
    self.onUserauthBanner       = sshOnUserauthBanner
    self.onConnectionAccepted   = sshOnConnectionAccepted
    self.onSessionChannelOpened = sshOnSessionChannelOpened
    self.onShellStarted         = sshOnShellStarted

    self.loop = sshLoop
    self.init = sshInit

    return self
end

----------------------------------------

local function usage()
    print("Usage: ssh [OPTIONS] destination [COMMAND]")
    print("Available options:")
    print("  -h, --help:        Print usage information and exit")
    print("  -v, --verbose:     Enable debug logging")
    print("      --port=<port>: Override port")
end

if #args < 1 or options.h or options.help then
    usage()
    return
end

local ssh = sshNew(address, port, user, verbose)

-- Search for existing config
local destination = args[1]
local config = sshlib.findHostConfig(destination)
if config then
    if not config.address then
        error("invalid config for entry '" .. destination .. "': no address found")
    end

    ssh.address = config.address
    ssh.user = config.user
    ssh.port = config.port

    if config.identity then
        ssh.identities = {sshlib.readIdentity(config.identity)}
    end
else
    ssh.address, ssh.user = parseDestination(args[1])
end

ssh.port = tonumber(options.port) or ssh.port or constants.DEFAULT_PORT
ssh.verbose = options.v or options.verbose
ssh.command = args[2]

ssh:init()
ssh:loop()

----------------------------------------