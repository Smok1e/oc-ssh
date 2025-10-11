local constants = require("ssh/constants")

local userauth = {}

local SSH_MESSAGE = constants.SSH_MESSAGE

---------------------------------------- Authentication request

local function userauthRequestService(self, serviceName)
    assert(self.user, "userauth.user is not set")
    assert(self.method, "userauth.method is not set")

    if self.verbose then
        print(
            ("[ssh-userauth] Requesting service %s with %s authentication for user %s"):format(
                serviceName,
                self.method.name,
                self.user
            )
        )
    end

    local packet = self.transport:packet()
    packet:writeByte(SSH_MESSAGE.USERAUTH_REQUEST)
    packet:writeString(self.user)
    packet:writeString(serviceName)
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
    end
}

----------------------------------------

function userauth.new(transport)
    local self = {}
    self.transport = transport

    self.requestService = userauthRequestService

    self.transport:listen(userauthMessageHandlers, self)
    
    return self
end

---------------------------------------- Password-based authentication

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