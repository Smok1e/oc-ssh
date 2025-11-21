local serialization = require("serialization")
local filesystem = require("filesystem")
local constants = require("ssh/constants")
local encoding = require("crypto/encoding")
local sha2 = require("crypto/sha2")
local streamlib = require("ssh/stream")
local keylib = require("ssh/key")

local ssh = {}

----------------------------------------

ssh.CONFIG_DIR = "/home/.ssh"
ssh.KNOWN_HOST_KEY_STORAGE_PATH = filesystem.concat(ssh.CONFIG_DIR, "known_hosts")
ssh.CONFIG_FILE_PATH = filesystem.concat(ssh.CONFIG_DIR, "config")

---------------------------------------- 

local function makeMissingDirectories(path)
    local segments, currPath = filesystem.segments(path), ""
    for i = 1, #segments do
        currPath = filesystem.concat(currPath, segments[i])

        if not filesystem.isDirectory(currPath) then
            if not filesystem.makeDirectory(currPath) then
                error(currPath .. " exists, but is not a directory")
            end
        end
    end
end

---------------------------------------- Known hosts storage

-- Returns canonitial host identifier
function ssh.host(address, port)
    if port == constants.DEFAULT_PORT then
        return address
    else
        return ("[%s]:%d"):format(address, port)
    end
end

-- Returns known host public key if exists
function ssh.findHostKey(keyType, host)
    local file, reason = io.open(ssh.KNOWN_HOST_KEY_STORAGE_PATH, "r")
    if not file then
        return
    end

    for line in file:lines() do
        local entryHost, entryKeyType, entryKeyBlobBase64 = line:match("(.+) (.+) (.+)")
        if not entryHost then
            error("host key storage corrupted")
        end
        
        if entryHost == host and entryKeyType == keyType then
            file:close()

            return keylib.decode(encoding.base64Decode(entryKeyBlobBase64))
        end
    end

    file:close()
end

-- Saves host public key into the local storage
function ssh.saveHostKey(host, key)
    makeMissingDirectories(ssh.CONFIG_DIR)

    local file, reason = io.open(ssh.KNOWN_HOST_KEY_STORAGE_PATH, "a")
    if not file then
        error(ssh.KNOWN_HOST_KEY_STORAGE_PATH .. ": " .. reason)
    end

    file:write(("%s %s %s\n"):format(host, key.type, encoding.base64Encode(keylib.encode(key))))
    file:close()
end

---------------------------------------- Key storage

function ssh.writeKey(path, key)
    makeMissingDirectories(filesystem.path(path))

    local file, reason = io.open(path, "w")
    if not file then
        error(path .. ": " .. reason)
    end

    file:write(("%s %s\n"):format(key.type, encoding.base64Encode(keylib.encode(key))))
    file:close()
end

function ssh.readKey(path)
    local file, reason = io.open(path, "r")
    if not file then
        error(path .. ": " .. reason)
    end

    local keyType, keyBlobBase64 = file:read(math.huge):match("(.+) ([^\n]+)\n?")
    file:close()

    if not keyType then
        return
    end

    local key = keylib.decode(encoding.base64Decode(keyBlobBase64))
    assert(key.type == keyType, "corrupted key file")

    return key
end

-- Reads private key and returns private/public pair
function ssh.readIdentity(path)
    local privateKey = ssh.readKey(path)

    return {
        type = privateKey.type,
        privateKey = privateKey,
        publicKey = keylib.generatePublicKey(privateKey)
    }
end

function ssh.readIdentities()
    if not filesystem.exists(ssh.CONFIG_DIR) then
        return {}
    end

    local identities = {}

    for filename in filesystem.list(ssh.CONFIG_DIR) do
        if filename:match("^id_.+") and not filename:match("%.pub$") then
            table.insert(
                identities, 
                ssh.readIdentity(
                    filesystem.concat(ssh.CONFIG_DIR, filename)
                )
            )
        end
    end

    return identities
end

---------------------------------------- Config

function ssh.readConfig()
    if not filesystem.exists(ssh.CONFIG_FILE_PATH) then
        return {}
    end

    local file, reason = io.open(ssh.CONFIG_FILE_PATH, "r")
    if not file then
        error(ssh.CONFIG_FILE_PATH .. ": " .. reason)
    end

    local result, reason = serialization.unserialize(file:read(math.huge))
    file:close()

    if not result then
        error("invalid config" .. (reason and (": " .. reason) or ""))
    end

    return result
end

function ssh.findHostConfig(host)
    return ssh.readConfig()[host]
end

----------------------------------------

return ssh