local component = require("component")
local computer = require("computer")
local shell = require("shell")
local fs = require("filesystem")
local term = require("term")

local internet = component.internet

local args, options = shell.parse(...)

local CONNECTION_TIMEOUT = 5
local REPO = "https://raw.githubusercontent.com/Smok1e/oc-ssh/" .. (options.branch or "master") .. "/"

local DIRECTORIES = {
    "/usr",
    "/usr/lib",
    "/usr/lib/ssh",
    "/usr/lib/crypto",
    "/usr/bin"
}

local FILES = {
    "lib/crypto/encoding.lua",
    "lib/crypto/padding.lua",
    "lib/crypto/array.lua",
    "lib/crypto/aes.lua",
    "lib/crypto/ctr.lua",
    "lib/crypto/sha2.lua",
    "lib/crypto/hmac.lua",
    "lib/crypto/curve25519.lua",

    "lib/ssh/constants.lua",
    "lib/ssh/transport.lua",
    "lib/ssh/userauth.lua",
    "lib/ssh/connection.lua",
    "lib/ssh/stream.lua",
    "lib/ssh/utils.lua",
    "lib/ssh/xterm.lua",
    "lib/ssh/key.lua",
    "lib/ssh.lua",

    "bin/ssh.lua",
    "bin/ssh-keygen.lua"
}

local PROGRESS_WIDTH = 50

-------------------------------------------

-- Downloads whole file
local function download(url)
    checkArg(1, url, "string")

    local request = internet.request(url)
    local connectionStartTime = computer.uptime()

    local success, reason
    while not success do
        success, reason = request.finishConnect()
        
        if success == nil then
            error("unable to download " .. url)
        end

        if computer.uptime() - connectionStartTime > CONNECTION_TIMEOUT then
            error("connection timed out")
        end
    end

    local data, chunk = ""
    repeat
        chunk = request.read(math.huge)
        data = data ..(chunk or "")
    until not chunk
    request.close()

    return data
end

local function install()
    local function status(format, ...)
        if options.q or options.quiet then
            return
        end

        io.stdout:write(format:format(...))
    end

    local function progress(value)
        local width = math.ceil(PROGRESS_WIDTH * value)

        status(
            "%3.0f%% [%s>%s]\r",
            100 * value,
            ("="):rep(width > 0 and (width - 1) or 0),
            (" "):rep(PROGRESS_WIDTH - width)
        )
    end

    status("Starting installer...\n")

    -- Creating necessary directories
    for _, dir in pairs(DIRECTORIES) do
        status("Creating directory %s\n", dir)

        if not fs.isDirectory(dir) then
            if fs.exists(dir) then
                io.stderr:write("Failed to create directory '" .. dir .. "', because it is an existing file. Delete this file and retry the installation\n")
                os.exit()
            end

            fs.makeDirectory(dir)
        end
    end

    -- Downloading files
    for index, path in pairs(FILES) do
        local url = REPO .. path

        status("Downloading %s...\n", url)
        progress((index - 1) / (#FILES - 1))

        local data, reason = download(url)
        if not data then
            error(reason)
        end

        local file, reason = fs.open("/usr/" .. path, 'wb')
        if not file then
            error(reason)
        end

        file:write(data)
        file:close()        
    end

    term.clearLine()
    status("ssh has been installed succesfully!\n")
end

local function help()
    print("Usage: get-ssh [OPTIONS]")
    print("Options:")
    print("  -h --help: Print usage and exit")
    print("  -q --quiet: Print only errors")
    print("     --branch=branch: Specify repository branch")
end

if options.h or options.help then
    help()
else
    install()
end

-------------------------------------------