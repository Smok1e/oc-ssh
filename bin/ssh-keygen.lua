local shell = require("shell")
local filesystem = require("filesystem")
local curve25519 = require("crypto/curve25519")
local keylib = require("ssh/key")
local ssh = require("ssh")

local args, options = shell.parse(...)

----------------------------------------

local function info(...)
    if options.q or options.quiet then
        return
    end

    print(...)
end

local function usage()
    info("Usage: ssh-keygen [OPTIONS] - Generate ed25519 keypair")
    info("Available options:")
    info("  -h, --help:        Print usage information and exit")
    info("  -q, --quiet:       Do not print output")
    info("      --path=<path>: Override key path")
end

if options.h or options.help then
    usage()
    return
end

local privateKeyPath = options.path or filesystem.concat(ssh.CONFIG_DIR, "id_ed25519")
local publicKeyPath = privateKeyPath .. ".pub"

local privateKeyData, publicKeyData = curve25519.ed25519.generateKeypair()

local privateKey = keylib.new("ssh-ed25519", privateKeyData)
local publicKey = keylib.new("ssh-ed25519", publicKeyData)

ssh.writeIdentity(privateKeyPath, privateKey)
info("Your private key saved to " .. privateKeyPath)

ssh.writeIdentity(publicKeyPath, publicKey)
info("Your public key saved to " .. publicKeyPath)
info("The key fingerprint is " .. keylib.fingerprint(publicKey))

----------------------------------------