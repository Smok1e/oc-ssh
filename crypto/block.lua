local array = require("crypto/array")

local lib = {}

---------------------------------------- ECB

--                           Electronic codebook (ECB) encryption
--
--                  Plaintext                            Plaintext            
--                      |                                    |                
--                      v                                    v                
--         +-------------------------+          +-------------------------+ 
--  Key -> | Block cipher encryption |   Key -> | Block cipher encryption |  ...
--         +-------------------------+          +-------------------------+ 
--                      |                                    |                
--                      v                                    v                
--                  Ciphertext                           Ciphertext           

function lib.ECBEncrypt(encryptCallback, plaintext, blockSize)
    local cipher = ""

    for i = 1, #plaintext // blockSize do
        cipher = cipher .. encryptCallback(plaintext:sub((i - 1) * blockSize + 1, i * blockSize))
    end

    return cipher
end

--                            Electronic codebook (ECB) decryption
--
--                  Ciphertext                           Ciphertext            
--                      |                                    |                
--                      v                                    v                
--         +-------------------------+          +-------------------------+ 
--  Key -> | Block cipher decryption |   Key -> | Block cipher decryption |  ...
--         +-------------------------+          +-------------------------+ 
--                      |                                    |                
--                      v                                    v                
--                  Plaintext                            Plaintext           

function lib.ECBDecrypt(decryptCallback, cipher, blockSize)
    local plaintext = ""

    for i = 1, #cipher // blockSize do
        plaintext = plaintext .. decryptCallback(cipher:sub((i - 1) * blockSize + 1, i * blockSize))
    end

    return plaintext
end

---------------------------------------- CBC

--                         Cipher block chaining (CBC) encryption
--
--                  Plaintext                              Plaintext            
--                      |                                      |                
--  IV --------------->XOR              +-------------------->XOR
--                      |               |                      |
--                      v               |                      v                
--         +-------------------------+  |         +-------------------------+ 
--  Key -> | Block cipher encryption |  |  Key -> | Block cipher encryption |  ...
--         +-------------------------+  |         +-------------------------+ 
--                      |               |                      |
--                      +---------------+                      |
--                      |                                      |
--                      v                                      v                
--                  Ciphertext                             Ciphertext           

function lib.CBCEncrypt(initializationVector, encryptCallback, plaintext, blockSize)
    local prevBlock, cipher = initializationVector, ""

    for i = 1, #plaintext // blockSize do
        prevBlock = encryptCallback(
            array.toBytes(
                array.xor(
                    array.fromBytes(plaintext:sub((i - 1) * blockSize + 1, i * blockSize)), 
                    array.fromBytes(prevBlock)
                )
            )
        )
        
        cipher = cipher .. prevBlock
    end

    return cipher
end

--                         Cipher block chaining (CBC) decryption
--
--                  Plaintext                              Plaintext            
--                      |                                      |                
--                      +---------------+                      |
--                      |               |                      |
--                      v               |                      v                
--         +-------------------------+  |         +-------------------------+ 
--  Key -> | Block cipher encryption |  |  Key -> | Block cipher encryption |  ...
--         +-------------------------+  |         +-------------------------+ 
--                      |               |                      |
--  IV --------------->XOR              +-------------------->XOR
--                      |                                      |
--                      v                                      v                
--                  Ciphertext                             Ciphertext           

function lib.CBCDecrypt(initializationVector, decryptCallback, cipher, blockSize)
    local plaintext, prevBlock = "", initializationVector

    for i = 1, #cipher // blockSize do
        local currBlock = cipher:sub((i - 1) * blockSize + 1, i * blockSize)
        
        plaintext = plaintext .. array.toBytes(
            array.xor(
                array.fromBytes(decryptCallback(currBlock)), 
                array.fromBytes(prevBlock)
            )
        )

        prevBlock = currBlock
    end

    return plaintext
end

---------------------------------------- CTR

--                           Counter (CTR) mode encryption
-- 
--                [Nonce+Counter]                      [Nonce+Counter]     
--                      |                                    |             
--                      v                                    v             
--         +-------------------------+          +-------------------------+
--  Key -> | Block cipher encryption |   Key -> | Block cipher encryption | ...
--         +-------------------------+          +-------------------------+
--                      |                                    |             
--  Plaintext -------->XOR               Plaintext -------->XOR            
--                      |                                    |             
--                      v                                    v             
--                  Ciphertext                           Ciphertext        
-- 
-- Combination method of the nonce (IV) and the counter seems not to be strictly defined
-- by the standard, and often IV just gets concateneted with the counter. However, 
-- openssl seems to be using an IV as a counter and increment it during the block
-- cipher. This implementation does basically the same.
--
-- CTR mode turns block cipher into a stream cipher. Instead of encrypting plaintext
-- divided by identically sized blocks, it encrypts some sort of combination of IV
-- and a counter, which was mentioned above. This produces a number of encrypted blocks,
-- which are then XORed with the plaintext. However, this does not require the length
-- of the plaintext to be multiple of block sizes. The rest of the last block produced
-- by the cipher can be simply discarded.

function lib.CTREncrypt(initializationVector, encryptCallback, plaintext, blockSize)
    local cipher, counter, block = "", initializationVector

    for i = 0, #plaintext - 1 do
        if i % blockSize == 0 then
            block = encryptCallback(counter)

            counter = array.toBytes(
                array.incrementCounter(
                    array.fromBytes(counter)
                )
            )
        end

        cipher = cipher .. string.char(plaintext:byte(i + 1) ~ block:byte(i % blockSize + 1))
    end

    return cipher
end

--                           Counter (CTR) mode decryption
-- 
--                 [IV+Counter]                         [IV+Counter]     
--                      |                                    |             
--                      v                                    v             
--         +-------------------------+          +-------------------------+
--  Key -> | Block cipher ENCRYPTION |   Key -> | Block cipher ENCRYPTION | ...
--         +-------------------------+          +-------------------------+
--                      |                                    |             
--  Ciphertext ------->XOR              Ciphertext -------->XOR            
--                      |                                    |             
--                      v                                    v             
--                  Plaintext                            Plaintext       

-- As we can see, the decryption process is roughly the same as the encryption

function lib.CTRDecrypt(initializationVector, encryptCallback, cipher, blockSize)
    return lib.CTREncrypt(initializationVector, encryptCallback, cipher, blockSize)
end

----------------------------------------

return lib