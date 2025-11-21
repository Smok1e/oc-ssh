local lib = {}

----------------------------------------

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

function lib.new(initializationVector, encryptCallback, blockSize)
    local counter = {initializationVector:byte(1, blockSize)}
    local offset = 0
    local block
    
    return function(plaintext)
        local cipher = {}
        local plaintext = {plaintext:byte(1, -1)}

        for i = 1, #plaintext do
            if offset == 0 then
                -- Generate next block
                block = {
                    encryptCallback(
                        string.char(
                            table.unpack(counter)
                        )
                    ):byte(1, -1)
                }

                -- Increment counter
                local carry = 1
                for j = #counter, 1, -1 do
                    local sum = counter[j] + carry
                    counter[j] = sum % 0x100
                    carry = sum >> 8
                end
            end

            cipher[i] = string.char(plaintext[i] ~ block[offset + 1])
            offset = (offset + 1) % blockSize
        end

        return table.concat(cipher)
    end
end

----------------------------------------

return lib