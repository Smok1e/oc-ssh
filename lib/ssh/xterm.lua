local component = require("component")
local computer = require("computer")
local unicode = require("unicode")
local term = require("term")

local xterm = {}

----------------------------------------

xterm.STATE = {
    NORMAL = 1,
    SEQUENCE = 2
}

xterm.SEQUENCE = {
    CSI = 1, -- Control sequence intruducer
    OSC = 2, -- Operating system command
    DCS = 3, -- Device control string
    SET = 4, -- G0/G1 select
    CMD = 5  -- Simple single-byte commands,
}

-- Normal colors
xterm.PALETTE_8 = {
    0x0F0F0F, -- Black 
    0x800000, -- Red 
    0x008000, -- Green 
    0x808000, -- Yellow 
    0x000080, -- Blue 
    0x800080, -- Magenta 
    0x008080, -- Cyan
    0xC0C0C0  -- White
}

-- Bright colors
xterm.PALETTE_16 = {
    0x0F0F0F, -- Black
    0xFF0000, -- Red
    0x00FF00, -- Green
    0xFFFF00, -- Yellow
    0x0000FF, -- Blue
    0xFF00FF, -- Magenta
    0x00B6FF, -- Cyan
    0xFFFFFF  -- White
}

xterm.PALETTE_8 = xterm.PALETTE_16

xterm.BG_DEFAULT_INDEX = 1
xterm.FG_DEFAULT_INDEX = 8

----------------------------------------

local function xtermEraseLine(self, arg)
    local x, y = term.getCursor()

    -- Erase to right (default)
    if (arg or 0) == 0 then
        self.gpu.fill(x, y, self.cols - x + 1, 1, " ")

    -- Erase to left
    elseif arg == 1 then
        self.gpu.fill(1, y, x - 1, 1, " ")
       
    -- Erase all
    elseif arg == 2 then
        self.gpu.fill(1, t, self.cols, 1, " ")
    end
end

local function xtermEraseDisplay(self, arg)
    local x, y = term.getCursor()

    -- Erase below (default)
    if (arg or 0) == 0 then
        self.gpu.fill(1, y, self.cols, self.rows - y + 1, " ")
        
    -- Erase above
    elseif arg == 1 then
        self.gpu.fill(1, 1, self.cols, y - 1, " ")

    -- Erase all
    elseif arg == 2 then
        self.gpu.fill(1, 1, self.cols, self.rows, " ")

    -- Erase saved lines
    elseif arg == 3 then
        
    end
end

local function xtermInsertLines(self, arg)
    local x, y = term.getCursor()
    local count = tonumber(arg) or 1

    self.gpu.copy(1, y, self.cols, self.rows - y + 1, 0, count)
    self.gpu.fill(1, y, self.cols, count, " ")
end

local function xtermDeleteLines(self, arg)
    local x, y = term.getCursor()
    local count = tonumber(arg) or 1

    self.gpu.copy(1, y, self.cols, self.rows - y + 1, 0, -count)
    self.gpu.fill(1, self.rows - count, self.cols, count, " ")
end

local function xtermDeleteCharacters(self, arg)
    local x, y = term.getCursor()
    local count = tonumber(arg) or 1
    
    self.gpu.copy(x + count, y, count, 1, -count, 0)
    self.gpu.fill(self.cols - count + 1, y, count, 1, " ")
end

local function xtermEraseCharacters(self, arg)
    local x, y = term.getCursor()
    local count = tonumber(arg) or 1

    self.gpu.fill(x, y, count, 1, " ")
end

local function xtermSetCharacterAttributes(self, arg)
    local function setColors(bg, fg)
        if bg then
            self.gpu.setBackground(bg)
        end

        if fg then
            self.gpu.setForeground(fg)
        end
    end

    local args = {}
    for value in arg:gmatch("([^;]+)") do
        table.insert(args, tonumber(value))
    end

    if #args < 2 then
        local arg1, arg2, arg3 = arg:match("(%d?)(%d?)(%d?)")
        arg1, arg2, arg3 = tonumber(arg1), tonumber(arg2), tonumber(arg3)

        if not arg2 then
            -- Normal (default)
            if (arg1 or 0) == 0 then
                setColors(xterm.PALETTE_8[xterm.BG_DEFAULT_INDEX], xterm.PALETTE_8[xterm.FG_DEFAULT_INDEX])
            end

            -- Modes 1 to 9 (bold, italic, underlined, etc) are ignored
        else
            -- Foreground colors
            if arg1 == 3 then
                if 0 <= arg2 and arg2 <= 7 then
                    setColors(nil, xterm.PALETTE_8[arg2 + 1])
                elseif arg2 == 9 then
                    setColors(nil, xterm.PALETTE_8[xterm.FG_DEFAULT_INDEX])
                end

            -- Background colors
            elseif arg1 == 4 then
                if 0 <= arg2 and arg2 <= 7 then
                    setColors(xterm.PALETTE_8[arg2 + 1], nil)
                elseif arg2 == 9 then
                    setColors(xterm.PALETTE_8[xterm.BG_DEFAULT_INDEX], nil)
                end            

            -- Bright foreground colors
            elseif arg1 == 9 then
                if 0 <= arg2 and arg2 <= 7 then
                    setColors(nil, xterm.PALETTE_16[arg2 + 1])
                elseif arg2 == 9 then
                    setColors(nil, xterm.PALETTE_16[xterm.FG_DEFAULT_INDEX])
                end

            elseif arg1 == 1 and arg2 == 0 then
                if 0 <= arg3 and arg3 <= 7 then
                    setColors(xterm.PALETTE_16[arg2 + 1], nil)
                elseif arg3 == 9 then
                    setColors(xterm.PALETTE_16[xterm.BG_DEFAULT_INDEX], nil)
                end 
            end
        end
    end
end

----------------------------------------

local function xtermProcessSequence(self)
    local x, y = term.getCursor()

    local matches
    local function match(pattern)
        -- Fisrt check last character instead of matching
        if self.sequence:sub(-1, -1) ~= pattern:sub(-1, -1) then
            return
        end

        matches = {self.sequence:match(pattern)}
        return #matches > 0
    end

    if self.sequenceType == xterm.SEQUENCE.CSI then
        -- CSI Ps A - Cursor Up Ps times (CUU)
        if match("%[(%d*)A") then
            term.setCursor(x, y - (tonumber(matches[1]) or 1))

        -- CSI Ps B - Cursor Down Ps times (CUD)
        elseif match("%[(%d*)B") then
            term.setCursor(x, y + (tonumber(matches[1]) or 1))

        -- CSI Ps C - Cursor forward Ps times (CUF)
        elseif match("%[(%d*)C") then
            term.setCursor(x + (tonumber(matches[1]) or 1), y)
            
        -- CSI Ps D - Cursor backward Ps times (CUB)
        elseif match("%[(%d*)D") then
            term.setCursor(x - (tonumber(matches[1]) or 1), y)

        -- CSI Ps E - Cursor next line Ps times (CNL)
        elseif match("%[(%d*)E") then
            term.setCursor(x, y + tonumber(matches[1]) or 1)

        -- CSI Ps F - Cursor preceding line Ps times (CPL)
        elseif match("%[(%d*)F") then
            term.setCursor(x, y - tonumber(matches[1]) or 1)

        -- CSI Ps G - Cursor character absolute (CHA)
        elseif match("%[(%d*)G") then
            term.setCursor(tonumber(matches[1]) or 1, y)

        -- CSI Ps ; Ps H - Set cursor positionя
        elseif match("%[(%d*);?(%d*)H") then
            term.setCursor(tonumber(matches[2]) or 1, tonumber(matches[1]) or 1)

        -- CSI Ps I - Cursor forward tabulation Ps tab stops (CHT)
        elseif match("%[(%d*)I") then
            term.write(("\t"):rep(tonumber(matches[1]) or 1))

        -- CSI Ps J - Erase in Display (ED)
        elseif match("%[(%d*)J") then
            self:eraseDisplay(tonumber(matches[1]))

        -- CSI Ps K - Erase in Line (EL)
        elseif match("%[(%d*)K") then
            self:eraseLine(tonumber(matches[1]))

        -- CSI Ps L - Insert Ps lines (IL)
        elseif match("%[(%d*)L") then
            self:insertLines(matches[1])

        -- CSI Ps M - Delete Ps lines (IL)
        elseif match("%[(%d*)M") then
            self:deleteLines(matches[1])

        -- CSI Ps P - Delete Ps Characters
        elseif match("%[(%d*)P") then
            self:deleteCharacters(matches[1])

        -- CSI Ps X - Erase character (ECH)
        elseif match("%[(%d*)X") then
            self:eraseCharacters(matches[1])

        -- CSI Ps c - Send device attributes (DA)
        elseif match("%[(%d*)c") then
            if self.responseHandler then
                self.responseHandler("\x1B[?1;2;0c")
            end

        -- CSI Pm d - Line position absolute (VPA)
        elseif match("%[(%d*)d") then
            term.setCursor(x, tonumber(matches[1]) or 1)

        -- CSI Pm e - Line position relative (VPR)
        elseif match("%[(%d*)e") then
            term.setCursor(x, y + (tonumber(matches[1]) or 1))

        -- CSI Pm m - Character attributes (SGR)
        elseif match("%[([%d*;]*)m") then
            self:setCharacterAttributes(matches[1])

        elseif match("%[(%d*);(%d*)f") then
            term.setCursor(tonumber(matches[2]) or 1, tonumber(matches[1]) or 1)

        end
    else
        -- component.ocelot.log("Escape sequence: " .. self.sequence .. " (" .. self.sequenceType .. ")")
    end

    self.sequence = nil
    self.sequenceType = nil
    self.state = xterm.STATE.NORMAL
end

local function xtermWrite(self, data)
    for i = 1, unicode.len(data) do
        local char = unicode.sub(data, i, i)
        local byte = char:byte()

        if self.state == xterm.STATE.SEQUENCE then
            self.sequence = self.sequence .. char

            if not self.sequenceType then
                if char == "[" then
                    self.sequenceType = xterm.SEQUENCE.CSI
                elseif char == "]" then
                    self.sequenceType = xterm.SEQUENCE.OSC
                elseif char == "P" then
                    self.sequenceType = xterm.SEQUENCE.DCS
                elseif char:match("[%(%)%*%+%-%.%/]") then
                    self.sequenceType = xterm.SEQUENCE.SET
                else
                    self.sequenceType = xterm.SEQUENCE.CMD
                    self:processSequence()
                end
            else
                if self.sequenceType == xterm.SEQUENCE.CSI then
                    -- '@'-'~'
                    if 0x40 <= byte and byte <= 0x7E then
                        self:processSequence()
                    end
                elseif self.sequenceType == xterm.SEQUENCE.OSC then
                    -- BEL or ESC \
                    if byte == 0x07 or self.sequence:sub(-2, -1) == "\x1B\\" then
                        self:processSequence()
                    end
                elseif self.sequenceType == xterm.SEQUENCE.DCS then
                    -- ESC \
                    if self.sequence:sub(-2, -1) == "\x1B\\" then
                        self:processSequence()
                    end
                elseif self.sequenceType == xterm.SEQUENCE.SET then
                    self:processSequence()
                end
            end
        else
            -- Escape sequence
            if byte == 0x1B then
                self.state = xterm.STATE.SEQUENCE
                self.sequence = ""

            -- I hate bells
            elseif byte ~= 0x07 then
                term.write(char)
            end
        end
    end
end

----------------------------------------

function xterm.new()
    local self = {}

    self.gpu = term.gpu()
    self.state = xterm.STATE.NORMAL

    self.cols, self.rows = self.gpu.getResolution()
    self.width, self.height = 8 * self.cols, 16 * self.rows

    self.eraseLine        = xtermEraseLine
    self.eraseDisplay     = xtermEraseDisplay
    self.insertLines      = xtermInsertLines
    self.deleteLines      = xtermDeleteLines
    self.deleteCharacters = xtermDeleteCharacters
    self.eraseCharacters  = xtermEraseCharacters
    self.setCharacterAttributes = xtermSetCharacterAttributes

    self.processSequence = xtermProcessSequence
    self.write = xtermWrite

    return self
end

----------------------------------------

return xterm