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
                component.ocelot.log("normal")
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
    local matches
    local function match(pattern)
        matches = {self.sequence:match(pattern)}
        return #matches > 0
    end

    local x, y = term.getCursor()
    if self.sequenceType == xterm.SEQUENCE.CSI then
        -- CSI Pm m - Character attributes (SGR)
        if match("%[([%d;]*)m") then
            self:setCharacterAttributes(matches[1])

        -- CSI Ps K - Erase in Line (EL)
        elseif match("%[(%d?)K") then
            self:eraseLine(tonumber(matches[1]))

        -- CSI Ps ; Ps H - Set cursor position
        elseif match("%[(%d*);?(%d*)H") then
            term.setCursor(tonumber(matches[1]) or 1, tonumber(matches[2]) or 1)

        -- CSI Ps J - Erase in Display (ED)
        elseif match("%[(%d?)J") then
            self:eraseDisplay(tonumber(matches[1]))

        -- CSI Ps G - Cursor character absolute (CHA) (default = 1)
        elseif match("%[(%d*)G") then
            term.setCursor(tonumber(matches[1]) or 1, y)

        -- CSI Ps A - Cursor Up Ps times (default = 1)
        elseif match("%[(%d*)A") then
            term.setCursor(x, y + (tonumber(matches[1]) or 1))

        -- CSI Ps C - Cursor forward Ps times (default = 1)
        elseif match("%[(%d*)C") then
            term.setCursor(x + (tonumber(matches[1]) or 1), y)

        else
            component.ocelot.log("Escape sequence: " .. self.sequence .. " (" .. self.sequenceType .. ")")
        end
    else
        component.ocelot.log("Escape sequence: " .. self.sequence .. " (" .. self.sequenceType .. ")")
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
            else
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

    self.eraseLine = xtermEraseLine
    self.eraseDisplay = xtermEraseDisplay
    self.setCharacterAttributes = xtermSetCharacterAttributes

    self.processSequence = xtermProcessSequence
    self.write = xtermWrite

    return self
end

----------------------------------------

return xterm