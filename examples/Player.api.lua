---@meta

-- Fictional API definition for editor tooling only.
-- Do not load this file into the game runtime.
-- A real exporter must use evidence-backed names and signatures.

---@class ExamplePlayer
---@field Id string
local ExamplePlayer = {}

---Returns the display name in this fictional API.
---@return string
function ExamplePlayer:GetDisplayName() end

---Represents a discovered callable whose signature is still unknown.
---@param ... any
---@return any ...
function ExamplePlayer.UnknownOperation(...) end

return ExamplePlayer
