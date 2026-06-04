-- Important!
commandHandlers=commandHandlers or {}
function registerCommandHandler(fn)
    if type(fn)=="function" then table.insert(commandHandlers,fn) end
end
function onCommand(command,args,channel)
    command=string.lower(command or "")
    args=args or ""
    for _,fn in ipairs(commandHandlers) do
        if fn(command,args,channel) then return true end
    end
    return false
end
