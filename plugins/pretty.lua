-- Please include 00commands.lua for script to work!!
irc.logStyled("pretty.lua loaded","magenta","bold")
local myNick="EnterYourNickname"
local nickColors={"cyan","green","yellow","magenta","white"}
local function hashNick(nick)
local h=0
nick=nick or ""
for i=1,#nick do h=(h*31+string.byte(nick,i))%2147483647 end
    return h
    end
    local function nickColor(nick)
    if nick==nil or nick=="" then return "white" end
        return nickColors[(hashNick(nick)%#nickColors)+1]
        end
        local function contains(haystack,needle)
        haystack=string.lower(haystack or "")
        needle=string.lower(needle or "")
        if needle=="" then return false end
            return string.find(haystack,needle,1,true)~=nil
            end
            function styleMessage(from,target,text,raw)
            return {
                brackets={color="white",dim=true},
                nick={color=nickColor(from),bold=true},
                body={color="white"}
            }
            end
            function styleLine(event,from,target,text,raw)
            from=from or ""
            text=text or ""
            if event=="message" and from==myNick then return {color="white",bold=true} end
                if event=="message" and contains(text,myNick) then return {color="yellow",bold=true} end
                    if event=="message" then return {color=nickColor(from)} end
                        if event=="notice" then return {color="yellow",dim=true} end
                            if event=="join" then return {color="green",bold=true} end
                                if event=="part" then return {color="yellow",dim=true} end
                                    if event=="quit" then return {color="red",bold=true} end
                                        if event=="ctcp" then return {color="magenta",bold=true} end
                                            if event=="names" or event=="endnames" then return {color="cyan",dim=true} end
                                                if event=="welcome" then return {color="green",bold=true} end
                                                    return {color="white",dim=true}
                                                    end
                                                    registerCommandHandler(function(command,args,channel)
                                                    command=string.lower(command or "")
                                                    args=args or ""
                                                    if command=="pretty" then
                                                        irc.logStyled("Pretty style hook is active.","cyan","bold")
                                                        return true
                                                        end
                                                        if command=="luaecho" then
                                                            irc.privmsg(channel,args)
                                                            return true
                                                            end
                                                            return false
                                                            end)
