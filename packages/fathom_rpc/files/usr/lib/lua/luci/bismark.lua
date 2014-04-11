--[[
LuCI - Lua Configuration Interface

Copyright 2008 Steven Barth <steven@midlink.org>
Copyright 2008 Jo-Philipp Wich <xm@leipzig.freifunk.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

]]--

--[[
bismark.active module for fathom rpc
Authors: saru sgrover@gatech.edu
         akp  anna-kaisa.pietilainen@inria.fr
]]--

local io     = require "io"
local os     = require "os"
local table  = require "table"
local nixio  = require "nixio"
local fs     = require "nixio.fs"
local uci    = require "luci.model.uci"
local string = require "string"
--local json = require("dkjson")

local luci   = {}
luci.util    = require "luci.util"
luci.ip      = require "luci.ip"
luci.sys     = require "luci.sys"

local tonumber, ipairs, pairs, pcall, type, next, setmetatable, require, select =
        tonumber, ipairs, pairs, pcall, type, next, setmetatable, require, select

--- RPC module
module "luci.bismark"
-- method namespace
active = {}

--- Execute a given shell command and return the error code
-- @class               function
-- @name                call
-- @param               ...             Command to call
-- @return              Error code of the command
function call(...)
   return os.execute(...) / 256
end

--- Execute a given shell command and capture its standard output
-- @class               function
-- @name                exec
-- @param command       Command to call
-- @return                      String containg the return the output of the command
exec = luci.util.exec

-- common return format for raw or formatted responses
function formatres(data, cmd)
--   return "{hostname:" .. luci.sys.hostname() .. ",ts:" .. os.time()*1000 .. ",data:" .. data .. ",cmd=" .. cmd .. "}"
   local res = {}
   res.data = data
   res.cmd = cmd
   res.hostname = luci.sys.hostname()
   res.ts = os.time() -- in sec
   return res
end

--[[
    SIMPLE COMMANDS: ping, alive, arp, ip
]]--

function active.heartbeat(ts)
   local res = "{tsecho:" .. ts .. ",ts:" .. os.time()*1000 .. "}"
   return formatres(res,"os.time")
end

function active.ping(host, count)
   if not host then
      return nil, {code=-32602, message="Missing destination"}
   else
      local cmd = "ping".. check_param(count, "-c") .. "'"..host:gsub("'", '').."'"
      local rawdata = luci.util.exec(cmd)
      return formatres(rawdata,cmd)
   end
end

--function active.fping(host, count, interval)
function active.fping(host, opt)
   if not host then
      return nil, {code=-32602, message="Missing destination"}
   else
      local cmd = "fping" .. check_param(opt.count, "-C") .. check_param(opt.interval, "-p") .. "'"..host:gsub("'", '').."'"
      local rawdata = luci.util.exec(cmd)
      return formatres(rawdata,cmd)
   end
end

-- return 0 if successful (alive) else 256/256 = 1
function active.alive(host)
   if not host then
      return nil, {code=-32602, message="Missing destination"}
   else
      local cmd = "ping -c1 -W1 '"..host:gsub("'", '').."' >/dev/null 2>&1"
      local rawdata = os.execute(cmd) / 256
      return formatres(rawdata,cmd)
   end
end

function active.ipneigh()
   local cmd = "ip neigh"
   return formatres(luci.util.exec(cmd),cmd)
end
function active.iplink()
   local cmd = "ip -o -s link"
   return formatres(luci.util.exec(cmd),cmd)
end
function active.ipaddr()
   local cmd = "ip -o addr"
   return formatres(luci.util.exec(cmd),cmd)
end

-- deprc
-- from net.arptable in sys.lua
function active.arptable(callback)
    local arp, e, r, v
    if fs.access("/proc/net/arp") then
        for e in io.lines("/proc/net/arp") do
            local r = { }, v
            for v in e:gmatch("%S+") do
                r[#r+1] = v
            end
            if r[1] ~= "IP" then
                local x = {
                    ["IP address"] = r[1],
                    ["HW type"]    = r[2],
                    ["Flags"]      = r[3],
                    ["HW address"] = r[4],
                    ["Mask"]       = r[5],
                    ["Device"]     = r[6],
                    ["Alive"]      = active.alive(r[1]),    -- ping device
                    ["Interface"]  = active.interface(r[4]) -- get state eth or wlan
                }

                if callback then
                    callback(x)
                else
                    arp = arp or { }
                    arp[#arp+1] = x
                end
            end
        end
    end
    return arp
end

--[[
    TRACEROUTES
]]--

function active.paristraceroute(ip_addr, count, proto)
   if not ip_addr then
      return nil, {code=-32600, message="Missing destination"}
   else
      local cmd = "paris-traceroute " .. check_param(count, "-q") .. check_param(proto, "-p") .. ip_addr
      local ret = luci.util.exec(cmd)
      return formatres(ret,cmd)
   end
end

function active.mtr(ip_addr, options)
   if not ip_addr then
      return nil, {code=-32600, message="Missing destination"}
   else      
      local options = " --raw" .. check_param(options.count, "-c") .. check_param(options.size, "-s") .. check_param(options.interval, "-i")
      if (proto == 'udp') then
	 options = options .. " -u "
      end
      local cmd = "mtr"..options..ip_addr
      local ret = luci.util.exec(cmd)
      return formatres(ret,cmd)
   end
end


--[[
    WIRELESS INFO
]]--

-- wireless devices
function active.iwdev()
   local cmd = "iw dev"
   return formatres(luci.util.exec(cmd),cmd)
end

-- channel surveys
function active.iwsurveydump()
    local survey_dump = ""
    
    local wireless_dev = luci.util.exec("iw dev | grep 'Interface'")
    for _,lines in pairs(wireless_dev:split("\n")) do
        for intfce in lines:gmatch('Interface%s*(%a.*)') do
            survey_dump = survey_dump .. "\n".. luci.util.exec("iw dev "..intfce.." survey dump")
        end
    end
    
    return formatres(survey_dump,"iw dev <dev> survey dump")
end

-- ap scan
function active.iwscan()
    local res = ""
    
    local wireless_dev = luci.util.exec("iw dev | grep 'Interface'")
    for _,lines in pairs(wireless_dev:split("\n")) do
        for intfce in lines:gmatch('Interface%s*(%a.*)') do
            res = res .. "\n".. luci.util.exec("iw dev "..intfce.." scan")
        end
    end
    
    return formatres(res,"iw dev <dev> scan")
end

-- associated clients
function active.iwstationdump()
    local station_dump = ""
    
    local wireless_dev = luci.util.exec("iw dev | grep 'Interface'")
    for _,lines in pairs(wireless_dev:split("\n")) do
        for intfce in lines:gmatch('Interface%s*(%a.*)') do
            station_dump = station_dump .. "\n".. luci.util.exec("iw dev "..intfce.." station dump")
        end
    end
    
    return formatres(station_dump,"iw dev <dev> station dump")
end

-- deprc ?
function active._wireless_interface()
    local wireless_dev = luci.util.exec("iw dev | grep 'Interface'")
    
    local Interface = { }
    local w = { }
    local i = 0
    
    for _,lines in pairs(wireless_dev:split("\n")) do
        for intfce in lines:gmatch('Interface%s*(%a.*)') do
            w[i] = luci.util.exec("iw dev "..intfce.." station dump | grep 'Station'" )
            for _,line in pairs(w[i]:split("\n")) do
                Interface[line:split(" ")[2]] = intfce
            end
            i = i+1
        end
    end
    return Interface
end

-- deprc ?
function active.interface(dev)
    
    local Interface = active._wireless_interface()
    
    if Interface[dev] then
        return Interface[dev]
    else
        return "eth"
    end
end


--[[
    BANDWIDTH TESTS
]]--

-- Anna: simplified iperf client interface
function active.iperf(opt)
   if not opt or not opt.client then
      return nil, {code=-32600, message="Missing destination"}
   else
      local options = ""
      if opt.proto=="udp" then
	 options = options .. " -u"
      end
      options = options .. check_param(opt.client, "-c")
      options = options .. check_param(opt.port, "-p")
      options = options .. check_param(opt.bandwidth, "-b")
      options = options .. check_param(opt.num, "-n")
      options = options .. check_param(opt.len, "-l")
      options = options .. check_param(opt.time, "-t")
      if opt.tradeoff == true then
	 options = options .. "-r"
      end
      options = options .. "-y C -i 1"
      local cmd = "iperf" .. options    
      local result = luci.util.exec(cmd)
      return formatres(result,cmd) 
   end
end

-- start iperf server
function active.iperfs_start(opt)
   if not opt or not opt.port then
      return nil, {code=-32600, message="Missing port parameter"}
   else
      local options = ""
      if opt.proto=="udp" then
	 options = options .. " -u"
      end
      options = options .. " -s"
      options = options .. check_param(opt.port, "-p")
      options = options .. "-y C -i 1"
      local cmd = "iperf" .. options 
      local pid = luci.util.exec("sh /usr/bin/bismark-command \"" .. cmd .. "\" \"/tmp/iperfserver" .. opt.port .. ".temp\"")
      return formatres(pid,cmd) 
   end
end

-- stop iperf server
function active.iperfs_stop(opt)
   if not opt or not opt.pid or not opt.port then
      return nil, {code=-32600, message="Missing pid or port parameter"}
   else
      -- send SIGTERM to iperf server process
      luci.sys.process.signal(opt.pid, 15)

      -- get the temp output file
      local resfile = "/tmp/iperfserver" .. opt.port .. ".temp" 
      if fs.access(resfile) then
	 local report = io.lines(resfile)
	 luci.util.exec("rm -f " .. resfile)
	 return formatres(report,"iperf -s") 
      else
	 return nil, {code=-32700, message="Bandwidth report doesn't exist"}
      end
   end
end


----------------------------------------------------------------------------------------------
--- TCP BANDWIDTH TEST
-- direction: UP - make this more OOPs  

function active.tcpserver(port_num, interval_time, window_size)
    -- currently use default parameters (-t, -P is set at client only)
    -- -i 10 -p 5001 -w 8.00 KByte
    -- try -w 1024k
    -- this should be called BEFORE iperf client starts on device
    local options = ""
    options = options .. check_param(port_num, "-p")
    options = options .. check_param(interval_time, "-i")
    options = options .. check_param(window_size, "-w")
    
    --SOS("iperf -y C -s" .. options .. " > /tmp/iperf"..port_num..".temp &")
    --os.execute("iperf -y C -s" .. options .. " > /tmp/iperf"..port_num..".temp &")
    --return luci.util.exec("pgrep iperf")
    
    local iperfPID = luci.util.exec("sh /usr/bin/bismark-command \"iperf -y C -s"..options.."\" \"/tmp/iperf"..port_num..".temp\"")
    SOS("sh /usr/bin/bismark-command \"iperf -y C -s"..options.."\" \"/tmp/iperf"..port_num..".temp\"")
    SOS(iperfPID, "iperf PID from bismark-command shell script = ")
    
    -- TODO can use luaposix instead to call getpid() directly from lua

    return iperfPID
end

-- direction: DW
function active.tcpclient(port_num, host, window_size, test_time, interval_time, bidirectional)
    -- currently use default parameters (-t, -P is set at client only)
    -- -i 10 -t 10 -p 5002 -w 8.00 KByte -P 1
    -- try -w 1024k, -P 4 etc
    -- return report if no errors, else return result
    local options = ""
    options = options .. check_param(port_num, "-p")
    options = options .. check_param(window_size, "-w")
    options = options .. check_param(test_time, "-t")
    options = options .. check_param(interval_time, "-i")
    if bidirectional==true then options = options .. " -r" end
    
    SOS("iperf -y C -c '"..host:gsub("'", '').."'" .. options .." > /tmp/iperf"..port_num..".temp")
    local result = os.execute("iperf -y C -c '"..host:gsub("'", '').."'" .. options .." > /tmp/iperf"..port_num..".temp")
    --SOS(result, "execution tcp client result = ")
    
    if result == 0 then
        return active.bandwidthreport(port_num)
    end
    return nil, {code=-32600, message="Invalid request. iperf client not started. result = "..result}
    
end

--------------------------------------------------------------------------------
--- UDP BANDWIDTH TEST
-- direction: UP - make this more OOPs

function active.udpserver(port_num, interval_time, buffer_size, packet_size)
    -- currently use default parameters (-t, -P is set at client only)
    -- -i 10 -p 5003 -w 160 KByte
    -- try -w 1024k
    -- this should be called BEFORE iperf client starts on device
    local options = ""
    options = options .. check_param(port_num, "-p")
    options = options .. check_param(interval_time, "-i")
    options = options .. check_param(buffer_size, "-w")
    options = options .. check_param(packet_size, "-l")
    
    --SOS("iperf -u -y C -s" .. options .." > /tmp/iperf"..port_num..".temp &")
    --os.execute("iperf -u -y C -s" .. options .." > /tmp/iperf"..port_num..".temp &")
    SOS("sh /usr/bin/bismark-command \"iperf -u -y C -s"..options.."\" \"/tmp/iperf"..port_num..".temp\"")
    local iperfPID = luci.util.exec("sh /usr/bin/bismark-command \"iperf -u -y C -s"..options.."\" \"/tmp/iperf"..port_num..".temp\"")
    SOS(iperfPID, "iperf PID from bismark-command shell script = ")
    
    -- TODO can use luaposix instead to call getpid() directly from lua

    return iperfPID
end

-- direction: DW
function active.udpclient(port_num, host, bandwidth, buffer_size, test_time, interval_time, packet_size, bidirectional)
    -- currently use default parameters (-t, -P is set at client only)
    -- -i 10 -t 10 -p 5004 -w 160 KByte; -b is compulsory
    -- try -w 1024k,
    -- always enter bandwidth in Mbps, socket buffer size in kb
    -- return report if no errors, else return result
    local options = ""
    options = options .. check_param(port_num, "-p")
    options = options .. check_param(bandwidth, "-b")
    options = options .. check_param(buffer_size, "-w")
    options = options .. check_param(test_time, "-t")
    options = options .. check_param(interval_time, "-i")
    options = options .. check_param(packet_size, "-l")
    if bidirectional==true then options = options .. " -r" end
    
    SOS("iperf -u -y C -c '"..host:gsub("'", '').."'"..options.." >/tmp/iperf"..port_num..".temp")
    local result = os.execute("iperf -u -y C -c '"..host:gsub("'", '').."'"..options.." >/tmp/iperf"..port_num..".temp")
    --SOS(result, "execution udp client result = ")
    
    if result==0 then
        return active.bandwidthreport(port_num)
    else
        return nil, {code=-32600, message="Invalid request. iperf client not started. result = "..result}
    end
end

-------------------------------------------------------------------------------------------

function active.killserver(PID, port_num)
    -- send SIGTERM to iperf server process
    -- if success return bandwidth report, else return error code
    --for pids in PID:split("\n") do
    --    luci.sys.process.signal(pids, 15)
    --end
    luci.sys.process.signal(PID, 15)
    return active.bandwidthreport(port_num)
end

function active.bandwidthreport(port_num)
    -- port_num = 5001 for server and 5002 for client TCP
    if fs.access("/tmp/iperf"..port_num..".temp") then
        local report = io.lines("/tmp/iperf"..port_num..".temp")
        os.execute("rm -f /tmp/iperf"..port_num..".temp")
        return report
    else
        return nil, {code=-32700, message="Parse error. Bandwidth report doesn't exist"}
    end
end

--------------------------------------------------------------------------------------------

--[[
    SHAPERPROBE (external)
]]

function active.shaperprobe(ip_addr)
    -- by default probes to a server at gatech where shaperprobeserver is running..
    local options = ""
    options = options .. check_param(ip_addr, "-s")
    
    os.execute("/usr/bin/prober"..options .. " >> /tmp/shaperprobe.temp &")
    return 0
end

function active.readshaperprobe()
    if fs.access("/tmp/shaperprobe.temp") then
        local report = io.lines("/tmp/shaperprobe.temp")
        os.execute("rm -f /tmp/shaperprobe.temp")
        return report
    else
        return -1
    end
end


--[[
    CONNTRACK
]]--
--function active.saveconntrack()
--    -- save /proc/net/nf_conntract > /tmp/<os.time>.conntrack
--    local t1 = os.time()
--    os.execute("cat /proc/net/nf_conntrack > /tmp/"..t1..".conntrack")
--
--    return t1
--    
--end
--
--function active.readconntrack(t1)
--    -- send saved conntrack temp files to client and delete from Device
--    if fs.access("/tmp/"..t1..".conntrack") then
--        local report=io.lines("/tmp/"..t1..".conntrack")
--        os.execute("rm -rf /tmp/"..t1..".conntrack")
--        return report
--    else
--        return -1
--    end
--end

-- Returns conntrack information
-- @return	Table with the currently tracked IP connections
function active.conntrack(callback)
	local connt = {}
	if io.open("/proc/net/nf_conntrack", "r") then
            local i = 0
	    for line in io.lines("/proc/net/nf_conntrack") do
                --line = line:match("^(.-( [^ =]+=).-)%2")
                
    		local entry, flags = _parse_mixed_record(line, " +")
                -- don't neglect time wait either
                --if flags[6] ~= "TIME_WAIT" then
                entry.layer3 = flags[1]     -- ipv4
                entry.layer4 = flags[3]     -- udp/tcp
                entry.timeout = flags[5]    -- timeout value when connected or waiting
                if flags[6] then
                    entry.connstate = flags[6]
                end
                if flags[7] then
                    entry.r_connstate = flags[7]
                end
                
                -- not sure why we do this...
                for i=1, #entry do
                    entry[i] = nil
                end

                if callback then
                    callback(entry)
                else
                    --#connt = flow table entry number
                    connt[#connt+1] = entry
                end
                --end
	    end
            
	else
		return nil
	end
	return connt
end

-----------------------------------------------------------------------
-- Internal functions
function string:split(sep)
        local sep, fields = sep or ":", {}
        local pattern = string.format("([^%s]+)", sep)
        self:gsub(pattern, function(c) fields[#fields+1] = c end)
        return fields
end

--function justWords(str)
--  local t = {}
--  local function helper(word) table.insert(t, word) return "" end
--  if not str:gsub("%w+", helper):find"%S" then return t end
--end

-- returns data,flags
-- data is table containing all values after "=" sign. if any key is repeated, append key string with "r" for reverse direction
-- flags is a table contains all values of string which were surrounded by spaces in order of occurance. the values without an "=" sign
function _parse_mixed_record(cnt, delimiter)
	delimiter = delimiter or "  "
	local data = {}
	local flags = {}

	for i, l in pairs(cnt:split("\n")) do
            for j, f in pairs(l:split(delimiter)) do
                local k, x, v = f:match('([^%s][^:=]*) *([:=]*) *"*([^\n"]*)"*')
                if k then
                    if x == "" then
                            table.insert(flags, k)
                    else
                        if data[k] then
                            k = 'r_'..k
                        end
                        data[k] = v
                    end
                end
            end
	end
	return data, flags
end

-- checks options and creates an option string to call commands on router
function check_param(attrib, option_string)
   if attrib and (attrib ~= 0) then
      if option_string then
	 return " " .. option_string .. " " .. attrib .. " "
      else
	 return " " .. attrib .. " "
      end
   end
   return " "
end

function SOS(command_string, description)
    if description then
        os.execute("echo ".. description .." >> /tmp/command.log")
    else
        os.execute("echo $(date) >> /tmp/command.log")
    end
    
    os.execute("echo '" .. command_string .. "' >> /tmp/command.log")

end
