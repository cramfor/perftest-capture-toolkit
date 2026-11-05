--[[
perftest_tcp.lua
Wireshark Lua dissector for the perftest socket control channel (default TCP port 18515).

Covers the messages exchanged on the TCP control socket when perftest runs
WITHOUT rdma_cm (ethernet_client/server_connect path):

  1. exchange_versions   : NUL-terminated version string, e.g. "25.07.0\0"
  2. check_sys_data      : two 4-byte big-endian ints (cycle_buffer, cache_line_size)
  3. check_mtu           : 2-byte ASCII decimal + NUL, e.g. "3\0"
  4. negotiate_params    : 4-byte BE negotiation version (>= 6.28, KV mode)
                           then 4-byte BE length + KV string
                           "name=hexbytes;name=hexbytes;..." (chunked, <= 2048B/write)
  5. ctx_hand_shake      : ASCII key message, exact wire sizes (incl. trailing NUL):
                             59  = KEY_PRINT_FMT         (no GID)
                             76  = KEY_PRINT_FMT_DV      (no GID, data validation)
                            108  = KEY_PRINT_FMT_GID     (with GID, e.g. -x <gid index>)
                            125  = KEY_PRINT_FMT_GID_DV  (with GID, data validation)
  6. xchg_bw_reports     : 8-byte BE longs / doubles (after the test)
  7. ctx_close_connection: another round of the key handshake

Notes / limitations:
  - The legacy negotiation path (remote version <= 6.29, fixed-size binary struct)
    is shown as raw bytes; its layout lives in perftest_negotiation.h.
  - The rdma_cm control path carries keys inside RDMA SENDs, not on this socket.
  - Message boundaries have no framing; classification is heuristic.
]]

local p_perftest = Proto("perftest_tcp", "Perftest Control Channel")

--------------------------------------------------------------------------
-- Fields
--------------------------------------------------------------------------
local f_msg_type = ProtoField.string("perftest_tcp.msg_type",  "Message Type")
local f_version  = ProtoField.string("perftest_tcp.version",   "Perftest Version")
local f_mtu      = ProtoField.uint8 ("perftest_tcp.mtu",       "MTU (ibv_mtu enum)", base.DEC)
local f_u32      = ProtoField.uint32("perftest_tcp.u32",       "32-bit BE value", base.DEC)
local f_u64      = ProtoField.uint64("perftest_tcp.u64",       "64-bit BE value", base.HEX)
local f_double   = ProtoField.double("perftest_tcp.double",    "Double (BE)")
local f_kvlen    = ProtoField.uint32("perftest_tcp.kv_len",    "KV Payload Length", base.DEC)
local f_kv_pair  = ProtoField.string("perftest_tcp.kv.pair",   "Negotiation Pair")
local f_lid      = ProtoField.uint16("perftest_tcp.lid",       "LID",  base.HEX)
local f_out      = ProtoField.uint16("perftest_tcp.out_reads", "OUT (outstanding reads)", base.DEC)
local f_qpn      = ProtoField.uint32("perftest_tcp.qpn",       "QPN",  base.HEX)
local f_psn      = ProtoField.uint32("perftest_tcp.psn",       "PSN",  base.HEX)
local f_rkey     = ProtoField.uint32("perftest_tcp.rkey",      "RKey", base.HEX)
local f_vaddr    = ProtoField.uint64("perftest_tcp.vaddr",     "VAddr", base.HEX)
local f_tailva   = ProtoField.uint64("perftest_tcp.tail_vaddr","Tail Markers VAddr", base.HEX)
local f_gid      = ProtoField.bytes ("perftest_tcp.gid",       "GID")
local f_srqn     = ProtoField.uint32("perftest_tcp.srqn",      "SRQN", base.HEX)
local f_raw      = ProtoField.bytes ("perftest_tcp.raw",       "Raw Payload")

p_perftest.fields = {
    f_msg_type, f_version, f_mtu, f_u32, f_u64, f_double, f_kvlen, f_kv_pair,
    f_lid, f_out, f_qpn, f_psn, f_rkey, f_vaddr, f_tailva, f_gid, f_srqn, f_raw
}

--------------------------------------------------------------------------
-- Helpers
--------------------------------------------------------------------------

-- Build an exact UInt64 from a hex string without going through Lua number
-- (Lua numbers lose precision beyond 2^53; x86-64 heap VAddr like
-- 0x55xxxxxxxxxx already exceeds that).
local function hex_to_uint64(hexstr)
    if #hexstr < 16 then
        hexstr = string.rep("0", 16 - #hexstr) .. hexstr
    elseif #hexstr > 16 then
        hexstr = hexstr:sub(-16)
    end
    local hi = tonumber(hexstr:sub(1, 8), 16) or 0
    local lo = tonumber(hexstr:sub(9, 16), 16) or 0
    return UInt64.new(hi, lo)
end

local function is_print_ascii(b)
    return b >= 0x20 and b <= 0x7e
end

-- Request one more TCP segment and bail out of this packet.
local function ask_more(pinfo)
    if pinfo.can_desegment then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        pinfo.desegment_offset = 0
        return true
    end
    return false
end

--------------------------------------------------------------------------
-- Key message parsing (KEY_PRINT_FMT* family)
--
-- Token layout (colon-separated, trailing ':' then a NUL byte on the wire):
--   plain    : lid:out:qpn:psn:rkey:vaddr:srqn                      ( 7 tokens,  59B)
--   plain+DV : lid:out:qpn:psn:rkey:vaddr:tail_vaddr:srqn           ( 8 tokens,  76B)
--   GID      : lid:out:qpn:psn:rkey:vaddr:gid[0..15]:srqn           (23 tokens, 108B)
--   GID+DV   : lid:out:qpn:psn:rkey:vaddr:tail_vaddr:gid[0..15]:srqn(24 tokens, 125B)
--------------------------------------------------------------------------
local KEY_SIZES = { [59] = true, [76] = true, [108] = true, [125] = true }

local function parse_key_msg(subtree, buf, base, msglen)
    local s = buf(base, msglen):raw()
    local tokens = {}
    local pos = 1
    while true do
        local c = s:find(":", pos, true)
        if not c then break end
        tokens[#tokens + 1] = { v = s:sub(pos, c - 1), off = pos - 1, len = c - pos }
        pos = c + 1
    end

    local n = #tokens
    local has_gid = (n == 23 or n == 24)
    local has_dv  = (n == 8  or n == 24)
    if not (n == 7 or n == 8 or n == 23 or n == 24) then return false end

    local function add(field, tok, as_uint64)
        if as_uint64 then
            subtree:add(field, buf(base + tok.off, tok.len), hex_to_uint64(tok.v))
        else
            subtree:add(field, buf(base + tok.off, tok.len), tonumber(tok.v, 16))
        end
    end

    local i = 1
    add(f_lid,   tokens[i]); i = i + 1
    add(f_out,   tokens[i]); i = i + 1
    add(f_qpn,   tokens[i]); i = i + 1
    add(f_psn,   tokens[i]); i = i + 1
    add(f_rkey,  tokens[i]); i = i + 1
    add(f_vaddr, tokens[i], true); i = i + 1
    if has_dv then
        add(f_tailva, tokens[i], true); i = i + 1
    end
    if has_gid then
        local gid_bytes = ByteArray.new()
        for g = 0, 15 do
            local tok = tokens[i + g]
            if tok then gid_bytes:append(ByteArray.new(tok.v)) end
        end
        -- Constructed bytes (the wire carries GID as ASCII text), marked generated.
        local gi = subtree:add(f_gid, gid_bytes:tvb()():range(0, 16))
        gi:set_generated()
        i = i + 16
    end
    add(f_srqn, tokens[i])

    local kind = (has_gid and "GID" or "no-GID") .. (has_dv and ", DV" or "")
    return true, kind, tokens[3] and tonumber(tokens[3].v, 16) or nil
end

--------------------------------------------------------------------------
-- KV negotiation string parsing: "name=hexbytes;name=hexbytes;..."
-- Values are the raw field bytes (network byte order) hex-encoded
-- (perftest_negotiation.c: negotiate_params_kv_string).
--------------------------------------------------------------------------
local KV_ENUMS = {
    connection_type = { "RC", "UC", "UD", "RawEth", "XRC", "DC", "SRD" },
    verb            = { "SEND", "SEND_IMM", "WRITE", "WRITE_IMM", "READ", "ATOMIC" },
    tst             = { "LAT", "BW", "LAT_BY_BW", "FS_RATE" },
    test_method     = { "RUN_REGULAR", "RUN_ALL", "RUN_INFINITELY" },
    atomicType      = { "CMP_AND_SWAP", "FETCH_AND_ADD" },
    test_type       = { "ITERATIONS", "DURATION" },
    report_fmt      = { "GBS", "MBS" },
}
local KV_BOOL = {
    aes_xts = true, use_rdma_cm = true, use_write_with_imm = true,
    no_enhanced_reorder = true, sig_offload = true, data_validation = true,
}

local function kv_value_text(key, hexstr)
    local nbytes = #hexstr / 2
    if nbytes == 4 then
        local v = tonumber(hexstr, 16)
        if not v then return nil end
        if KV_ENUMS[key] and KV_ENUMS[key][v + 1] then
            return string.format("%s (%d)", KV_ENUMS[key][v + 1], v)
        elseif KV_BOOL[key] then
            return v == 0 and "OFF (0)" or "ON (" .. v .. ")"
        end
        return tostring(v)
    elseif nbytes == 8 then
        return "0x" .. hexstr
    end
    return nil -- odd size: just show raw hex
end

local function parse_kv(subtree, buf, base, kvlen)
    local s = buf(base, kvlen):raw()
    local count = 0
    for pair in string.gmatch(s, "([^;]*);") do
        local eq = pair:find("=", 1, true)
        if eq then
            local key  = pair:sub(1, eq - 1)
            local hexv = pair:sub(eq + 1)
            local text = kv_value_text(key, hexv)
            local label = key .. " = " .. (text or ("hex:" .. hexv))
            -- Link the item to the raw pair bytes in the packet.
            local startoff = s:find(pair, 1, true)
            if startoff then
                subtree:add(f_kv_pair, buf(base + startoff - 1, #pair), label)
            else
                subtree:add(f_kv_pair, label)
            end
            count = count + 1
        end
    end
    return count
end

--------------------------------------------------------------------------
-- Single-message dissection.
-- Returns: consumed bytes (>0), or 0 for "unknown: dump as raw",
-- or nil when desegmentation was requested.
--------------------------------------------------------------------------
local function dissect_one(buf, pinfo, root, off, rem)
    local b0 = buf(off, 1):uint()

    -- 1) Key exchange message: "xxxx:" hex prefix, NUL-terminated at a known size.
    if rem >= 6 then
        local probe = buf(off, math.min(rem, 6)):raw()
        if probe:match("^%x%x%x%x:") then
            local maxlen = math.min(rem, 130)
            local zoff = nil
            for i = 0, maxlen - 1 do
                if buf(off + i, 1):uint() == 0 then zoff = i; break end
            end
            if zoff and KEY_SIZES[zoff + 1] then
                local subtree = root:add(p_perftest, buf(off, zoff + 1),
                    "Key Exchange (" .. (zoff + 1) .. " bytes)")
                local ok, kind, qpn = parse_key_msg(subtree, buf, off, zoff + 1)
                if ok then
                    subtree:add(f_msg_type, buf(off, zoff + 1), "Key Exchange " .. kind)
                    if qpn then
                        pinfo.cols.info = string.format("Key Exchange QPN=%#06x", qpn)
                    end
                    return zoff + 1
                end
            elseif not zoff and rem < 130 then
                -- Prefix looks like a key message but it is not complete here.
                if ask_more(pinfo) then return nil end
            end
        end
    end

    -- 2) Version exchange: NUL-terminated "x.y.z" ASCII (<= 16 bytes).
    if rem >= 4 and is_print_ascii(b0) then
        local maxlen = math.min(rem, 16)
        local candidate = buf(off, maxlen):raw()
        -- NB: use raw() rather than string() everywhere in this script:
        -- TvbRange:string() is backed by a NUL-terminated C string and
        -- truncates at the first embedded zero byte on some builds.
        local zpos = candidate:find("\0", 1, true)
        if zpos then
            local body = candidate:sub(1, zpos - 1)
            if body:match("^%d+%.%d+") then
                -- The version travels in a fixed-size char buffer
                -- (sizeof(rem_version)); trailing NUL padding belongs to the
                -- same field. Consume the zero run only up to the last
                -- plausible field size it actually reaches (8/16/32), so a
                -- coalesced following message is not swallowed.
                local fieldlen = zpos
                local i = zpos
                while i < rem
                    and i < 32
                    and buf(off + i, 1):uint() == 0 do
                    i = i + 1
                    if i == 8 or i == 16 or i == 32 then fieldlen = i end
                end
                local subtree = root:add(p_perftest, buf(off, fieldlen),
                    "Version Exchange (" .. fieldlen .. " bytes)")
                subtree:add(f_msg_type, buf(off, fieldlen), "Version Exchange")
                subtree:add(f_version, buf(off, zpos - 1), body)
                pinfo.cols.info = "Version Exchange: " .. body
                return fieldlen
            end
        end
    end

    -- 3) MTU exchange: one ASCII digit ('1'..'5') + NUL (sizeof(char[2])).
    if rem == 2 and b0 >= 0x31 and b0 <= 0x35 and buf(off + 1, 1):uint() == 0 then
        local subtree = root:add(p_perftest, buf(off, 2), "MTU Exchange")
        subtree:add(f_msg_type, buf(off, 2), "MTU Exchange")
        subtree:add(f_mtu, buf(off, 1), b0 - 0x30)
        pinfo.cols.info = "MTU Exchange: enum " .. (b0 - 0x30)
        return 2
    end

    -- 4) KV negotiation: 4-byte BE length + "name=hex;..." payload.
    if rem >= 6 then
        local kvlen = buf(off, 4):uint()
        if kvlen >= 2 and kvlen <= 100000 then
            local headlen = math.min(rem - 4, 16)
            if headlen >= 2 then
                local head = buf(off + 4, headlen):raw()
                if head:match("^%a[%w_]*=") then
                    if rem - 4 < kvlen then
                        if pinfo.can_desegment then
                            pinfo.desegment_len = kvlen - (rem - 4)
                            pinfo.desegment_offset = 0
                            return nil
                        end
                    else
                        local subtree = root:add(p_perftest, buf(off, 4 + kvlen),
                            "Parameter Negotiation (KV)")
                        subtree:add(f_msg_type, buf(off, 4 + kvlen), "KV Negotiation")
                        subtree:add(f_kvlen, buf(off, 4))
                        local npairs = parse_kv(subtree, buf, off + 4, kvlen)
                        pinfo.cols.info = string.format("KV Negotiation (%d pairs)", npairs)
                        return 4 + kvlen
                    end
                end
            end
        end
    end

    -- 5) Standalone 8-byte big-endian binary field: bw report longs/doubles.
    --    Checked before the generic u32 rule; a coalesced pair of u32 control
    --    values landing in one 8-byte packet is the accepted ambiguity.
    if rem == 8 then
        local looks_binary = false
        for i = 0, 7 do
            if not is_print_ascii(buf(off + i, 1):uint()) then
                looks_binary = true
                break
            end
        end
        if looks_binary then
            local subtree = root:add(p_perftest, buf(off, 8), "8-byte Control / Report Field")
            subtree:add(f_msg_type, buf(off, 8), "8-byte BE value (report u64/double)")
            subtree:add(f_u64, buf(off, 8))
            local ok, d = pcall(function() return buf(off, 8):double() end)
            if ok and d then
                local di = subtree:add(f_double, d)
                di:set_generated()
            end
            pinfo.cols.info = "8-byte control/report field"
            return 8
        end
    end

    -- 6) Generic 4-byte big-endian value (negotiation version, cycle_buffer,
    --    cache_line_size, chunk length prefix, ...). Also fires mid-stream in
    --    coalesced segments when the window looks binary. Without conversation
    --    state it cannot be told apart from the first half of an 8-byte report
    --    field, so it is labeled generically.
    if rem >= 4 then
        local looks_binary = false
        for i = 0, 3 do
            if not is_print_ascii(buf(off + i, 1):uint()) then
                looks_binary = true
                break
            end
        end
        if looks_binary then
            local subtree = root:add(p_perftest, buf(off, 4), "32-bit Control Value")
            subtree:add(f_msg_type, buf(off, 4),
                "32-bit BE value (version/sys-data/length)")
            subtree:add(f_u32, buf(off, 4))
            pinfo.cols.info = "Control u32 = " .. buf(off, 4):uint()
            return 4
        end
    end

    return 0 -- unknown: caller dumps the remainder as raw
end

--------------------------------------------------------------------------
-- Main dissector: iterate, because several small control writes may be
-- coalesced into one TCP segment.
--------------------------------------------------------------------------
function p_perftest.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    if len == 0 then return end

    pinfo.cols.protocol = "PERFTEST_TCP"
    local root = tree:add(p_perftest, buffer(), "Perftest Control Channel")

    local off = 0
    while off < len do
        local consumed = dissect_one(buffer, pinfo, root, off, len - off)
        if consumed == nil then return end -- desegmentation requested
        if consumed == 0 then
            root:add(f_raw, buffer(off))
            break
        end
        off = off + consumed
    end
end

--------------------------------------------------------------------------
-- Heuristic entry: also catches the channel when a non-default port is used
-- (perftest -p <port>). Kept deliberately conservative.
--------------------------------------------------------------------------
local function heur(buffer, pinfo, tree)
    local len = buffer:len()
    if len < 5 then return false end
    local head = buffer(0, math.min(len, 5)):raw()
    -- key message prefix "xxxx:" or version "x.y."
    if head:match("^%x%x%x%x:") or head:match("^%d+%.%d") then
        p_perftest.dissector(buffer, pinfo, tree)
        return true
    end
    return false
end

--------------------------------------------------------------------------
-- Registration: default port + heuristic for custom ports.
--------------------------------------------------------------------------
local tcp_port_table = DissectorTable.get("tcp.port")
tcp_port_table:add(18515, p_perftest)
p_perftest:register_heuristic("tcp", heur)
