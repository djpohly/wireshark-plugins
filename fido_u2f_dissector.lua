-- started based on https://gist.github.com/z4yx/218116240e2759759b239d16fed787ca

cbor = Dissector.get("cbor")

ctaphid_proto = Proto("CTAPHID","FIDO Client to Authenticator Protocol over USB HID")
ctaphidfield_cid  = ProtoField.uint32("ctaphid.cid", "Channel ID", base.HEX)
ctaphidfield_cmd  = ProtoField.uint8("ctaphid.cmd", "Command", base.HEX)
ctaphidfield_bcnt = ProtoField.uint16("ctaphid.bcnt", "Payload Length", base.DEC_HEX)
ctaphidfield_seq  = ProtoField.uint8("ctaphid.seq", "Packet Sequence", base.HEX)
ctaphidfield_data = ProtoField.bytes("ctaphid.data", "Data")
ctaphid_proto.fields = { ctaphidfield_cid, ctaphidfield_cmd, ctaphidfield_bcnt, ctaphidfield_seq, ctaphidfield_data }

u2f_proto = Proto("u2f","FIDO CTAP1/U2F Protocol")
u2ffield_cla = ProtoField.uint8("u2f.request.cla", "Class", base.HEX)
u2ffield_ins = ProtoField.uint8("u2f.request.ins", "U2F command code", base.HEX)
u2ffield_p1 = ProtoField.uint8("u2f.request.p1", "U2F command parameter 1", base.HEX)
u2ffield_p2 = ProtoField.uint8("u2f.request.p2", "U2F command parameter 2", base.HEX)
u2ffield_reqlen = ProtoField.uint24("u2f.request.length", "U2F request data length", base.HEX)
u2ffield_reqdata = ProtoField.bytes("u2f.request.data", "U2F request data")
u2ffield_status = ProtoField.uint16("u2f.response.status", "U2F response status", base.HEX)
u2ffield_respframe = ProtoField.framenum("u2f.response.req_frame", "U2F request frame", base.NONE, frametype.REQUEST)
u2ffield_respdata = ProtoField.bytes("u2f.response.data", "U2F response data")
u2ffield_respversion = ProtoField.string("u2f.response.version", "Version string")
u2ffield_clientdata = ProtoField.bytes("u2f.clientdatahash", "Client data hash (SHA-256)")
u2ffield_appid = ProtoField.bytes("u2f.appidhash", "App ID hash (SHA-256)")
u2ffield_handlelen = ProtoField.uint8("u2f.handle.len", "Key handle length")
u2ffield_handle = ProtoField.bytes("u2f.handle.data", "Key handle")
u2ffield_userpresence = ProtoField.uint8("u2f.userpresence", "User presence")
u2ffield_counter = ProtoField.uint32("u2f.counter", "Counter")
u2ffield_pk = ProtoField.bytes("u2f.pk", "User public key")
u2ffield_cert = ProtoField.bytes("u2f.cert", "Attestation certificate (X.509)")
u2ffield_signature = ProtoField.bytes("u2f.signature", "Signature (X9.62)")
u2f_proto.fields = { u2ffield_cla, u2ffield_ins, u2ffield_p1, u2ffield_p2, u2ffield_reqlen, u2ffield_reqdata, u2ffield_status, u2ffield_respframe, u2ffield_respdata, u2ffield_respversion, u2ffield_clientdata, u2ffield_appid, u2ffield_handlelen, u2ffield_handle, u2ffield_userpresence, u2ffield_counter, u2ffield_signature, u2ffield_pk, u2ffield_cert }


-- Field Extractor
field_usb_bus = Field.new("usb.bus_id")
field_usb_device = Field.new("usb.device_address")
field_usb_endpoint = Field.new("usb.endpoint_address")
field_usb_endpointdir = Field.new("usb.endpoint_address.direction")
field_usb_endpointnum = Field.new("usb.endpoint_address.number")
field_usb_datalen = Field.new("usb.data_len")

CTAPHID_COMMANDS = {
	CTAPHID_MSG          = 0x03,
	CTAPHID_CBOR         = 0x10,
	CTAPHID_INIT         = 0x06,
	CTAPHID_PING         = 0x01,
	CTAPHID_CANCEL       = 0x11,
	CTAPHID_ERROR        = 0x3F,
	CTAPHID_KEEPALIVE    = 0x3B,
	CTAPHID_WINK         = 0x08,
	CTAPHID_LOCK         = 0x04,
	CTAPHID_VENDOR_FIRST = 0x40,
	CTAPHID_VENDOR_LAST  = 0x7F
}

CTAPHID_COMMAND_STRINGS = {
    [0x03] = 'CTAPHID_MSG',
    [0x10] = 'CTAPHID_CBOR',
    [0x06] = 'CTAPHID_INIT',
    [0x01] = 'CTAPHID_PING',
    [0x11] = 'CTAPHID_CANCEL',
    [0x3F] = 'CTAPHID_ERROR',
    [0x3B] = 'CTAPHID_KEEPALIVE',
    [0x08] = 'CTAPHID_WINK',
    [0x04] = 'CTAPHID_LOCK',
	[0x40] = 'VENDOR_FIRST',
	[0x7F] = 'VENDOR_LAST',
}

U2F_INS_STRINGS = {
    [0x01] = 'U2F_REGISTER',
    [0x02] = 'U2F_AUTHENTICATE',
    [0x03] = 'U2F_VERSION',
	[0x40] = 'VENDOR_FIRST',
	[0xBF] = 'VENDOR_LAST'
}

U2F_STATUS_STRINGS = {
    [0x9000] = 'SW_NO_ERROR',
    [0x6985] = 'SW_CONDITIONS_NOT_SATISFIED',
    [0x6A80] = 'SW_WRONG_DATA',
	[0x6700] = 'SW_WRONG_LENGTH',
	[0x6E00] = 'SW_CLA_NOT_SUPPORTED',
	[0x6D00] = 'SW_INS_NOT_SUPPORTED'
}

CTAP_COMMAND_CODE = {
    [0x01]='authenticatorMakeCredential',
    [0x02]='authenticatorGetAssertion',
    [0x04]='authenticatorGetInfo',
    [0x06]='authenticatorClientPIN',
    [0x07]='authenticatorReset',
    [0x08]='authenticatorGetNextAssertion',
    [0x40]='authenticatorVendorFirst',
    [0xBF]='authenticatorVendorLast'
}
CTAP_RESPONSE_CODE = {
    [0x00]='CTAP1_ERR_SUCCESS',
    [0x01]='CTAP1_ERR_INVALID_COMMAND',
    [0x02]='CTAP1_ERR_INVALID_PARAMETER',
    [0x03]='CTAP1_ERR_INVALID_LENGTH',
    [0x04]='CTAP1_ERR_INVALID_SEQ',
    [0x05]='CTAP1_ERR_TIMEOUT',
    [0x06]='CTAP1_ERR_CHANNEL_BUSY',
    [0x0A]='CTAP1_ERR_LOCK_REQUIRED',
    [0x0B]='CTAP1_ERR_INVALID_CHANNEL',
    [0x11]='CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
    [0x12]='CTAP2_ERR_INVALID_CBOR',
    [0x14]='CTAP2_ERR_MISSING_PARAMETER',
    [0x15]='CTAP2_ERR_LIMIT_EXCEEDED',
    [0x16]='CTAP2_ERR_UNSUPPORTED_EXTENSION',
    [0x19]='CTAP2_ERR_CREDENTIAL_EXCLUDED',
    [0x21]='CTAP2_ERR_PROCESSING',
    [0x22]='CTAP2_ERR_INVALID_CREDENTIAL',
    [0x23]='CTAP2_ERR_USER_ACTION_PENDING',
    [0x24]='CTAP2_ERR_OPERATION_PENDING',
    [0x25]='CTAP2_ERR_NO_OPERATIONS',
    [0x26]='CTAP2_ERR_UNSUPPORTED_ALGORITHM',
    [0x27]='CTAP2_ERR_OPERATION_DENIED',
    [0x28]='CTAP2_ERR_KEY_STORE_FULL',
    [0x29]='CTAP2_ERR_NOT_BUSY',
    [0x2A]='CTAP2_ERR_NO_OPERATION_PENDING',
    [0x2B]='CTAP2_ERR_UNSUPPORTED_OPTION',
    [0x2C]='CTAP2_ERR_INVALID_OPTION',
    [0x2D]='CTAP2_ERR_KEEPALIVE_CANCEL',
    [0x2E]='CTAP2_ERR_NO_CREDENTIALS',
    [0x2F]='CTAP2_ERR_USER_ACTION_TIMEOUT',
    [0x30]='CTAP2_ERR_NOT_ALLOWED',
    [0x31]='CTAP2_ERR_PIN_INVALID',
    [0x32]='CTAP2_ERR_PIN_BLOCKED',
    [0x33]='CTAP2_ERR_PIN_AUTH_INVALID',
    [0x34]='CTAP2_ERR_PIN_AUTH_BLOCKED',
    [0x35]='CTAP2_ERR_PIN_NOT_SET',
    [0x36]='CTAP2_ERR_PIN_REQUIRED',
    [0x37]='CTAP2_ERR_PIN_POLICY_VIOLATION',
    [0x38]='CTAP2_ERR_PIN_TOKEN_EXPIRED',
    [0x39]='CTAP2_ERR_REQUEST_TOO_LARGE',
    [0x3A]='CTAP2_ERR_ACTION_TIMEOUT',
    [0x3B]='CTAP2_ERR_UP_REQUIRED',
    [0x7F]='CTAP1_ERR_OTHER',
    [0xDF]='CTAP2_ERR_SPEC_LAST',
    [0xE0]='CTAP2_ERR_EXTENSION_FIRST',
    [0xEF]='CTAP2_ERR_EXTENSION_LAST',
    [0xF0]='CTAP2_ERR_VENDOR_FIRST',
    [0xFF]='CTAP2_ERR_VENDOR_LAST'
}

-- Sorted set

-- Returns the first index at which value could be inserted and have the list
-- remain sorted.  Iff the list contains value, then its first occurrence is at
-- the returned index.
function ss_index(ss, value)
	-- Binary search
	start = 1
	fin = #ss
	while start <= fin do
		local mid = math.floor((start + fin) / 2)
		if value <= ss[mid] then
			fin = mid - 1
		else -- value > ss[mid]
			start = mid + 1
		end
	end
	return start
end

function ss_add(ss, value)
	local i = ss_index(ss, value)
	-- No duplicates
	if ss[i] == value then return end
	table.insert(ss, i, value)
end

function ss_contains(ss, value)
	local i = ss_index(ss, value)
	return ss[i] == value
end

-- End sorted set

function dissect_ctaphid_payload(cmd, buffer, pinfo, tree)
	if buffer:len() == 0 then return end -- && usb.function == 0x0008 && select correct endpoint/etc.
	local is_request = (field_usb_endpointdir().value == 0)
	if cmd == CTAPHID_COMMANDS.CTAPHID_MSG then
		Dissector.get("u2f"):call(buffer, pinfo, tree)
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_CBOR then
		local subtree = tree:add(buffer(0),"FIDO2 Payload")
		local ctap_cmd = buffer(0,1):uint()
			local text = nil
			if is_request then
				text = CTAP_COMMAND_CODE[ctap_cmd]
			else
				text = CTAP_RESPONSE_CODE[ctap_cmd]
			end
		pinfo.cols.protocol = "CTAP " .. text
		subtree:add(buffer(0,1),string.format('CTAP CMD/Status: %s (0x%02x)', text, ctap_cmd))
		if buffer(1):len() > 0 then
		    cbor:call(buffer(1):tvb(), pinfo, subtree)
		end
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_INIT then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_PING then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_CANCEL then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_ERROR then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_KEEPALIVE then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_WINK then
	elseif cmd == CTAPHID_COMMANDS.CTAPHID_LOCK then
	elseif cmd >= CTAPHID_COMMANDS.CTAPHID_VENDOR_FIRST and cmd <= CTAPHID_COMMANDS.CTAPHID_VENDOR_LAST then
	else
		tree:add(ctaphidfield_data, buffer(0)):prepend_text("Unknown payload ")
	end
end

function u2f_command_label(cmd, abbrev)
	if abbrev ~= true then
		abbrev = false
	end
	local command_string = U2F_INS_STRINGS[cmd]
	if command_string ~= nil and not abbrev then
		command_string = command_string .. string.format(" (0x%02x)", cmd)
	elseif command_string == nil then
		command_string =  string.format("0x%02x", cmd)
	end
	return command_string
end

function u2f_status_label(status, abbrev)
	if abbrev ~= true then
		abbrev = false
	end
	local status_string = U2F_STATUS_STRINGS[status]
	if status_string ~= nil and not abbrev then
		status_string = status_string .. string.format(" (0x%02x)", status)
	elseif status_string == nil then
		status_string =  string.format("0x%02x", status)
	end
	return status_string
end

function ctaphid_command_label(cmd)
	local command_string = CTAPHID_COMMAND_STRINGS[cmd]
	if command_string ~= nil then
		command_string = command_string .. string.format(" (0x%02x)", cmd)
	else
		command_string =  string.format("0x%02x", cmd)
		if cmd >= CTAPHID_COMMANDS.CTAPHID_VENDOR_FIRST and cmd <= CTAPHID_COMMANDS.CTAPHID_VENDOR_LAST then
			command_string = command_string .. " [Vendor specific]"
		end
	end
	return command_string
end

function channel_state_key(channel_id)
	local key = Struct.pack(">I2I2I1", field_usb_bus().value, field_usb_device().value, field_usb_endpointnum().value) .. channel_id:raw()
	return Struct.tohex(key)
end

packet_state = {} -- { packet_number => { cmd = uint, buffer = bytearray, complete = bool, u2fcmd = uint, cstate = channel_state } }
channel_state = {} -- { channel_state_key => { cmd = uint, payload_length = uint, buffer = bytearray, requests = ss } }

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

function u2f_proto.dissector(buffer,pinfo,tree)
	if buffer:len() == 0 then return end -- && usb.function == 0x0008 && select correct endpoint/etc.
	pinfo.cols.protocol = u2f_proto.name -- FIXME why can't I filter against this?
	local subtree = tree:add(ctaphid_proto,buffer(),"CTAP1/U2F")
	local is_request = (field_usb_endpointdir().value == 0)
	local pstate = packet_state[pinfo.number]
	local cstate = pstate.cstate
	if is_request then -- this is a request
		local u2f_command = buffer(1,1):uint()
		subtree:append_text(" Request")
		pinfo.cols.info = "U2F Request (" .. u2f_command_label(u2f_command, true) .. ")"
		subtree:add(u2ffield_cla, buffer(0,1))
		subtree:add(u2ffield_ins, buffer(1,1), u2f_command, "Command: " .. u2f_command_label(u2f_command))			
		subtree:add(u2ffield_p1, buffer(2,1))
		subtree:add(u2ffield_p2, buffer(3,1))
		local request_length = buffer(4,3):uint()
		subtree:add(u2ffield_reqlen, buffer(4,3))
		if request_length > 0 then
			if u2f_command == 0x01 then -- U2F_REGISTER
				local cmdtree = subtree:add(buffer(7, request_length), "U2F registration")
				cmdtree:add(u2ffield_clientdata, buffer(7, 32))
				cmdtree:add(u2ffield_appid, buffer(39, 32))
			elseif u2f_command == 0x02 then -- U2F_AUTHENTICATE
				local cmdtree = subtree:add(buffer(7, request_length), "U2F authentication")
				cmdtree:add(u2ffield_clientdata, buffer(7, 32))
				cmdtree:add(u2ffield_appid, buffer(39, 32))
				local handlelen = buffer(71, 1):uint()
				cmdtree:add(u2ffield_handlelen, buffer(71, 1))
				cmdtree:add(u2ffield_handle, buffer(72, handlelen))
			-- elseif u2f_command >= 0x40 and u2f_command <= 0xbf then -- Vendor-specific
			else
				subtree:add(u2ffield_reqdata, buffer(7, request_length))
			end
		end
		pstate.u2fcmd = u2f_command
		ss_add(cstate.requests, pinfo.number)
	else -- response
		local resp_length = buffer:len()-2
		local u2f_status = buffer(resp_length,2):uint()
		subtree:append_text(" Response")
		pinfo.cols.info = "U2F Response (" .. u2f_status_label(u2f_status, true) .. ")"

		local reqframe = cstate.requests[ss_index(cstate.requests, pinfo.number) - 1]
		assert(reqframe ~= nil)

		local u2f_command = packet_state[reqframe].u2fcmd
		subtree:add(u2ffield_respframe, reqframe, "[U2F request frame]")
		subtree:add("[Command: " .. u2f_command_label(u2f_command) .. "]")
		subtree:add(u2ffield_status, buffer(resp_length,2), u2f_status, "Status: " .. u2f_status_label(u2f_status))
		if resp_length > 0 then
			local cmdtree = subtree:add(buffer(0, resp_length), "Response data")
			if u2f_command == 0x01 then -- U2F_REGISTER
				cmdtree:add(buffer(0,1), "Reserved (must be 0x05)")
				cmdtree:add(u2ffield_pk, buffer(1,65))
				local handlelen = buffer(66, 1):uint()
				cmdtree:add(u2ffield_handlelen, buffer(66, 1))
				cmdtree:add(u2ffield_handle, buffer(67, handlelen))

				local asn1start = 67 + handlelen
				local asn1prefixlen = 2
				local asn1len = buffer(asn1start+1, 1):uint()
				if bit.band(asn1len, 0x80) then
					local asn1lenlen = bit.band(asn1len, 0x7f)
					asn1prefixlen = 2 + asn1lenlen
					asn1len = buffer(asn1start+2, asn1lenlen):int()
				end
				cmdtree:add(u2ffield_cert, buffer(asn1start, asn1prefixlen + asn1len))
				local sigstart = asn1start + asn1prefixlen + asn1len
				cmdtree:add(u2ffield_signature, buffer(sigstart, resp_length - sigstart))
			elseif u2f_command == 0x02 then -- U2F_AUTHENTICATE
				cmdtree:add(u2ffield_userpresence, buffer(0, 1))
				cmdtree:add(u2ffield_counter, buffer(1, 4))
				cmdtree:add(u2ffield_signature, buffer(5, resp_length - 5))
			elseif u2f_command == 0x03 then -- U2F_VERSION
				cmdtree:add(u2ffield_respversion, buffer(0, resp_length))
			else -- unrecognized, show raw data
				cmdtree:add(u2ffield_respdata, buffer(0, resp_length))
			end
		end
	end
	return true
end

function ctaphid_proto.init()
	packet_state = {}
	channel_state = {}
end

function ctaphid_proto.dissector(buffer,pinfo,tree)
    if buffer:len() == 0 then return end -- && usb.function == 0x0008 && select correct endpoint/etc.
	pinfo.cols.protocol = ctaphid_proto.name
	
	local channel_id = buffer(0,4)
	local payload = nil
	local cmd_or_seq = buffer(4,1):uint()
	local is_init_packet = (bit.band(cmd_or_seq, 0x80) == 0x80)
	local cmd = nil
	local payload_length = nil
	local sequence = nil
	
	-- extract relevant fields for each packet type
	if is_init_packet then
		cmd = bit.band(cmd_or_seq, 0x7f) -- ignore first bit of command field on initialization packets
		payload_length = buffer(5,2):uint()
		payload = buffer(7)
	else
		sequence = cmd_or_seq
		payload = buffer(5)
	end
	
	-- keep track of state across packets to combine segmented packets
	local cskey = channel_state_key(channel_id:bytes())
	local cstate = channel_state[cskey]
	if cstate == nil then
		assert(is_init_packet)
		cstate = {}
		cstate.requests = {}
		channel_state[cskey] = cstate
	end

	local pstate = packet_state[pinfo.number]
	if pstate == nil then
		pstate = {}
		pstate.cstate = cstate
		if cstate.buffer == nil then
			assert(is_init_packet)
			cstate.buffer = ByteArray.new()
			cstate.cmd = cmd
			cstate.payload_length = payload_length
		end
		cstate.buffer:append(payload:bytes())
		
		if cstate.payload_length > cstate.buffer:len() then -- packet incomplete
			pstate.complete = false
			pstate.cmd = cstate.cmd
		else
			cstate.buffer:set_size(cstate.payload_length) -- usbpcap always returns full packets so we need to truncate them
			pstate.complete = true
			pstate.cmd = cstate.cmd
			pstate.buffer = cstate.buffer
			cstate.buffer = nil
		end
		packet_state[pinfo.number] = pstate
	end
	
	-- generate CTAPHID subtree
	local subtree = tree:add(ctaphid_proto,buffer())

	if is_init_packet then
		local packet_text = "CTAPHID Initialization Packet"
		pinfo.cols.info = packet_text
		subtree:set_text(packet_text)
		subtree:add(ctaphidfield_cid, channel_id)
		subtree:add(ctaphidfield_cmd, buffer(4,1), cmd, "Command: " .. ctaphid_command_label(cmd))
		subtree:add(ctaphidfield_bcnt, buffer(5,2))
		subtree:add(ctaphidfield_data, payload)
	else
		local packet_text ="CTAPHID Continuation Packet"
		pinfo.cols.info = packet_text
		subtree:set_text(packet_text)
		subtree:add(ctaphidfield_cid, channel_id)
		subtree:add("Command: " .. ctaphid_command_label(pstate.cmd)):set_generated(true)
		subtree:add(ctaphidfield_seq, buffer(4,1))
		subtree:add(ctaphidfield_data, payload)
	end
		
	if pstate.complete then
		dissect_ctaphid_payload(pstate.cmd, pstate.buffer:tvb("CTAPHID data"), pinfo, tree)
	end
	return
end

usb_table = DissectorTable.get("usb.product")
usb_table:add(0x10500407,ctaphid_proto) -- VID/PID of Yubikey
usb_table:add(0x096e0858,ctaphid_proto) -- VID/PID of Feitian key
usb_table:add(0x32a33201,ctaphid_proto) -- VID/PID of Idem Key
usb_table:add_for_decode_as(u2f_proto)
