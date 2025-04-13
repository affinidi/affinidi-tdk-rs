#!lua name=atm

-- store_message
-- keys = message_hash
-- args = [1] message
--        [2] expiry epoch at in seconds resolution
--        [3] message length in bytes
--        [4] to_did_hash
--        [5] from_did_hash <optional>
local function store_message(keys, args)
    -- Do we have the correct number of arguments?
    -- from_did_hash can be optional!!! Means an anonymous message
    if #args < 4 and #args > 5 then
        return redis.error_reply('store_message: expected 4 or 5 arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Get current time on server
    local time = redis.call('TIME')
    local time = string.format("%d%03d", time[1], time[2] / 1000)
    local bytes = tonumber(args[3])
    if bytes == nil then
        return redis.error_reply('store_message: invalid bytes')
    end

    -- Store message
    redis.call('SET', 'MSG:' .. keys[1], args[1])

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_BYTES', bytes)
    redis.call('HINCRBY', 'GLOBAL', 'RECEIVED_COUNT', 1)

    -- Create Message Expiry Record
    redis.call('ZADD', 'MSG_EXPIRY', 'NX', args[2], 'MSG_EXPIRY:' ..args[2])
    redis.call('SADD', 'MSG_EXPIRY:' ..args[2], keys[1])

    -- Update the receiver records
    redis.call('HINCRBY', 'DID:' .. args[4], 'RECEIVE_QUEUE_BYTES', bytes)
    redis.call('HINCRBY', 'DID:' .. args[4], 'RECEIVE_QUEUE_COUNT', 1)
    -- If changing the fields in the future, update the fetch_messages function
    local RQ = redis.call('XADD', 'RECEIVE_Q:' .. args[4], time .. '-*', 'MSG_ID', keys[1], 'BYTES', bytes, 'FROM',
        args[5])

    -- Update the sender records
    local SQ = nil
    if table.getn(args) == 5 then
        -- Update the sender records
        redis.call('HINCRBY', 'DID:' .. args[5], 'SEND_QUEUE_BYTES', bytes)
        redis.call('HINCRBY', 'DID:' .. args[5], 'SEND_QUEUE_COUNT', 1)
        SQ = redis.call('XADD', 'SEND_Q:' .. args[5], time .. '-*', 'MSG_ID', keys[1], 'BYTES', bytes, 'TO', args[4])
    end

    -- Update message MetaData
    redis.call('HMSET', 'MSG:META:' .. keys[1], 'BYTES', bytes, 'TO', args[4], 'TIMESTAMP', time, 'RECEIVE_ID', RQ)
    if SQ ~= nil then
        redis.call('HMSET', 'MSG:META:' .. keys[1], 'FROM', args[5], 'SEND_ID', SQ)
    end

    return redis.status_reply('OK')
end

-- delete_message
-- keys = message_hash
-- args = [1] did_hash
local function delete_message(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('delete_message: only accepts one key')
    end

    -- Correct number of args?
    if #args ~= 1 then
        return redis.error_reply('delete_message: Requires DID hash argument')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Retrieve message metadata
    local meta = redis.call('HGETALL', 'MSG:META:' .. keys[1])
    local next = next
    if next(meta.map) == nil then
        return redis.error_reply('NOT_FOUND: message_hash ('.. keys[1] ..')')
    end

    -- Check that the requesting DID has some form of ownership of this message
    if meta.map.TO ~= args[1] and meta.map.FROM ~= args[1] and args[1] ~= "ADMIN" then
        return redis.error_reply('PERMISSION_DENIED: Requesting DID does not have ownership of this message')
    end

    local bytes = meta.map.BYTES
    if bytes == nil then
        redis.log(redis.LOG_WARNING, 'message (' .. keys[1] .. ') metadata did not contain BYTES field.')
        return redis.error_reply('message (' .. keys[1] .. ') metadata did not contain BYTES field.')
    end

    -- Delete message
    redis.call('DEL', 'MSG:' .. keys[1])

    -- Set Global Metrics
    redis.call('HINCRBY', 'GLOBAL', 'DELETED_BYTES', bytes)
    redis.call('HINCRBY', 'GLOBAL', 'DELETED_COUNT', 1)

    -- Remove the receiver records
    redis.call('HINCRBY', 'DID:' .. meta.map.TO, 'RECEIVE_QUEUE_BYTES', -bytes)
    redis.call('HINCRBY', 'DID:' .. meta.map.TO, 'RECEIVE_QUEUE_COUNT', -1)
    redis.call('XDEL', 'RECEIVE_Q:' .. meta.map.TO, meta.map.RECEIVE_ID)

    -- Remove the sender records
    local SQ = nil
    if meta.map.SEND_ID ~= nil then
        -- Remove the sender records
        redis.call('HINCRBY', 'DID:' .. meta.map.FROM, 'SEND_QUEUE_BYTES', -bytes)
        redis.call('HINCRBY', 'DID:' .. meta.map.FROM, 'SEND_QUEUE_COUNT', -1)
        SQ = redis.call('XDEL', 'SEND_Q:' .. meta.map.FROM, meta.map.SEND_ID)
    end

    -- Remove the message metadata
    redis.call('DEL', 'MSG:META:' .. keys[1])

    return redis.status_reply('OK')
end

-- fetch_messages
-- keys = did_hash
-- args = [1] start_id
--        [2] limit
local function fetch_messages(keys, args)
    -- Do we have the correct number of arguments?
    if #args ~= 2 then
        return redis.error_reply('fetch_messages: wrong arguments')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Prepend an exclusive start_id if it exists
    local start_id = '-'
    if args[1] ~= "-" then
        start_id = '(' .. args[1]
    end

    -- Get list of messages from stream
    local list = redis.call('XRANGE', 'RECEIVE_Q:' .. keys[1], start_id, '+', 'COUNT', args[2])

    local fetched_messages = {}
    -- unpack the XRANGE list
    for x, element in ipairs(list) do
        -- element[1] = stream_id
        -- element[2] = array of Stream Fields
        for i, sub_element in ipairs(element) do
            if i == 1 then
                -- This is the stream ID
                fetched_messages[x] = { 'STREAM_ID', sub_element }
            else
                -- [1] = MSG_ID
                -- [2] = message_id
                -- [3] = BYTES
                -- [4] = bytes
                -- [5] = FROM
                -- [6] = from_did
                table.insert(fetched_messages[x], sub_element[1])
                table.insert(fetched_messages[x], sub_element[2])
                table.insert(fetched_messages[x], 'FROM_DID')
                table.insert(fetched_messages[x], sub_element[6])

                -- fetch the message
                table.insert(fetched_messages[x], 'MSG')
                local msg = redis.call('GET', 'MSG:' .. sub_element[2])
                table.insert(fetched_messages[x], msg)

                -- fetch the message metadata
                local meta = redis.call('HGETALL', 'MSG:META:' .. sub_element[2])
                for k, v in pairs(meta.map) do
                    table.insert(fetched_messages[x], 'META_' .. k)
                    table.insert(fetched_messages[x], v)
                end
            end
        end
    end -- end of XRANGE list

    return fetched_messages
end

-- clean_start_streaming
-- keys = uuid
-- returns number of sessions cleaned up
local function clean_start_streaming(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('clean_start_streaming: only accepts one key')
    end

    -- Correct number of args?
    if #args ~= 0 then
        return redis.error_reply('clean_start_streaming: No arguments required')
    end

    -- set response type to Version 3
    redis.setresp(3)

    -- Prepend an exclusive start_id if it exists
    local key = 'STREAMING_SESSIONS:' .. keys[1]

    -- Clean up sessions
    local counter = 0
    while (true) do
        local response = redis.call('SPOP', key, 1)

        -- No more items in the set
        if next(response.set) == nil then
            break
        end

        local session = nil
        for k, v in pairs(response.set) do
            session = k
            counter = counter + 1
        end


        -- remove from global session list
        redis.call('HDEL', 'GLOBAL_STREAMING', session)
    end

    return counter
end

-- get_status_reply
-- keys = did_hash that we are getting status for
-- returns Message Pickup 3.0 Status details
local function get_status_reply(keys, args)
    -- Correct number of keys?
    if #keys ~= 1 then
        return redis.error_reply('get_status_reply: only accepts one key (recipient_did_hash)')
    end

    -- Correct number of args?
    if #args ~= 0 then
        return redis.error_reply('get_status_reply: No arguments required')
    end

    -- set response type to Version 3
    redis.setresp(3)

    local response = {}
    response.map = {}
    response.map.recipient_did = keys[1]

    -- Set the message count and total bytes
    local r = redis.call('HMGET', 'DID:' .. keys[1], 'RECEIVE_QUEUE_COUNT', 'RECEIVE_QUEUE_BYTES')
    response.map.message_count = tonumber(r[1])
    response.map.total_bytes = tonumber(r[2])

    -- Get the oldest and newest message information
    local r = redis.pcall('XINFO', 'STREAM', 'RECEIVE_Q:' .. keys[1])
    if r['err'] == nil and r.map then
        response.map.oldest_received = r.map['first-entry'] and r.map['first-entry'][1] or 0
        response.map.newest_received = r.map['last-entry'] and r.map['last-entry'][1] or 0
        response.map.queue_count = r.map['length']
    end

    -- Get live streaming status
    local r = redis.call("HEXISTS", "GLOBAL_STREAMING", keys[1])
    if r == 0 then
        response.map.live_delivery = false
    else
        response.map.live_delivery = true
    end

    return response
end

redis.register_function('store_message', store_message)
redis.register_function('delete_message', delete_message)
redis.register_function('fetch_messages', fetch_messages)
redis.register_function('clean_start_streaming', clean_start_streaming)
redis.register_function('get_status_reply', get_status_reply)
