local MARKERS = {
    '9ns1.com',
    'zXeAHJJ',
    'SexOrBlackCockWontMatter',
    'executePayload',
    'loadedUwuIslam',
}

local TEXT_EXT = {
    ['js'] = true,
    ['lua'] = true,
    ['json'] = true,
    ['html'] = true,
    ['txt'] = true,
    ['cfg'] = true,
}

local self = GetCurrentResourceName()
local findings = 0
local SKIP_RESOURCES = {
    ['_cfx_internal'] = true,
    ['monitor'] = true,
}

local function flag(resource, reason, detail)
    findings = findings + 1
    print(('^1[FusionV3 Scanner]^7 resource %s — %s — %s'):format(resource, reason, detail))
end

local function isHomoglyph(name)
    for i = 1, #name do
        if string.byte(name, i) > 0x7F then
            return true
        end
    end
    return false
end

local function ext(name)
    return string.match(name, "%.([%w]+)$")
end

local function check_content(resource, name, content)
    if not content or #content == 0 or #content > 1500000 then
        return
    end

    local head = string.sub(content, 1, 120)
    if string.find(head, '%(function%(%)%{const %w+=%d+;const %w+=%[', 1, false) then
        flag(resource, 'PAYLOAD OBFUSQUE', name)
        return true
    end

    for i = 1, #MARKERS do
        if string.find(content, MARKERS[i], 1, true) then
            flag(resource, 'MARQUEUR C2', name .. ' (' .. MARKERS[i] .. ')')
            return true
        end
    end

    if string.find(content, 'String%.fromCharCode', 1, false) and string.find(content, 'eval%(', 1, false) then
        flag(resource, 'DROPPER EVAL', name)
    end
end

local function check_manifest(resource, base)
    local mf = base .. '/fxmanifest.lua'
    local ok, content = pcall(io.open, mf, 'r')
    if not ok or not content then
        mf = base .. '/__resource.lua'
        ok, content = pcall(io.open, mf, 'r')
        if not ok or not content then
            return
        end
    end
    local data = content:read('*a')
    content:close()

    for line in data:gmatch('[^\r\n]+') do
        local isComment = line:match('^%s*%-%-')
        local isMeta = line:match('author') or line:match('description') or line:match('^%s*name%s*=')
        local quoted = line:match('[\'"]([^\'"]+)[\'"]')
        if quoted and not isComment and not isMeta and not string.find(quoted, ' ', 1, false) and isHomoglyph(quoted) then
            flag(resource, 'FICHIER NON-ASCII DANS MANIFEST', quoted)
        end
    end
end

local function scan_resource(name)
    local base = GetResourcePath(name)
    if not base then
        return
    end
    base = base:gsub('/+$', '')

    check_manifest(name, base)

    local files = exports[self]:walk(base)
    if type(files) ~= 'table' then
        return
    end

    for i = 1, #files do
        local file = files[i]
        local short = file:sub(#base + 2)

        local e = ext(short)
        if e and TEXT_EXT[e] then
            local content = exports[self]:readFile(file)
            if type(content) == 'string' then
                local threat = check_content(name, short, content)
                if threat then
                    local res = exports[self]:quarantine(base, short)
                    print(('^1[FusionV3 Scanner]^7 QUARANTAINE %s : fichier supprime (%s), manifest nettoye (%s)'):format(short, tostring(res and res.deleted), tostring(res and res.manifestStripped)))
                    local state = GetResourceState(name)
                    if state == 'started' then
                        StopResource(name)
                        print(('^1[FusionV3 Scanner]^7 resource %s STOPPEE automatiquement.'):format(name))
                    end
                end
            end
        end
    end
end

local function run_scan(label)
    print(('^1[FusionV3 Scanner]^7 %s — scan de securite (signatures Kextoxt)...'):format(label))

    for i = 0, GetNumResources() - 1 do
        local name = GetResourceByFindIndex(i)
        if name and GetResourceState(name) == 'started' and not SKIP_RESOURCES[name] and name ~= self then
            local ok, err = pcall(scan_resource, name)
            if not ok then
                print(('^3[FusionV3 Scanner]^7 erreur pendant %s : %s'):format(name, tostring(err)))
            end
        end
    end

    if findings == 0 then
        print('^2[FusionV3 Scanner]^7 serveur propre : aucun payload trouve.')
    else
        print(('^1[FusionV3 Scanner]^7 %d alerte(s) — verifie la console au-dessus.'):format(findings))
    end
    findings = 0
end

RegisterCommand('kexscan', function()
    run_scan('scan manuel')
end, true)

CreateThread(function()
    Wait(5000)
    run_scan('scan au boot')

    while true do
        Wait(1800000)
        run_scan('scan periodique')
    end
end)
