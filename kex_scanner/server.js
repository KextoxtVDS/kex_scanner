const fs = require("fs")
const path = require("path")

exports("walk", function(dir) {
    if (GetInvokingResource() !== GetCurrentResourceName()) return false
    const out = []
    const stack = [dir]
    while (stack.length > 0) {
        const current = stack.pop()
        let entries
        try {
            entries = fs.readdirSync(current, { withFileTypes: true })
        } catch (e) {
            continue
        }
        for (const entry of entries) {
            const full = path.join(current, entry.name)
            if (entry.isDirectory()) {
                stack.push(full)
            } else {
                out.push(full)
            }
        }
    }
    return out
})

exports("readFile", function(file) {
    if (GetInvokingResource() !== GetCurrentResourceName()) return false
    try {
        return fs.readFileSync(file, "utf8")
    } catch (e) {
        return false
    }
})

exports("quarantine", function(resourcePath, fileName) {
    if (GetInvokingResource() !== GetCurrentResourceName()) return false
    const results = { deleted: false, manifestStripped: false }
    try {
        const full = path.join(resourcePath, fileName)
        fs.unlinkSync(full)
        results.deleted = true
    } catch (e) {}

    for (const mf of ["fxmanifest.lua", "__resource.lua"]) {
        const mfp = path.join(resourcePath, mf)
        try {
            const src = fs.readFileSync(mfp, "utf8")
            const out = src.split(/\r?\n/).filter(line => !line.includes(fileName)).join("\n")
            if (out !== src) {
                fs.writeFileSync(mfp, out)
                results.manifestStripped = true
            }
        } catch (e) {}
    }

    return results
})
