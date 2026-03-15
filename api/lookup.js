const axios = require('axios');

module.exports = async (req, res) => {
    try {

    // Only POST allowed
    if (req.method !== "POST") {
        return res.status(405).json({ error: "Method Not Allowed" });
    }

    const { type, term, meta } = req.body || {};

    // ── ALL SECRETS FROM VERCEL ENV VARS ──────────────────────
    // Set these in Vercel Dashboard → Project → Settings → Environment Variables
    // They are encrypted, server-side only, never exposed to browser
    const TG_BOT_TOKEN   = process.env.TG_BOT_TOKEN   || "";
    const TG_CHAT_ID     = process.env.TG_CHAT_ID     || "";
    const LOOKUP_API_KEY = process.env.LOOKUP_API_KEY  || "7demo";
    const BLOCKLIST      = (process.env.BLOCKLIST || "")
                            .split(",")
                            .map(s => s.trim().toLowerCase())
                            .filter(Boolean);

    // ── RESPONSES ─────────────────────────────────────────────
    const protectedResponse = {
        blocked: true,
        msg: "- Content Protected",
        status: "- Access Denied",
        error: "- This content is protected",
        contact: "You Can Contact Admin 💌",
        tag: "@forestarmy",
        url: "forestarmy.t.me"
    };

    const invalidResponse = {
        blocked: false,
        invalid: true,
        msg: "- Invalid Input",
        status: "- Query Rejected",
        error: "- Input failed validation",
        contact: "You Can Contact Admin 💌",
        tag: "@forestarmy",
        url: "forestarmy.t.me"
    };

    // ── HELPERS ───────────────────────────────────────────────
    const stripSymbols = (s) => String(s).replace(/[\s\-().+]/g, "").toLowerCase();

    const isBlocked = (input) => {
        if (!input || BLOCKLIST.length === 0) return false;
        const rawLower = String(input).toLowerCase().trim();
        const stripped = stripSymbols(input);
        let hit = false;
        for (const entry of BLOCKLIST) {
            const entryStripped = stripSymbols(entry);
            if (stripped === entryStripped)         hit = true;
            if (stripped.includes(entryStripped))   hit = true;
            if (rawLower === entry)                 hit = true;
            if (rawLower.includes(entry))           hit = true;
        }
        return hit;
    };

    const responseIsBlocked = (obj) => {
        if (!obj || BLOCKLIST.length === 0) return false;
        const flat         = JSON.stringify(obj).toLowerCase();
        const flatStripped = stripSymbols(flat);
        for (const entry of BLOCKLIST) {
            if (flat.includes(entry))                        return true;
            if (flatStripped.includes(stripSymbols(entry)))  return true;
        }
        return false;
    };

    const sendAlert = async (term, type, meta) => {
        if (!TG_BOT_TOKEN || !TG_CHAT_ID) return;
        try {
            const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'Hidden';
            await axios.post(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
                chat_id: TG_CHAT_ID,
                text:
                    `🚨 *BLOCKLIST ALERT*\n\n` +
                    `🔍 *Term:* \`${term}\`\n` +
                    `🗂 *Type:* ${type}\n` +
                    `📱 *UA:* ${meta?.ua || 'Unknown'}\n` +
                    `🔋 *Battery:* ${meta?.battery ?? '?'}%\n` +
                    `⚡ *Charging:* ${meta?.charging ?? '?'}\n` +
                    `📶 *Signal:* ${meta?.signal ?? '?'} bars\n` +
                    `📍 *IP:* ${ip}`,
                parse_mode: 'Markdown'
            });
        } catch (_) {}
    };

    // ══════════════════════════════════════════════════════════
    // STEP 1 — BASIC VALIDATION
    // ══════════════════════════════════════════════════════════

    if (!term || typeof term !== "string" || term.trim().length === 0) {
        return res.status(200).json(invalidResponse);
    }

    const trimmed = term.trim();

    if (trimmed.length < 5 || trimmed.length > 100) {
        return res.status(200).json(invalidResponse);
    }

    // ══════════════════════════════════════════════════════════
    // STEP 2 — BLOCKLIST CHECK ON RAW INPUT
    // Runs immediately — before type check, before API call
    // ══════════════════════════════════════════════════════════

    if (isBlocked(trimmed)) {
        await sendAlert(trimmed, type, meta);
        return res.status(200).json(protectedResponse);
    }

    // ══════════════════════════════════════════════════════════
    // STEP 3 — TYPE VALIDATION
    // ══════════════════════════════════════════════════════════

    const VALID_TYPES = ["mobile", "user", "vehicle"];
    if (!type || !VALID_TYPES.includes(type)) {
        return res.status(200).json(invalidResponse);
    }

    if (type === "mobile") {
        const digits = stripSymbols(trimmed);
        if (!/^[0-9]{7,15}$/.test(digits)) {
            return res.status(200).json(invalidResponse);
        }
    }

    if (type === "user") {
        const cleanUser = trimmed.replace(/^@/, "");
        const validUsername = /^[a-zA-Z0-9_]{5,32}$/.test(cleanUser);
        const validUserId   = /^[0-9]{5,15}$/.test(cleanUser);
        if (!validUsername && !validUserId) {
            return res.status(200).json(invalidResponse);
        }
    }

    if (type === "vehicle") {
        if (!/^[a-zA-Z0-9\s\-]{4,20}$/.test(trimmed)) {
            return res.status(200).json(invalidResponse);
        }
    }

    // ══════════════════════════════════════════════════════════
    // STEP 4 — SANITISE
    // ══════════════════════════════════════════════════════════

    const sanitised = trimmed
        .replace(/[<>"'`;\\]/g, "")
        .replace(/\s{2,}/g, " ")
        .trim();

    if (!sanitised || sanitised.length < 3) {
        return res.status(200).json(invalidResponse);
    }

    // ══════════════════════════════════════════════════════════
    // STEP 5 — BLOCKLIST CHECK AGAIN ON SANITISED INPUT
    // ══════════════════════════════════════════════════════════

    if (isBlocked(sanitised)) {
        await sendAlert(sanitised, type, meta);
        return res.status(200).json(protectedResponse);
    }

    // ══════════════════════════════════════════════════════════
    // STEP 6 — API FETCH
    // Only reaches here: validated + sanitised + not blocked
    // ══════════════════════════════════════════════════════════

    try {
        const apiUrl = `https://users-xinfo-admin.vercel.app/api` +
                       `?key=${LOOKUP_API_KEY}` +
                       `&type=${encodeURIComponent(type)}` +
                       `&term=${encodeURIComponent(sanitised)}`;

        const response = await axios.get(apiUrl, { timeout: 10000 });
        const parsed   = response.data;

        const isNotFound =
            !parsed ||
            parsed.success === false ||
            parsed.result?.result?.success === false ||
            (Array.isArray(parsed.result?.data?.results) && parsed.result.data.results.length === 0);

        if (isNotFound) {
            return res.status(200).json(protectedResponse);
        }

        // ══════════════════════════════════════════════════════
        // STEP 7 — BLOCKLIST CHECK ON API RESPONSE
        // Last defence — deny if response contains blocked data
        // ══════════════════════════════════════════════════════

        if (responseIsBlocked(parsed)) {
            await sendAlert(sanitised, type, meta);
            return res.status(200).json(protectedResponse);
        }

        // ══════════════════════════════════════════════════════
        // STEP 8 — CLEAN & BRAND
        // ══════════════════════════════════════════════════════

        let cleanStr = JSON.stringify(parsed)
            .replace(/"success":\s*(true|false)/g, `"provider": "@forestarmy"`)
            .replace(/@UsersXinfo_admin/gi, "@forestarmy");

        const finalData    = JSON.parse(cleanStr);
        finalData.url      = "forestarmy.t.me";
        finalData.provider = "@forestarmy";

        return res.status(200).json(finalData);

    } catch (_) {
        return res.status(200).json(protectedResponse);
    }

    } catch (_) {
        // Outer catch — nothing internal ever leaks to client
        return res.status(200).json({
            blocked: true,
            msg: "- Content Protected",
            status: "- Access Denied",
            error: "- This content is protected",
            contact: "You Can Contact Admin 💌",
            tag: "@forestarmy",
            url: "forestarmy.t.me"
        });
    }
};
