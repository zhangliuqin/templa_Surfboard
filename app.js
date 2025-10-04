let path = require('path');
let util = require('./util');
let readSync = util.readSync;
let writeSync = util.writeSync;

let BUILD_DIR = 'dist';
let ENTRY_FILE = './node.txt';
let str = readSync(ENTRY_FILE);

// 你可以根据需要修改 [General] 区块内容
let generalBlock = `[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = false
dns-server = system, 223.5.5.5
exclude-simple-hostnames = true
enhanced-mode-by-rule = true
`;

function parseVmess(item) {
    try {
        let b64 = item.replace('vmess://', '').trim();
        let json = Buffer.from(b64, 'base64').toString('utf8');
        let obj = JSON.parse(json);
        let out = [];
        out.push(`${obj.ps || obj.add} = vmess, ${obj.add}, ${obj.port}, username=${obj.id}`);
        if (obj.net === "ws" || obj.net === "websocket") {
            out[0] += `, ws=true`;
            if (obj.path) out[0] += `, ws-path=${obj.path}`;
            if (obj.host) out[0] += `, ws-headers=Host:${obj.host}`;
        }
        if (obj.tls === "tls") out[0] += `, tls=true`;
        return out[0];
    } catch {
        return null;
    }
}

function parseSS(item) {
    try {
        let content = item.replace('ss://', '').trim();
        let [base, namePart] = content.split('#');
        let name = namePart ? decodeURIComponent(namePart) : "ss";
        let [main, params] = base.split('?');
        let decoded = Buffer.from(main, 'base64').toString('utf8');
        let [methodPwd, serverPort] = decoded.split('@');
        let [method, password] = methodPwd.split(':');
        let [server, port] = serverPort.split(':');
        let out = `${name} = ss, ${server}, ${port}, method=${method}, password=${password}`;
        return out;
    } catch {
        return null;
    }
}

function parseTrojan(item) {
    try {
        let url = item.replace('trojan://', '').trim();
        let [main, params] = url.split('?');
        let [passwordAtHost, ...rest] = main.split('@');
        let password = passwordAtHost;
        let [server, port] = rest.join('@').split(':');
        let out = `${server}-trojan = trojan, ${server}, ${port}, password=${password}`;
        if (params) {
            params.split('&').forEach(kv => {
                let [k, v] = kv.split('=');
                out += `, ${k}=${v}`;
            });
        }
        return out;
    } catch {
        return null;
    }
}

function parseVless(item) {
    try {
        let url = item.replace('vless://', '').trim();
        let [main, params] = url.split('?');
        let [uuidAtServer, ...rest] = main.split('@');
        let uuid = uuidAtServer;
        let [server, port] = rest.join('@').split(':');
        let name = server + '-vless';
        let out = `${name} = vless, ${server}, ${port}, uuid=${uuid}`;
        if (params) {
            params.split('&').forEach(kv => {
                let [k, v] = kv.split('=');
                out += `, ${k}=${v}`;
            });
        }
        return out;
    } catch {
        return null;
    }
}

function parseNode(item) {
    if(item.startsWith('vmess://')) return parseVmess(item);
    if(item.startsWith('ss://')) return parseSS(item);
    if(item.startsWith('trojan://')) return parseTrojan(item);
    if(item.startsWith('vless://')) return parseVless(item);
    return null;
}

let rawList = str.split('\n').map(l => l.trim()).filter(Boolean);
let proxyLines = [];
for(let item of rawList) {
    let parsed = parseNode(item);
    if(parsed) proxyLines.push(parsed);
}

let proxyBlock = `[Proxy]\n${proxyLines.join('\n')}\n`;

let surfboardText = `${generalBlock}\n${proxyBlock}`;

writeSync(path.resolve(__dirname, BUILD_DIR, 'index.html'), surfboardText);

console.log(`已输出 Surfboard [General] 和 [Proxy] 格式到 dist/index.html，节点数：${proxyLines.length}`);
