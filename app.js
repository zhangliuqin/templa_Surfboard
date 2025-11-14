/**
 * app.js
 * 支持协议：VMess（v2rayNG）、Trojan
 * 输出：dist/index.html（Surfboard 配置）
 */

const path = require('path');
const fs = require('fs');

// 工具函数：读取、写入文件
function readSync(file) {
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
}
function writeSync(file, content) {
  fs.writeFileSync(file, content, 'utf8');
}

// 配置常量
const BUILD_DIR = 'dist';
const ENTRY_FILE = './node.txt';
const OUT_FILE = path.resolve(__dirname, BUILD_DIR, 'index.html');

// Surfboard 基础块
const managedBlock = `#!MANAGED-CONFIG https://jv20.pages.dev/index.html interval=86400 strict=true\n`;
const generalBlock = `[General]
loglevel = notify
interface = 127.0.0.1
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
ipv6 = true
dns-server = 223.5.5.5, 2400:3200::1
enhanced-mode-by-rule = true
udp-relay = true
`;

// 清理节点名称，避免非法字符
const cleanName = name => {
  let raw = decodeURIComponent((name || 'node')).replace(/[\r\n\t]/g, '').trim();
  const isLegal = /^[\w\-\u4e00-\u9fa5]+$/.test(raw);
  if (isLegal) return raw;
  raw = raw
    .replace(/[^\w\-\u4e00-\u9fa5]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
  return raw || 'node';
};

// Base64 解码（兼容 URL-safe 格式）
const decodeBase64 = s => {
  try {
    if (!s) return '';
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    return Buffer.from(s, 'base64').toString();
  } catch {
    return '';
  }
};

// 仅在有值时追加
const appendIf = (arr, key, val) => {
  if (val !== undefined && val !== null && val !== '') arr.push(`${key}=${val}`);
};

// ✅ VMess 解析器
function parseVmess(line) {
  try {
    const jsonStr = decodeBase64(line.replace('vmess://', '').trim());
    const j = JSON.parse(jsonStr);

    const name = cleanName(j.ps || j.add || 'vmess');
    const add = j.add || '';
    const port = j.port || '';
    const id = j.id || '';
    const aid = j.aid || 0;
    const net = (j.net || 'tcp').toLowerCase();
    const type = (j.type || '').toLowerCase();
    const host = j.host || '';
    const path = j.path || '';
    const sni = j.sni || host || '';
    const tls = j.tls && j.tls.toLowerCase() !== 'none';
    const scy = j.scy || '';
    const alpn = j.alpn || '';
    const fp = j.fp || '';
    const allowInsecure = j.allowInsecure ? 'true' : 'false';

    const out = [`${name} = vmess`, add, port, `username=${id}`];

    appendIf(out, 'alterId', aid);
    appendIf(out, 'cipher', scy);
    appendIf(out, 'network', net);
    appendIf(out, 'header-type', type);

    if (net === 'tcp' && type === 'http') {
      out.push('http=true');
      if (host) out.push(`headers=Host:${host}`);
    }

    if (net === 'ws') {
      out.push('ws=true');
      appendIf(out, 'ws-path', path);
      if (host) out.push(`ws-headers=Host:${host}`);
    }

    if (net === 'grpc') {
      out.push('grpc=true');
      appendIf(out, 'grpc-service-name', path);
      appendIf(out, 'grpc-mode', type || 'gun');
    }

    if (net === 'h2') {
      out.push('h2=true');
      appendIf(out, 'h2-path', path);
      appendIf(out, 'h2-host', host);
    }

    if (tls) out.push('tls=true');
    appendIf(out, 'sni', sni);
    appendIf(out, 'alpn', alpn);
    appendIf(out, 'fingerprint', fp);
    appendIf(out, 'skip-cert-verify', allowInsecure);

    return out.join(', ');
  } catch (e) {
    console.warn('⚠️ 无法解析 VMess 节点:', e.message);
    return null;
  }
}

// ✅ Trojan 解析器
function parseTrojan(line) {
  try {
    const raw = line.replace('trojan://', '').trim();
    const [cred, rest] = raw.split('@');
    const password = cred;
    const urlObj = new URL('trojan://' + rest);

    const name = cleanName(decodeURIComponent(urlObj.hash.replace('#', '')) || urlObj.hostname);
    const add = urlObj.hostname;
    const port = urlObj.port || '443';
    const sni = urlObj.searchParams.get('peer') || urlObj.hostname;
    const allowInsecure = urlObj.searchParams.get('allowInsecure') === '1' ? 'true' : 'false';
    const alpn = urlObj.searchParams.get('alpn') || '';
    const fp = urlObj.searchParams.get('fp') || '';

    const out = [`${name} = trojan`, add, port, `password=${password}`];

    out.push('tls=true');
    appendIf(out, 'sni', sni);
    appendIf(out, 'alpn', alpn);
    appendIf(out, 'fingerprint', fp);
    appendIf(out, 'skip-cert-verify', allowInsecure);

    return out.join(', ');
  } catch (e) {
    console.warn('⚠️ 无法解析 Trojan 节点:', e.message);
    return null;
  }
}

// 根据协议类型调用解析器
function parseNode(line) {
  if (line.startsWith('vmess://')) return parseVmess(line);
  if (line.startsWith('trojan://')) return parseTrojan(line);
  console.warn('⚠️ 不支持的协议:', line.slice(0, 30));
  return null;
}

// 创建输出目录
if (!fs.existsSync(path.resolve(__dirname, BUILD_DIR)))
  fs.mkdirSync(path.resolve(__dirname, BUILD_DIR));

// 读取并解析节点文件
const raw = readSync(ENTRY_FILE).trim();
const proxyLines = raw
  .split('\n')
  .map(l => l.trim())
  .filter(Boolean)
  .map(parseNode)
  .filter(Boolean)
  .map((l, i) => l.replace(/^([^=]+)=/, `$1_${i + 1} =`));

const proxyNames = proxyLines.map(l => l.split('=')[0].trim());

// 拼接配置块
const proxyBlock = `[Proxy]\n${proxyLines.join('\n')}\n`;
const groupBlock = `[Proxy Group]
🌏 自动选择 = url-test, ${proxyNames.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300, tolerance=100
🔄 故障切换 = fallback, ${proxyNames.join(', ')}, url=http://www.gstatic.com/generate_204, interval=300
🚀 节点选择 = select, ${proxyNames.join(', ')}, 🌏 自动选择, 🔄 故障切换, DIRECT
🚫 广告拦截 = select, REJECT, DIRECT
`;

const ruleBlock = `[Rule]
DOMAIN-SUFFIX,local,DIRECT
IP-CIDR,127.0.0.0/8,DIRECT
IP-CIDR,192.168.0.0/16,DIRECT
IP-CIDR,10.0.0.0/8,DIRECT
IP-CIDR,172.16.0.0/12,DIRECT
GEOIP,CN,DIRECT
DOMAIN-SUFFIX,ad.com,🚫 广告拦截
DOMAIN-KEYWORD,adservice,🚫 广告拦截
DOMAIN-SUFFIX,doubleclick.net,🚫 广告拦截
FINAL,🚀 节点选择
`;

// 写入最终结果
const result = `${managedBlock}${generalBlock}\n${proxyBlock}\n${groupBlock}\n${ruleBlock}`;
writeSync(OUT_FILE, result);

console.log(`✅ 已输出 Surfboard 配置：
→ ${OUT_FILE}
节点数：${proxyLines.length}`);