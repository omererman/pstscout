// PSTScout M1: metadata-only by default; no file writes or network calls.
// Uses the MIT-licensed `pst-extractor` project (epfromer/pst-extractor).
import { PSTFile } from 'pst-extractor';
import { writeSync } from 'node:fs';

const [, , source, rawLimit, rawBody, rawCap] = process.argv;
const limit = Number(rawLimit);
const includeBody = rawBody === '1';
const bodyCap = Number(rawCap);
if (!source || !Number.isSafeInteger(limit) || limit < 0 ||
    !Number.isSafeInteger(bodyCap) || bodyCap < 1 || bodyCap > 1024 * 1024) {
  process.stderr.write('E_ARGUMENTS\n');
  process.exit(2);
}
const safe = (fn, fallback = null) => { try { const x = fn(); return x == null ? fallback : x; } catch { return fallback; } };
const asDate = value => safe(() => value?.toISOString(), null);
const asNumber = value => {
  const number = safe(() => Number(value?.toNumber?.() ?? value ?? 0), 0);
  return Number.isFinite(number) && number >= 0 ? Math.floor(number) : 0;
};
const emit = record => {
  const data = Buffer.from(JSON.stringify(record) + '\n', 'utf8');
  let position = 0;
  while (position < data.length) position += writeSync(1, data, position, data.length - position);
};
function recipientsFromHeaders(headers) {
  const str = String(headers || '').slice(0, 32768);
  const fields = [];
  for (const key of ['To', 'Cc', 'Bcc']) {
    const match = str.match(new RegExp(`^${key}:\\s*(.+(?:\\r?\\n[ \\t].+)*)`, 'im'));
    if (match) fields.push(`${key}: ${match[1].replace(/\r?\n\s+/g, ' ')}`);
  }
  return fields;
}
function getBody(msg) {
  if (!includeBody) return { body: '', body_truncated: false };
  let text = safe(() => msg.body, '');
  if (!text) {
    const html = safe(() => msg.bodyHTML, '');
    // Plain-text preview, not an HTML renderer; no remote resources are loaded.
    text = String(html).replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<[^>]*>/g, ' ').replace(/&nbsp;/gi, ' ').replace(/&amp;/gi, '&');
  }
  text = String(text || '');
  const truncated = text.length > bodyCap;
  return { body: text.slice(0, bodyCap), body_truncated: truncated };
}
function getAttachments(msg) {
  const n = Math.min(asNumber(safe(() => msg.numberOfAttachments, 0)), 100000);
  const result = [];
  for (let i = 0; i < n; i++) {
    const att = safe(() => msg.getAttachment(i));
    if (!att) continue;
    result.push({ index: i, name: safe(() => att.longFilename, '') ||
      safe(() => att.filename, '') || `attachment_${i}`,
      size: asNumber(safe(() => att.filesize, 0) || safe(() => att.size, 0)) });
  }
  return result;
}
let pst;
try {
  pst = new PSTFile(source);
} catch {
  process.stderr.write('E_PST_OPEN\n');
  process.exit(3);
}
let messages = 0;
let folders = 0;
let skipped = 0;
// Fixed aggregate counters only: never expose private fields or exception text.
const skippedByReason = {
  message_read_error: 0,
  empty_message: 0,
  invalid_identifier: 0,
  message_processing_error: 0,
  folder_read_error: 0,
};
function noteSkipped(reason) { skipped++; skippedByReason[reason]++; }
// Report only aggregate metadata flags. Never emit folder names, paths or raw
// parser errors: pst-extractor can include private folder names in its errors.
const folderErrorHints = {
  no_subfolders: 0,
  subfolders_expected: 0,
  unknown: 0,
};
function noteFolderReadError(folder) {
  noteSkipped('folder_read_error');
  const flag = safe(() => folder.hasSubfolders, null);
  if (flag === false) folderErrorHints.no_subfolders++;
  else if (flag === true) folderErrorHints.subfolders_expected++;
  else folderErrorHints.unknown++;
}
let limited = false;
const skipNames = new Set(['SPAM Search Folder 2', 'ItemProcSearch', 'PST Conversation Lookup']);
function visit(folder, parents) {
  folders++;
  const name = String(safe(() => folder.displayName, '') || '<unnamed>');
  const segments = [...parents, name];
  const folderPath = segments.join('/');
  const count = asNumber(safe(() => folder.contentCount, 0));
  for (let i = 0; i < count; i++) {
    if (limit > 0 && messages >= limit) { limited = true; return false; }
    let msg;
    try { msg = folder.getNextChild(); } catch { noteSkipped('message_read_error'); continue; }
    if (!msg) { noteSkipped('empty_message'); continue; }
    try {
      const identifier = safe(() => msg.descriptorNodeId?.toString(), '');
      if (!identifier || !/^\d+$/.test(identifier)) { noteSkipped('invalid_identifier'); continue; }
      const body = getBody(msg);
      emit({ type: 'message', identifier, folder_path: folderPath,
        subject: safe(() => msg.subject, '') || '',
        sender_name: safe(() => msg.senderName, '') || '',
        sender_email: safe(() => msg.senderEmailAddress, '') || '',
        recipients: recipientsFromHeaders(safe(() => msg.transportMessageHeaders, '')),
        delivery_time: asDate(safe(() => msg.messageDeliveryTime)),
        submit_time: asDate(safe(() => msg.clientSubmitTime)),
        ...body, attachments: getAttachments(msg) });
      messages++;
    } catch { noteSkipped('message_processing_error'); }
  }
  let subFolders;
  try { subFolders = folder.getSubFolders() || []; } catch { noteFolderReadError(folder); return true; }
  for (const sub of subFolders) {
    if (skipNames.has(safe(() => sub.displayName, ''))) continue;
    if (!visit(sub, segments)) return false;
  }
  return true;
}
try {
  visit(pst.getRootFolder(), []);
  emit({ type: 'summary', messages, folders, skipped, skipped_by_reason: skippedByReason, folder_error_hints: folderErrorHints, limited });
} catch {
  process.stderr.write('E_PST_PARSE\n');
  process.exitCode = 4;
} finally {
  try { pst.close(); } catch { /* read-only cleanup */ }
}
