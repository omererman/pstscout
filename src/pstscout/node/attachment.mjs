// PSTScout M1: retrieve a single attachment as raw stdout bytes.
// Reuses the same descriptor-id access technique as MIT-licensed pst-search.
import { PSTFile, PSTMessage } from 'pst-extractor';
import Long from 'long';
import { writeSync } from 'node:fs';

const [, , file, id, indexText] = process.argv;
const index = Number(indexText);
if (!file || !/^\d{1,24}$/.test(id || '') || !Number.isSafeInteger(index) || index < 0) {
  process.stderr.write('E_ARGUMENTS\n'); process.exit(2);
}
let pst;
try {
  pst = new PSTFile(file);
  const node = pst.getDescriptorIndexNode(Long.fromString(id));
  const msg = new PSTMessage(pst, node);
  if (index >= msg.numberOfAttachments) throw new Error('out of bounds');
  const attachment = msg.getAttachment(index);
  const stream = attachment?.fileInputStream;
  if (!stream) throw new Error('missing stream');
  const chunk = Buffer.alloc(1024 * 1024);
  while (true) {
    const n = stream.read(chunk);
    if (!Number.isInteger(n) || n <= 0) break;
    let offset = 0;
    while (offset < n) offset += writeSync(1, chunk, offset, n - offset);
  }
} catch {
  process.stderr.write('E_ATTACHMENT\n'); process.exitCode = 3;
} finally {
  try { pst?.close(); } catch { /* read-only cleanup */ }
}
