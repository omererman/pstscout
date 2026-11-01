"""M3.1 ephemeral encrypted-source search, without unencrypted disk writes."""
from __future__ import annotations

import argparse
import getpass
import sqlite3
from pathlib import Path

from .search_index import VolatileSearchIndex, IndexErrorM3
from .vault_bridge import iter_messages, BridgeError


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog='python -m pstscout.search_cli',
            description='M3.1 in-memory FTS5 prototype; index disappears on exit')
    p.add_argument('--archive', required=True, type=Path, help='An existing .pstsc archive')
    p.add_argument('--max-messages', type=int, default=200,
                   help='M3.1 RAM safety: 200 by default; 0 for all messages')
    p.add_argument('--body-cap', type=int, default=65536,
                   help='Maximum plaintext body characters per message (<= 1048576)')
    p.add_argument('--show-results', action='store_true',
                   help='Show private subject/sender/folder in terminal')
    p.add_argument('--metadata-only', action='store_true',
                   help='M3 diagnostic: index metadata only, without reading email bodies')
    args = p.parse_args(argv)
    if args.max_messages < 0 or not 1 <= args.body_cap <= 1048576:
        p.error('Invalid message limit or body cap')
    counts = {'messages': 0, 'summaries': 0}

    def counted_events(events):
        for item in events:
            if isinstance(item, dict):
                if item.get('type') == 'message':
                    counts['messages'] += 1
                elif item.get('type') == 'summary':
                    counts['summaries'] += 1
            yield item

    try:
        password = getpass.getpass('Archive password (not stored): ')
        with VolatileSearchIndex() as index:
            source = iter_messages(args.archive, password, limit=args.max_messages,
                                   show_body=not args.metadata_only, body_cap=args.body_cap)
            summary = index.build(counted_events(source), archive_id='local-archive')
            print('M3 MEMORY INDEX: messages={0} folders={1} skipped={2} limited={3} body_truncated={4}'.format(
                summary.indexed, summary.folders_reported, summary.skipped_reported,
                summary.limited, summary.body_truncated))
            print('WARNING: M3.1 is RAM-only. No permanent index; rebuilt on next launch.')
            if args.metadata_only:
                print('DIAGNOSTIC MODE: message bodies were NOT indexed.')
            if summary.skipped_reported or summary.body_truncated:
                print('WARNING: Some source items or body text may be unavailable in search results.')
            while True:
                try:
                    phrase = input('Search text (empty to quit): ').strip()
                except (EOFError, KeyboardInterrupt):
                    print('\nSearch session ended')
                    break
                if not phrase:
                    break
                try:
                    hits = index.search(phrase)
                    print(f'MATCHES_SHOWN: {len(hits)} (maximum 20; full match count not calculated)')
                    if args.show_results:
                        for h in hits:
                            print(f'ID={h.message_id} | {h.sent_at} | {h.subject} | {h.sender_email} | {h.folder}')
                except (ValueError, IndexErrorM3):
                    print('Invalid search phrase; please try a shorter simple phrase')
        return 0
    except BridgeError:
        print('M3 ERROR [PST_READER]: encrypted PST stream failed or ended early; '
              f'messages_seen={counts["messages"]}; summaries_seen={counts["summaries"]}; '
              'no partial index persisted')
        return 1
    except IndexErrorM3 as exc:
        # Only show messages originating from a fixed allowlist in our own code.
        # A future upstream error might accidentally contain email text or paths.
        safe_details = {
            'SQLite FTS5 is not available in this Python runtime',
            'The in-memory index is closed',
            'M3 received a message without a valid identifier',
            'M3 received invalid attachment metadata',
            'M3 received invalid recipient metadata',
            'Unexpected PST event type',
            'PST helper emitted a message after summary',
            'Unexpected PST event in index stream',
            'Incomplete PST scan; in-memory index changes rolled back',
        }
        detail = str(exc) if str(exc) in safe_details else 'Index validation or consistency error'
        print(f'M3 ERROR [INDEX_VALIDATION]: {detail}; '
              f'messages_seen={counts["messages"]}; summaries_seen={counts["summaries"]}; '
              'no partial index persisted')
        return 1
    except sqlite3.Error:
        print(f'M3 ERROR [SQLITE]: SQLite/FTS5 failure; messages_seen={counts["messages"]}; '
              'no partial index persisted')
        return 1
    except UnicodeError:
        print(f'M3 ERROR [TEXT_ENCODING]: unsupported text encoding; '
              f'messages_seen={counts["messages"]}; no partial index persisted')
        return 1
    except OSError as exc:
        # Only numeric OS error codes; never expose raw exceptions or filenames.
        winerror = getattr(exc, 'winerror', None)
        errno = getattr(exc, 'errno', None)
        print(f'M3 ERROR [FILE_IO]: errno={errno} winerror={winerror}; '
              f'messages_seen={counts["messages"]}; no partial index persisted')
        return 1
    except KeyboardInterrupt:
        print('M3 ERROR [INTERRUPTED]: index build cancelled; no partial index persisted')
        return 130
    except Exception:
        # Contain unexpected third-party errors rather than exposing sensitive
        # PST metadata, body, archive names, passwords or parser tracebacks.
        print(f'M3 ERROR [UNEXPECTED]: unable to build search index; '
              f'messages_seen={counts["messages"]}; no partial index persisted')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
