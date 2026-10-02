# Source and contribution record

Technical source: [sleuthkit/sleuthkit](https://github.com/sleuthkit/sleuthkit) at fixed commit `7c94288dec0c9621a883da402b3552a46f916320`. License: `CPL-1.0`; the original license text and original copyright notices are preserved.

New implementation author: **dhtfish98**. This project implements the explicitly selected standalone scope below. It is not presented as original ownership of the upstream algorithms or as a full rewrite of an upstream platform. No source files have merely been renamed into the runtime package.

Scope: Bodyfile 11-column records: MD5 declaration syntax, inode/mode/user/group/size fields, bounded decimal timestamps, conflicting identity declarations and sorted a/m/c/b events; zero timestamps are omitted and equal times in a record coalesce.

The upstream entry points, format layouts and relevant default file/network/execution paths were inspected in the fixed files listed in SOURCE_MANIFEST.json. Complete new runtime files are reviewed separately; this does not imply audit of unselected upstream platform code.

Excluded upstream capabilities: SleuthKit extraction, passwd/group lookups, mactime date filtering or presentation formats, filesystem access and activity attribution.

The repository owner must verify their actual contribution and authorization before using this record in an application. No CVE, rejected-model task, CVP acceptance or personal identity evidence has been invented.
