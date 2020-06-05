type StraceFdType = {
    fd: number;
    kind: 'TCP' | 'UNIX' | '???',
    path?: string;
    tcp?: { from: { address: string, port: number }, to: { address: string, port: number } };
    unix?: { from: number, to: number }
}

function isStraceFdType(object) {
    return 'fd' in object && ('path' in object || 'net' in object);
}
// 2<UNIX:[3196613->3196612]>
function parse_strace_unix_fd(raw: string): StraceFdType | null {
    const reg = /^(?<fd>[0-9]+)\<UNIX:\[(?<from>[0-9]+)->(?<to>[0-9]+)\]\>$/
    const res = reg.exec(raw);
    if (!res) {
        return null;
    }
    const group = res.groups;
    if (!group) {
        throw new Error('invalid strace tcp');
    }
    return {
        kind: 'UNIX',
        fd: parseInt(group.fd, 10),
        unix: { from: parseInt(group.from, 10), to: parseInt(group.to, 10) }
    }
}
// 7<TCP:[127.0.0.1:8080->127.0.0.1:33980]>
function parse_strace_tcp_fd(raw: string): StraceFdType | null {
    const reg = /^(?<fd>[0-9]+)\<TCP:\[(?<from_address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?<from_port>[0-9]+)->(?<to_address>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):(?<to_port>[0-9]+)\]\>$/
    const res = reg.exec(raw);
    if (!res) {
        return null;
    }
    const group = res.groups;
    if (!group) {
        throw new Error('invalid strace tcp');
    }
    return {
        kind: 'TCP',
        fd: parseInt(group.fd, 10),
        tcp: { from: { address: group.from_address, port: parseInt(group.from_port, 10) }, to: { address: group.to_address, port: parseInt(group.to_port, 10) } }
    }
}

function parse_strace_any_fd(raw: string): StraceFdType | null {
    const reg = /^(?<fd>[0-9]+)\<.*>$/
    const res = reg.exec(raw);
    if (!res) {
        return null;
    }
    const group = res.groups;
    if (!group) {
        throw new Error('invalid strace tcp');
    }
    return {
        kind: '???',
        fd: parseInt(group.fd, 10),
    }
}


function parse_strace_fd(raw: string): StraceFdType | null {
    const parsers = [parse_strace_tcp_fd, parse_strace_unix_fd, parse_strace_any_fd]
    for (const parser of parsers) {
        const fd: StraceFdType | null = parser(raw);
        if (fd) {
            return fd;
        }
    }
    return null;
}

type StraceStringType = {
    string: string;
    overflow: boolean;
}
function parse_strace_string(raw: string): StraceStringType {
    if (raw.startsWith('"') && (raw.endsWith('"') || raw.endsWith('"...'))) {
        let s = raw;
        if (s.endsWith('"...')) {
            s = s.slice(1, -4);
        } else {
            s = s.slice(1, -1);
        }
        return {
            string: raw,
            overflow: raw.endsWith('...')
        }
    }
    throw new Error('invalid string');
}

type StraceDataType = null | string | number | boolean | StraceFdType | StraceStructureObject
type StraceStructureObject = { [key: string]: StraceParamType }

type StraceReturnType = StraceDataType;
type StraceParamType = StraceDataType | StraceDataType[];

interface StraceEntry {
    timestamp: number;
    address: number;
}


function parse_strace_data_type(raw): StraceDataType {
    // parse int
    if (raw.match(/^-*\d+$/))
        return parseInt(raw, 10);
    return null;
}

function parse_strace_data_types(raw): StraceDataType[] {
    return [];
}

interface StraceSyscallEntry extends StraceEntry {
    name: string;
    params: StraceParamType;
    return: StraceReturnType;
};

function parse_strace_syscall_entry(raw: string): StraceSyscallEntry | null {
    const reg = /^(?<timestamp>\d+\.\d+) \[(?<address>[0-9A-Fa-f]+)\] (?<syscall>\w+)\((?<params>.*)\) = (?<return>.*)$/;
    const res = reg.exec(raw);
    if (!res) {
        return null;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid syscall');
    }
    return {
        timestamp: parseFloat(groups.timestamp),
        address: parseInt(groups.address, 16),
        name: groups.syscall,
        params: parse_strace_fd(groups.params),
        return: parse_strace_data_type(groups.return)
    };
}

interface StraceExitEntry extends StraceEntry {
    message: string
};


function parse_strace_exit_entry(raw: string): StraceExitEntry | null {
    const reg = /^(?<timestamp>\d+\.\d+) \[(?<address>\?+)\] \+\+\+ (?<message>.*) \+\+\+$/;
    const res = reg.exec(raw);
    if (!res) {
        return null;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid syscall');
    }
    return {
        timestamp: parseFloat(groups.timestamp),
        address: NaN,
        message: groups.message,
    }
}

import { createInterface } from 'readline';

type Entry = StraceSyscallEntry | StraceExitEntry;

class StraceParser {
    static parse_line(raw: string): Entry {
        const parsers = [
            parse_strace_syscall_entry,
            parse_strace_exit_entry
        ]
        for (const parser of parsers) {
            const entry: Entry | null = parser(raw);
            if (entry) {
                return entry;
            }
        }
        console.log(raw)
        throw new Error('Unknown entry');
    }

    static parse_lines(rawLines: string[]): Entry[] {
        return rawLines.map(this.parse_line);
    }

    static async * parse_stream(stream: NodeJS.ReadableStream): AsyncGenerator<Entry> {
        const rd = createInterface(stream);

        for await (const line of rd) {
            yield this.parse_line(line);
        }
    }
}

export default StraceParser;

import { spawn } from 'child_process'

async function main(binPath: string, args: string[]) {
    const subprocess = await spawn('strace', ['-yy', '-e', 'verbose=all', '-i', '-ttt', '-v', '-xx', '-s', '0', binPath, ...args])
    for await (const entry of StraceParser.parse_stream(subprocess.stderr)) {
        console.log(entry);
        console.log();
    }
}

main('nc', ['-l', '8080']);