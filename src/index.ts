
function decodeStraceHexString(encoded: string): string {
    return encoded.replace(/\\x([0-9A-Fa-f]{2,4})/g, (data) => {
        return String.fromCharCode(parseInt(data.slice(-2), 16));
    });
}

type StraceFdType = {
    fd: number;
    type: string;
}

function parse_strace_fd(raw: string): StraceFdType | undefined {
    const reg = /^(?<fd>-?[0-9]+)<(?<type>.*):\[(?<params>.*)\]>$/;
    const res = reg.exec(raw);
    if (!res) {
        return undefined;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid fd');
    }
    return {
        fd: parseInt(groups.fd, 10),
        type: groups.type
    }
}

function parse_strace_array_fd(raw: string): StraceFdType[] | undefined {
    const reg = /^\[(?<fds>.*)\]$/;
    const res = reg.exec(raw);
    if (!res) {
        return undefined;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid fd');
    }
    // console.log(groups.fds)
    const elems = groups.fds.split(' ').map(parse_strace_fd)
    if (elems.find((e) => e === undefined))
        return undefined;
    return elems.filter((e) => e !== undefined) as StraceFdType[];
}

type StraceStringType = {
    string: string;
    overflow: boolean;
}

function parse_strace_string(raw: string): StraceStringType | undefined {
    if (raw.startsWith('"') && (raw.endsWith('"') || raw.endsWith('"...'))) {
        let s = raw;
        if (s.endsWith('"...')) {
            s = s.slice(1, -4);
        } else {
            s = s.slice(1, -1);
        }
        return {
            string: decodeStraceHexString(s),
            overflow: raw.endsWith('...')
        }
    }
    return undefined;
}

type StraceDataType = null | string | number | boolean | StraceFdType | StraceFdType[] | StraceStringType | StraceStructureObject
type StraceStructureObject = { [key: string]: StraceParamType }

type StraceReturnType = StraceDataType;
type StraceParamType = StraceDataType | StraceDataType[];

interface StraceEntry {
    timestamp: number;
    address: number;
    raw: string;
}


function parse_strace_number(raw: string): number | undefined {
    if (raw.match(/^-?\d$/))
        return parseInt(raw, 10);
    return undefined;
}

function parse_strace_null(raw: string): null | undefined {
    if (raw.match(/^NULL$/))
        return null
    return undefined;
}

function parse_strace_data_type(raw): StraceDataType {
    const parsers = [
        parse_strace_number,
        parse_strace_null,
        parse_strace_string,
        parse_strace_fd,
        parse_strace_array_fd,
    ];
    for (const parser of parsers) {
        const type = parser(raw);
        if (type !== undefined) {
            return type;
        }
    }
    return raw;
}

function parse_strace_data_types(raw): StraceDataType[] {
    return raw.split(', ').map(parse_strace_data_type);
}

interface StraceSyscallEntry extends StraceEntry {
    name: string;
    params: StraceParamType;
    return: StraceReturnType;
};

function parse_strace_syscall_entry(raw: string): StraceSyscallEntry | undefined {
    const reg = /^(?<timestamp>\d+\.\d+) \[(?<address>[0-9A-Fa-f]+)\] (?<syscall>\w+)\((?<params>.*)\) = (?<return>.*)$/;
    const res = reg.exec(raw);
    if (!res) {
        return undefined;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid syscall');
    }
    return {
        raw,
        timestamp: parseFloat(groups.timestamp),
        address: parseInt(groups.address, 16),
        name: groups.syscall,
        params: parse_strace_data_types(groups.params),
        return: parse_strace_data_type(groups.return)
    };
}

interface StraceExitEntry extends StraceEntry {
    message: string
};


function parse_strace_exit_entry(raw: string): StraceExitEntry | undefined {
    const reg = /^(?<timestamp>\d+\.\d+) \[(?<address>\?+)\] \+\+\+ (?<message>.*) \+\+\+$/;
    const res = reg.exec(raw);
    if (!res) {
        return undefined;
    }
    const groups = res.groups;
    if (!groups) {
        throw new Error('invalid syscall');
    }
    return {
        raw,
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
            const entry: Entry | undefined = parser(raw);
            if (entry) {
                return entry;
            }
        }
        /// console.log(raw)
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
import { pipeline } from 'stream';

// /*
async function start(binPath: string, args: string[]) {
    const subprocess = spawn('strace', ['-yy', '-e', 'verbose=all', '-i', '-ttt', '-v', '-xx', '-s', '1024', binPath, ...args], { stdio: ['inherit', 'inherit', 'pipe'] })

    for await (const entry of StraceParser.parse_stream(subprocess.stderr)) {
        console.error(subprocess.pid, entry);
        console.error();
    }
    return subprocess;
}
// */

async function main() {
    //console.log('start server')
    //start('ls', ['-la', '.']);


    console.log('start server')
    start('nc', ['-l', '8080']);
    console.log('wait')
    await new Promise((resolve) => setTimeout(() => { resolve(null) }, 1000));
    console.log('start client')
    start('nc', ['127.0.0.1', '8080']);
}

main().catch(console.error);