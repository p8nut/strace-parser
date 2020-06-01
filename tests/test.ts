import { parse_line, instanceOfInstructionEntry } from '../lib/src/index'

describe('parse syscall', () => {
    test('write', () => {
        const entry = parse_line('1590956412.769884 [00007efd9716c1e8] write(1<\x2f\x64\x65\x76\x2f\x70\x74\x73\x2f\x33<char 136:3>>, "\x6f\x6b\x0a", 3) = 3');
        expect(instanceOfInstructionEntry(entry)).toBeTruthy()
        expect(entry.timestamp).toBe(parseFloat('1590956412.769884'));
        expect(entry.pointer).toBe(parseInt('00007efd9716c1e8', 16));
        if (instanceOfInstructionEntry(entry)) {
            expect(entry.name).toBe('write')
            expect(entry.params instanceof Array).toBeTruthy()
            expect(entry.params.length).toBe(3);
            expect(entry.params[0]).toBe(1);
            expect(entry.params[1]).toBe('ok\n');
            expect(entry.params[2]).toBe(3);
            expect(entry.returnValue).toBe(3);
        }
    });

    test('recvfrom', () => {
        const entry = parse_line('1590956412.769525 [00007efd9717c301] recvfrom(7<TCP:[127.0.0.1:8080->127.0.0.1:33980]>, "\x6f\x6b\x0a", 8192, 0, NULL, NULL) = 3');
        expect(instanceOfInstructionEntry(entry)).toBeTruthy()
        expect(entry.timestamp).toBe(parseFloat('1590956412.769525'));
        expect(entry.pointer).toBe(parseInt('00007efd9717c301', 16));
        if (instanceOfInstructionEntry(entry)) {
            expect(entry.name).toBe('recvfrom')
            expect(entry.params instanceof Array).toBeTruthy()
            expect(entry.params.length).toBe(6);
            expect(entry.params[0]).toBe(7);
            expect(entry.params[1]).toBe('ok\n');
            expect(entry.params[2]).toBe(8192);
            expect(entry.params[3]).toBe(0);
            expect(entry.params[4]).toBeNull();
            expect(entry.params[5]).toBeNull();
            expect(entry.returnValue).toBe(3);
        }
    });

    test('close', () => {
        const entry = parse_line('1590956413.495544 [00007efd9716c878] close(7<TCP:[127.0.0.1:8080->127.0.0.1:33980]>) = 0');
        expect(instanceOfInstructionEntry(entry)).toBeTruthy()
        expect(entry.timestamp).toBe(parseFloat('1590956413.495544'));
        expect(entry.pointer).toBe(parseInt('00007efd9716c878', 16));
        if (instanceOfInstructionEntry(entry)) {
            expect(entry.name).toBe('close')
            expect(entry.params instanceof Array).toBeTruthy()
            expect(entry.params.length).toBe(1);
            expect(entry.params[0]).toBe(7);
            expect(entry.returnValue).toBe(0);
        }
    });

    test('access', () => {
        const entry = parse_line('1590956382.908961 [00007efd9716c2bb] access("\x2f\x65\x74\x63\x2f\x73\x79\x73\x74\x65\x6d\x2d\x66\x69\x70\x73", F_OK) = -1 ENOENT (No such file or directory)');
        expect(instanceOfInstructionEntry(entry)).toBeTruthy()
        expect(entry.timestamp).toBe(parseFloat('1590956382.908961'));
        expect(entry.pointer).toBe(parseInt('00007efd9716c2bb', 16));
        if (instanceOfInstructionEntry(entry)) {
            expect(entry.name).toBe('access')
            expect(entry.params instanceof Array).toBeTruthy()
            expect(entry.params.length).toBe(2);
            expect(entry.params[0]).toBe('/etc/system-fips');
            expect(entry.params[1]).toBe('F_OK');
            expect(entry.returnValue).toBe(-1);
        }
    });
});
