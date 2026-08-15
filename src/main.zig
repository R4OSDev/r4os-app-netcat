const r4os = @import("r4os");

const MAX_TCP_PAYLOAD: usize = r4os.abi.net_service_tcp_read_max;
const MAX_INTERACTIVE_LINE: usize = 512;
const DEFAULT_PAYLOAD = "R4NETCAT";

const Options = struct {
    target_text: []const u8,
    target_ip: [4]u8,
    port: u16,
    payload: []const u8,
    resolved: bool,
};

const App = struct {
    sys: r4os.r4sys.Context,
    desk: r4os.r4desk.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .desk = r4_app.desktop() orelse return null,
            .net = r4_app.networkLowLevel() orelse return null,
        };
    }

    fn argsRaw(self: *const App) [*:0]const u8 {
        return self.sys.argsRaw();
    }

    fn write(self: *const App, value: []const u8) void {
        self.sys.write(value);
    }

    fn putc(self: *const App, ch: u8) void {
        self.sys.putc(ch);
    }

    fn printU64(self: *const App, value: u64) void {
        self.sys.printU64(value);
    }

    fn taskYield(self: *const App) void {
        self.sys.taskYield();
    }

    fn consoleRead(self: *const App, out: []u8) i32 {
        return self.desk.consoleRead(out);
    }

    fn netDnsResolveService(self: *const App, name_value: []const u8, out: *[4]u8) i32 {
        return self.net.netDnsResolveService(name_value, out);
    }

    fn netDnsResultName(self: *const App, result: i32) []const u8 {
        return self.net.netDnsResultName(result);
    }

    fn tcpConnectService(self: *const App, a: u8, b: u8, c: u8, d: u8, port: u16) i32 {
        return self.net.tcpConnectService(a, b, c, d, port);
    }

    fn tcpWriteService(self: *const App, handle: u32, data: []const u8) i32 {
        return self.net.tcpWriteService(handle, data);
    }

    fn tcpReadService(self: *const App, handle: u32, out: []u8) i32 {
        return self.net.tcpReadService(handle, out);
    }

    fn tcpAcceptPollReadService(self: *const App, port: u16, out: []u8, result: *r4os.abi.TcpAcceptResult) i32 {
        return self.net.tcpAcceptPollReadService(port, out, result);
    }

    fn tcpCloseService(self: *const App, handle: u32) i32 {
        return self.net.tcpCloseService(handle);
    }
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    const ctx = App.init(r4_app) orelse return r4os.abi.err_no_group;
    const args = trim(zSlice(ctx.argsRaw()));
    if (parseListenOptions(args)) |listen| {
        return listenOnce(&ctx, listen);
    }
    if (parseInteractiveOptions(&ctx, args)) |interactive| {
        return interactiveSession(&ctx, interactive);
    }

    const options = parseOptions(&ctx, args) orelse {
        usage(&ctx);
        return 1;
    };

    if (options.payload.len > MAX_TCP_PAYLOAD) {
        ctx.write("NETCAT: payload too large\r\n");
        return 1;
    }

    if (options.resolved) {
        ctx.write("NETCAT resolved ");
        ctx.write(options.target_text);
        ctx.write(" to ");
        writeIpv4(&ctx, options.target_ip);
        ctx.write("\r\n");
    }

    ctx.write("NETCAT connect ");
    writeIpv4(&ctx, options.target_ip);
    ctx.write(":");
    ctx.printU64(options.port);
    ctx.write(": ");

    const conn = ctx.tcpConnectService(options.target_ip[0], options.target_ip[1], options.target_ip[2], options.target_ip[3], options.port);
    if (conn <= 0) {
        ctx.write("failed\r\n");
        return 1;
    }
    ctx.write("ok\r\n");

    const conn_id: u32 = @intCast(conn);
    const written = ctx.tcpWriteService(conn_id, options.payload);
    ctx.write("NETCAT sent: ");
    if (written >= 0) {
        ctx.printU64(@intCast(written));
    } else {
        ctx.write("failed");
    }
    ctx.write("\r\n");
    if (written < 0 or written != @as(i32, @intCast(options.payload.len))) {
        _ = ctx.tcpCloseService(conn_id);
        return 1;
    }

    var reply: [MAX_TCP_PAYLOAD]u8 = undefined;
    const got = ctx.tcpReadService(conn_id, reply[0..]);
    _ = ctx.tcpCloseService(conn_id);

    ctx.write("NETCAT received: ");
    if (got >= 0) {
        ctx.printU64(@intCast(got));
    } else {
        ctx.write("failed");
    }
    ctx.write("\r\n");
    if (got <= 0) {
        ctx.write("NETCAT result: timeout\r\n");
        return 1;
    }

    const reply_bytes = reply[0..@intCast(got)];
    ctx.write("NETCAT reply: ");
    ctx.write(reply_bytes);
    ctx.write("\r\n");

    const ok = bytesEqual(reply_bytes, options.payload);
    ctx.write("NETCAT result: ");
    ctx.write(if (ok) "ok" else "mismatch");
    ctx.write("\r\n");
    return if (ok) 0 else 1;
}

const InteractiveOptions = struct {
    target_text: []const u8,
    target_ip: [4]u8,
    port: u16,
    resolved: bool,
};

const ListenOptions = struct {
    port: u16,
    reply: []const u8,
    has_reply: bool,
};

fn listenOnce(ctx: *const App, options: ListenOptions) i32 {
    if (options.has_reply and options.reply.len > MAX_TCP_PAYLOAD) {
        ctx.write("NETCAT: reply too large\r\n");
        return 1;
    }

    var payload: [MAX_TCP_PAYLOAD]u8 = undefined;
    var accept: r4os.abi.TcpAcceptResult = .{};

    ctx.write("NETCAT listen ");
    ctx.printU64(options.port);
    ctx.write(": waiting\r\n");

    const got = ctx.tcpAcceptPollReadService(options.port, payload[0..], &accept);
    if (got <= 0 or accept.conn_id == 0) {
        ctx.write("NETCAT listen ");
        ctx.printU64(options.port);
        ctx.write(": ");
        ctx.write(if (got == 0) "timeout\r\n" else "failed\r\n");
        return 1;
    }

    const bytes = payload[0..@intCast(got)];
    ctx.write("NETCAT accepted: conn=");
    ctx.printU64(accept.conn_id);
    ctx.write(" bytes=");
    ctx.printU64(@intCast(got));
    ctx.write("\r\n");
    ctx.write("NETCAT received: ");
    ctx.printU64(@intCast(got));
    ctx.write("\r\n");
    ctx.write("NETCAT payload: ");
    ctx.write(bytes);
    ctx.write("\r\n");

    if (options.has_reply) {
        const written = ctx.tcpWriteService(accept.conn_id, options.reply);
        ctx.write("NETCAT reply-sent: ");
        if (written >= 0) {
            ctx.printU64(@intCast(written));
        } else {
            ctx.write("failed");
        }
        ctx.write("\r\n");
        _ = ctx.tcpCloseService(accept.conn_id);
        if (written < 0 or written != @as(i32, @intCast(options.reply.len))) {
            ctx.write("NETCAT result: write-failed\r\n");
            return 1;
        }
    } else {
        _ = ctx.tcpCloseService(accept.conn_id);
        ctx.write("NETCAT reply-sent: none\r\n");
    }

    ctx.write("NETCAT result: ok\r\n");
    return 0;
}

fn interactiveSession(ctx: *const App, options: InteractiveOptions) i32 {
    if (options.resolved) {
        ctx.write("NETCAT resolved ");
        ctx.write(options.target_text);
        ctx.write(" to ");
        writeIpv4(ctx, options.target_ip);
        ctx.write("\r\n");
    }

    ctx.write("NETCAT connect ");
    writeIpv4(ctx, options.target_ip);
    ctx.write(":");
    ctx.printU64(options.port);
    ctx.write(": ");

    const conn = ctx.tcpConnectService(options.target_ip[0], options.target_ip[1], options.target_ip[2], options.target_ip[3], options.port);
    if (conn <= 0) {
        ctx.write("failed\r\n");
        return 1;
    }
    ctx.write("ok\r\n");
    ctx.write("NETCAT interactive: line mode, single dot or Ctrl+Z ends\r\n");

    const conn_id: u32 = @intCast(conn);
    var input: [128]u8 = undefined;
    var line: [MAX_INTERACTIVE_LINE]u8 = undefined;
    var line_len: usize = 0;
    var lines: usize = 0;
    var total_sent: usize = 0;
    var total_received: usize = 0;
    var last_was_cr = false;
    var done = false;

    while (!done) {
        const read = ctx.consoleRead(input[0..]);
        if (read < 0) {
            _ = ctx.tcpCloseService(conn_id);
            ctx.write("NETCAT result: stdin-failed\r\n");
            return 1;
        }
        if (read == 0) {
            ctx.taskYield();
            continue;
        }

        const bytes = input[0..@intCast(read)];
        for (bytes) |ch| {
            if (ch == 0x03) {
                _ = ctx.tcpCloseService(conn_id);
                ctx.write("NETCAT result: cancelled\r\n");
                return 1;
            }
            if (ch == 0x1A) {
                done = true;
                break;
            }
            if (ch == '\n' and last_was_cr) {
                last_was_cr = false;
                continue;
            }
            last_was_cr = ch == '\r';

            if (ch == '\r' or ch == '\n') {
                const current = line[0..line_len];
                if (current.len == 1 and current[0] == '.') {
                    done = true;
                    break;
                }
                if (!sendInteractiveLine(ctx, conn_id, current, &lines, &total_sent, &total_received)) {
                    _ = ctx.tcpCloseService(conn_id);
                    return 1;
                }
                line_len = 0;
                continue;
            }

            if (line_len >= line.len) {
                _ = ctx.tcpCloseService(conn_id);
                ctx.write("NETCAT result: line-too-large\r\n");
                return 1;
            }
            line[line_len] = ch;
            line_len += 1;
        }
    }

    if (line_len != 0) {
        if (!sendInteractiveLine(ctx, conn_id, line[0..line_len], &lines, &total_sent, &total_received)) {
            _ = ctx.tcpCloseService(conn_id);
            return 1;
        }
    }

    _ = ctx.tcpCloseService(conn_id);
    ctx.write("NETCAT interactive lines: ");
    ctx.printU64(@intCast(lines));
    ctx.write("\r\n");
    ctx.write("NETCAT interactive sent: ");
    ctx.printU64(@intCast(total_sent));
    ctx.write("\r\n");
    ctx.write("NETCAT interactive received: ");
    ctx.printU64(@intCast(total_received));
    ctx.write("\r\n");
    ctx.write("NETCAT result: ok\r\n");
    return 0;
}

fn sendInteractiveLine(ctx: *const App, conn_id: u32, line: []const u8, lines: *usize, total_sent: *usize, total_received: *usize) bool {
    if (line.len + 2 > MAX_TCP_PAYLOAD) {
        ctx.write("NETCAT result: line-too-large\r\n");
        return false;
    }

    var payload: [MAX_TCP_PAYLOAD]u8 = undefined;
    var len: usize = 0;
    while (len < line.len) : (len += 1) payload[len] = line[len];
    payload[len] = '\r';
    payload[len + 1] = '\n';
    const send_len = len + 2;

    ctx.write("NETCAT interactive send: ");
    writeVisible(ctx, payload[0..send_len]);
    ctx.write("\r\n");

    const written = ctx.tcpWriteService(conn_id, payload[0..send_len]);
    if (written < 0 or written != @as(i32, @intCast(send_len))) {
        ctx.write("NETCAT result: write-failed\r\n");
        return false;
    }

    var reply: [MAX_TCP_PAYLOAD]u8 = undefined;
    const got = ctx.tcpReadService(conn_id, reply[0..]);
    if (got <= 0) {
        ctx.write("NETCAT result: timeout\r\n");
        return false;
    }

    const reply_bytes = reply[0..@intCast(got)];
    ctx.write("NETCAT interactive reply-bytes: ");
    ctx.printU64(@intCast(got));
    ctx.write("\r\n");
    ctx.write("NETCAT interactive reply: ");
    writeVisible(ctx, reply_bytes);
    ctx.write("\r\n");

    lines.* += 1;
    total_sent.* += send_len;
    total_received.* += @intCast(got);
    return true;
}

fn parseOptions(ctx: *const App, args: []const u8) ?Options {
    var rest = trim(args);
    const target = takeToken(rest) orelse return null;
    rest = target.rest;
    const port_token = takeToken(rest) orelse return null;
    rest = port_token.rest;
    const port = parsePort(port_token.token) orelse return null;

    var target_ip: [4]u8 = undefined;
    var resolved = false;
    if (parseIpv4(target.token)) |ip| {
        target_ip = ip;
    } else {
        const result = ctx.netDnsResolveService(target.token, &target_ip);
        if (result != r4os.abi.dns_result_ok) {
            ctx.write("NETCAT resolve failed for ");
            ctx.write(target.token);
            ctx.write(": ");
            ctx.write(ctx.netDnsResultName(result));
            ctx.write("\r\n");
            return null;
        }
        resolved = true;
    }

    return .{
        .target_text = target.token,
        .target_ip = target_ip,
        .port = port,
        .payload = if (rest.len == 0) DEFAULT_PAYLOAD else rest,
        .resolved = resolved,
    };
}

fn parseInteractiveOptions(ctx: *const App, args: []const u8) ?InteractiveOptions {
    var rest = trim(args);
    const first = takeToken(rest) orelse return null;
    if (!equalsIgnoreCase(first.token, "/INTERACTIVE") and !equalsIgnoreCase(first.token, "-I")) return null;
    rest = first.rest;

    const target = takeToken(rest) orelse return null;
    rest = target.rest;
    const port_token = takeToken(rest) orelse return null;
    if (port_token.rest.len != 0) return null;
    const port = parsePort(port_token.token) orelse return null;

    var target_ip: [4]u8 = undefined;
    var resolved = false;
    if (parseIpv4(target.token)) |ip| {
        target_ip = ip;
    } else {
        const result = ctx.netDnsResolveService(target.token, &target_ip);
        if (result != r4os.abi.dns_result_ok) {
            ctx.write("NETCAT resolve failed for ");
            ctx.write(target.token);
            ctx.write(": ");
            ctx.write(ctx.netDnsResultName(result));
            ctx.write("\r\n");
            return null;
        }
        resolved = true;
    }

    return .{
        .target_text = target.token,
        .target_ip = target_ip,
        .port = port,
        .resolved = resolved,
    };
}

fn usage(ctx: *const App) void {
    ctx.write("Usage: NETCAT host port [text]\r\n");
    ctx.write("       NETCAT /INTERACTIVE host port\r\n");
    ctx.write("       NETCAT /LISTEN [port] [reply]\r\n");
}

fn parseListenOptions(args: []const u8) ?ListenOptions {
    var rest = trim(args);
    const first = takeToken(rest) orelse return null;
    if (!equalsIgnoreCase(first.token, "/LISTEN") and !equalsIgnoreCase(first.token, "-L")) return null;
    rest = first.rest;

    const port_token = takeToken(rest);
    if (port_token) |tok| {
        const port = parsePort(tok.token) orelse return null;
        return .{
            .port = port,
            .reply = tok.rest,
            .has_reply = tok.rest.len != 0,
        };
    }
    return .{
        .port = 8080,
        .reply = "",
        .has_reply = false,
    };
}

const Token = struct {
    token: []const u8,
    rest: []const u8,
};

fn takeToken(value: []const u8) ?Token {
    const trimmed = trim(value);
    if (trimmed.len == 0) return null;
    var end: usize = 0;
    while (end < trimmed.len and !isSpace(trimmed[end])) : (end += 1) {}
    return .{
        .token = trimmed[0..end],
        .rest = if (end >= trimmed.len) "" else trim(trimmed[end..]),
    };
}

fn parsePort(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    var out: u32 = 0;
    for (value) |ch| {
        if (ch < '0' or ch > '9') return null;
        out = out * 10 + @as(u32, ch - '0');
        if (out == 0 or out > 65535) return null;
    }
    return @intCast(out);
}

fn parseIpv4(value: []const u8) ?[4]u8 {
    var out: [4]u8 = .{0} ** 4;
    var part: usize = 0;
    var accum: u16 = 0;
    var digits: usize = 0;

    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const ch = value[index];
        if (ch >= '0' and ch <= '9') {
            accum = accum * 10 + @as(u16, ch - '0');
            if (accum > 255) return null;
            digits += 1;
            if (digits > 3) return null;
        } else if (ch == '.') {
            if (digits == 0 or part >= 3) return null;
            out[part] = @intCast(accum);
            part += 1;
            accum = 0;
            digits = 0;
        } else {
            return null;
        }
    }
    if (digits == 0 or part != 3) return null;
    out[part] = @intCast(accum);
    return out;
}

fn writeIpv4(ctx: *const App, ip: [4]u8) void {
    ctx.printU64(ip[0]);
    ctx.putc('.');
    ctx.printU64(ip[1]);
    ctx.putc('.');
    ctx.printU64(ip[2]);
    ctx.putc('.');
    ctx.printU64(ip[3]);
}

fn bytesEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var index: usize = 0;
    while (index < a.len) : (index += 1) {
        if (a[index] != b[index]) return false;
    }
    return true;
}

fn writeVisible(ctx: *const App, bytes: []const u8) void {
    for (bytes) |ch| {
        switch (ch) {
            '\r' => ctx.write("\\r"),
            '\n' => ctx.write("\\n"),
            '\t' => ctx.write("\\t"),
            else => {
                if (ch >= 0x20 and ch <= 0x7E) {
                    ctx.putc(ch);
                } else {
                    ctx.putc('.');
                }
            },
        }
    }
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var index: usize = 0;
    while (index < a.len) : (index += 1) {
        if (upperAscii(a[index]) != upperAscii(b[index])) return false;
    }
    return true;
}

fn upperAscii(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - ('a' - 'A');
    return ch;
}

fn zSlice(ptr: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return ptr[0..len];
}

fn trim(value: []const u8) []const u8 {
    var start: usize = 0;
    var end = value.len;
    while (start < end and isSpace(value[start])) : (start += 1) {}
    while (end > start and isSpace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}
