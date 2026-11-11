const std = @import("std");
const r4os = @import("r4os");

const MAX_TCP_PAYLOAD: usize = r4os.abi.net_service_tcp_read_max;
const MAX_INTERACTIVE_LINE: usize = 512;
const DEFAULT_PAYLOAD = "R4NETCAT";

const Options = struct {
    target_text: []const u8,
    target: r4os.abi.NetworkEndpoint,
    port: u16,
    payload: []const u8,
    resolved: bool,
};

const App = struct {
    sys: r4os.r4sys.Context,
    output: *r4os.launch_io.Output,
    network: *r4os.network_stream.Session,
    budget: *r4os.rpc_budget.Budget,
    args: []const u8,
    family: u32,

    fn write(self: *const App, value: []const u8) void {
        self.output.write(value);
    }
    fn putc(self: *const App, ch: u8) void {
        self.output.put(ch);
    }
    fn printU64(self: *const App, value: u64) void {
        self.output.number(value);
    }
};

pub fn r4_app_main(app: *r4os.App2) i32 {
    var output: r4os.launch_io.Output = undefined;
    if (r4os.launch_io.Output.init(app, &output) != 0) return 1;
    var selected_family: u32 = 0;
    const args = r4os.network_stream.arguments(app.args(), &selected_family) orelse {
        output.write("NETCAT: invalid argument grammar\r\n");
        _ = output.close();
        return 1;
    };
    var budget = r4os.rpc_budget.Budget.fromTimeout(output.clock.read, .{ .kind = 1, .nanoseconds = 10_000_000_000 }) catch {
        _ = output.close();
        return 1;
    };
    var network: r4os.network_stream.Session = undefined;
    const opened = r4os.network_stream.Session.open(app, &budget, &network);
    if (opened != 0) {
        output.write("NETCAT: TCPSVC unavailable or invalid\r\n");
        _ = output.close();
        return 1;
    }
    const ctx: App = .{ .sys = app.system(), .output = &output, .network = &network, .budget = &budget, .args = args, .family = selected_family };
    const result = run(&ctx);
    const closed = network.close();
    if (closed != 0) output.write("NETCAT close: not confirmed\r\n");
    const io_closed = output.close();
    return if (output.failed or closed != 0 or io_closed != 0) 1 else result;
}

fn run(ctx: *const App) i32 {
    const args = trim(ctx.args);
    if (parseListenOptions(args)) |listen| {
        return listenOnce(ctx, listen);
    }
    if (parseInteractiveOptions(ctx, args)) |interactive| {
        return interactiveSession(ctx, interactive);
    }

    const options = parseOptions(ctx, args) orelse {
        usage(ctx);
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
        writeAddress(ctx, options.target.address);
        ctx.write("\r\n");
    }

    ctx.write("NETCAT connect ");
    writeAddress(ctx, options.target.address);
    ctx.write(":");
    ctx.printU64(options.port);
    ctx.write(": ");

    var socket: r4os.network_stream.Socket = undefined;
    if (ctx.network.create(options.target, false, ctx.budget, &socket) != 0) {
        ctx.write("failed\r\n");
        return 1;
    }
    ctx.write("ok\r\n");
    defer socket.close();
    const sent = socket.writeAll(options.payload, ctx.budget) catch return 1;
    const written: i32 = @intCast(sent.bytes);
    ctx.write("NETCAT sent: ");
    if (written >= 0) {
        ctx.printU64(@intCast(written));
    } else {
        ctx.write("failed");
    }
    ctx.write("\r\n");
    if (!r4os.network_stream.complete(sent)) {
        return 1;
    }

    var reply: [MAX_TCP_PAYLOAD]u8 = undefined;
    var reader: r4os.network_stream.Reader = .{ .socket = &socket };
    const received = reader.read(reply[0..options.payload.len], true, ctx.budget) catch return 1;
    const got: i32 = @intCast(received.bytes);

    ctx.write("NETCAT received: ");
    if (got >= 0) {
        ctx.printU64(@intCast(got));
    } else {
        ctx.write("failed");
    }
    ctx.write("\r\n");
    if (!r4os.network_stream.complete(received)) {
        ctx.write("NETCAT result: ");
        ctx.write(@tagName(@as(r4os.stream_transfer.Outcome, @enumFromInt(received.outcome))));
        ctx.write("\r\n");
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
    target: r4os.abi.NetworkEndpoint,
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
    ctx.write("NETCAT listen ");
    ctx.printU64(options.port);
    ctx.write(": waiting\r\n");
    const endpoint: r4os.abi.NetworkEndpoint = .{ .address = .{ .family = if (ctx.family == 6) 6 else 4 }, .port = options.port };
    var listener: r4os.network_stream.Socket = undefined;
    if (ctx.network.create(endpoint, true, ctx.budget, &listener) != 0) return 1;
    defer listener.close();
    var socket: r4os.network_stream.Socket = undefined;
    if (listener.accept(ctx.budget, &socket) != 0) {
        ctx.write("NETCAT listen: accept failed\r\n");
        return 1;
    }
    defer socket.close();
    var payload: [MAX_TCP_PAYLOAD]u8 = undefined;
    var reader: r4os.network_stream.Reader = .{ .socket = &socket };
    const got = reader.read(&payload, false, ctx.budget) catch return 1;
    if (got.bytes == 0 or got.flags & r4os.stream_transfer.core.terminal != 0 and got.outcome != @intFromEnum(r4os.stream_transfer.Outcome.eof) and !r4os.network_stream.complete(got)) return 1;
    const bytes = payload[0..@intCast(got.bytes)];
    ctx.write("NETCAT accepted: conn=");
    ctx.printU64(socket.id);
    ctx.write(" bytes=");
    ctx.printU64(got.bytes);
    ctx.write("\r\nNETCAT received: ");
    ctx.printU64(got.bytes);
    ctx.write("\r\nNETCAT payload: ");
    ctx.write(bytes);
    ctx.write("\r\n");
    if (options.has_reply) {
        const sent = socket.writeAll(options.reply, ctx.budget) catch return 1;
        ctx.write("NETCAT reply-sent: ");
        ctx.printU64(sent.bytes);
        ctx.write("\r\n");
        if (!r4os.network_stream.complete(sent)) {
            ctx.write("NETCAT result: write-failed\r\n");
            return 1;
        }
    } else ctx.write("NETCAT reply-sent: none\r\n");
    ctx.write("NETCAT result: ok\r\n");
    return 0;
}

fn interactiveSession(ctx: *const App, options: InteractiveOptions) i32 {
    if (options.resolved) {
        ctx.write("NETCAT resolved ");
        ctx.write(options.target_text);
        ctx.write(" to ");
        writeAddress(ctx, options.target.address);
        ctx.write("\r\n");
    }

    ctx.write("NETCAT connect ");
    writeAddress(ctx, options.target.address);
    ctx.write(":");
    ctx.printU64(options.port);
    ctx.write(": ");

    var socket: r4os.network_stream.Socket = undefined;
    if (ctx.network.create(options.target, false, ctx.budget, &socket) != 0) {
        ctx.write("failed\r\n");
        return 1;
    }
    defer socket.close();
    var reader: r4os.network_stream.Reader = .{ .socket = &socket };
    ctx.write("ok\r\n");
    ctx.write("NETCAT interactive: line mode, single dot or Ctrl+Z ends\r\n");
    var input: [128]u8 = undefined;
    var line: [MAX_INTERACTIVE_LINE]u8 = undefined;
    var line_len: usize = 0;
    var lines: usize = 0;
    var total_sent: usize = 0;
    var total_received: usize = 0;
    var last_was_cr = false;
    var done = false;

    while (!done) {
        if (ctx.sys.programShouldClose() or ctx.output.failed) return 1;
        var progress: r4os.byte_pipe.Progress = .{};
        const read_rc = ctx.output.io.readChecked(&input, .{}, &progress);
        if (read_rc != 0 or progress.bytes > input.len or progress.state < r4os.abi.byte_pipe_ready or progress.state > r4os.abi.byte_pipe_closed) {
            ctx.write("NETCAT result: stdin-failed\r\n");
            return 1;
        }
        if (progress.state == r4os.abi.byte_pipe_eof) done = true;
        if (progress.state == r4os.abi.byte_pipe_cancelled or progress.state == r4os.abi.byte_pipe_closed or progress.state == r4os.abi.byte_pipe_broken_pipe or progress.state == r4os.abi.byte_pipe_timed_out) {
            ctx.write("NETCAT result: stdin-cancelled\r\n");
            return 1;
        }
        if (progress.bytes == 0 and !done) {
            ctx.sys.sleepTicks(1);
            continue;
        }
        const bytes = input[0..@intCast(progress.bytes)];
        for (bytes) |ch| {
            if (ch == 0x03) {
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
                if (!sendInteractiveLine(ctx, &socket, &reader, current, &lines, &total_sent, &total_received)) {
                    return 1;
                }
                line_len = 0;
                continue;
            }

            if (line_len >= line.len) {
                ctx.write("NETCAT result: line-too-large\r\n");
                return 1;
            }
            line[line_len] = ch;
            line_len += 1;
        }
    }

    if (line_len != 0) {
        if (!sendInteractiveLine(ctx, &socket, &reader, line[0..line_len], &lines, &total_sent, &total_received)) {
            return 1;
        }
    }

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

fn sendInteractiveLine(ctx: *const App, socket: *r4os.network_stream.Socket, reader: *r4os.network_stream.Reader, line: []const u8, lines: *usize, total_sent: *usize, total_received: *usize) bool {
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

    var budget = r4os.rpc_budget.Budget.fromTimeout(ctx.network.clock.read, .{ .kind = 1, .nanoseconds = 10_000_000_000 }) catch return false;
    const sent = socket.writeAll(payload[0..send_len], &budget) catch return false;
    if (!r4os.network_stream.complete(sent)) {
        ctx.write("NETCAT result: write-failed\r\n");
        return false;
    }

    var reply: [MAX_TCP_PAYLOAD]u8 = undefined;
    const received = reader.read(&reply, false, &budget) catch return false;
    const got: usize = @intCast(received.bytes);
    if (got == 0 or received.flags & r4os.stream_transfer.core.terminal != 0 and received.outcome != @intFromEnum(r4os.stream_transfer.Outcome.eof) and !r4os.network_stream.complete(received)) {
        ctx.write("NETCAT result: ");
        ctx.write(@tagName(@as(r4os.stream_transfer.Outcome, @enumFromInt(received.outcome))));
        ctx.write("\r\n");
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

    var endpoint: r4os.abi.NetworkEndpoint = .{};
    if (ctx.network.resolve(target.token, port, ctx.family, ctx.budget, &endpoint) != 0) {
        ctx.write("NETCAT resolve failed for ");
        ctx.write(target.token);
        ctx.write("\r\n");
        return null;
    }
    const numeric = if (target.token.len >= 2 and target.token[0] == '[') target.token[1 .. target.token.len - 1] else target.token;
    const resolved = r4os.network_family.parseAddress(numeric) == null;

    return .{
        .target_text = target.token,
        .target = endpoint,
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

    var endpoint: r4os.abi.NetworkEndpoint = .{};
    if (ctx.network.resolve(target.token, port, ctx.family, ctx.budget, &endpoint) != 0) {
        ctx.write("NETCAT resolve failed for ");
        ctx.write(target.token);
        ctx.write("\r\n");
        return null;
    }
    const numeric = if (target.token.len >= 2 and target.token[0] == '[') target.token[1 .. target.token.len - 1] else target.token;
    const resolved = r4os.network_family.parseAddress(numeric) == null;

    return .{
        .target_text = target.token,
        .target = endpoint,
        .port = port,
        .resolved = resolved,
    };
}

fn usage(ctx: *const App) void {
    ctx.write("Usage: NETCAT [-4|-6] host port [text]\r\n");
    ctx.write("       NETCAT [-4|-6] /INTERACTIVE host port\r\n");
    ctx.write("       NETCAT [-4|-6] /LISTEN [port] [reply]\r\n");
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

const Token = struct { token: []const u8, rest: []const u8 };
fn takeToken(value: []const u8) ?Token {
    var failure: r4os.arguments.Failure = .{};
    var cursor = r4os.arguments.ArgCursor.init(value, .{}, &failure) catch return null;
    const token = (cursor.next() catch return null) orelse return null;
    return .{ .token = token.bytes(value) catch return null, .rest = cursor.remainingArguments() catch return null };
}

fn parsePort(value: []const u8) ?u16 {
    if (value.len == 0) return null;
    for (value) |byte| if (byte < '0' or byte > '9') return null;
    const number = std.fmt.parseInt(u16, value, 10) catch return null;
    return if (number == 0) null else number;
}

fn writeAddress(ctx: *const App, address: r4os.abi.NetworkAddress) void {
    var buffer: [80]u8 = undefined;
    ctx.write(r4os.network_family.addressText(&buffer, address) catch "unknown");
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
