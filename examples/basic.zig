const std = @import("std");
const Writer = std.Io.Writer;
const sopt = @import("sourceopt");
const Parser = sopt.Parser;
const Iterator = sopt.Iterator;
const Flag = sopt.Flag;
const Setter = sopt.Setter;
const Source = sopt.Source;

const NAME = "basic";

const USAGE =
    \\Usage: 
++ NAME ++ ": " ++
    \\[OPTIONS] COMMAND [ARGS...]
    \\
    \\Basic sourceopt flags example
    \\
    \\Options:
    \\  -h, --help          Show this help message and exit
    \\
    \\Commands:
    \\  greet [--greeting=WORD] [name ...]
    \\      Greet one or more people by name, optionally customized with --greeting.
    \\      Defaults to "Hello".
;

const Command = enum {
    greet,
};

pub fn main() !void {
    var dba = std.heap.DebugAllocator(.{}).init;
    defer if (dba.deinit() == .leak) @panic("leaked");

    var arena = std.heap.ArenaAllocator.init(dba.allocator());
    defer arena.deinit(); // <- Clean up any allocated values at the end!
    const alloc = arena.allocator();

    var help: bool = false;
    const help_setter = Setter.bool(&help, .{});
    var help_flag = Flag{ .long = "help", .short = 'h', .setter = help_setter };
    var greeting: []const u8 = "Hello";
    const greeting_setter = Setter.@"[]const u8"(&greeting);
    var greeting_flag = Flag{ .long = "greeting", .setter = greeting_setter };

    var env = try Source.Env.init(alloc, .{});
    defer env.deinit();
    var env_source = env.source();

    var proc = try Iterator.Process.init(alloc);
    defer proc.deinit();
    var iterator = proc.iterator();

    // Skip program name.
    _ = iterator.next();

    const root_flags = [_]*Flag{&help_flag};
    const greet_flags = [_]*Flag{&greeting_flag} ++ root_flags;
    const root_sources = [_]*Source{&env_source};
    var p = Parser{
        .iterator = iterator,
        .flags = &root_flags,
        .sources = &root_sources,
    };

    var selected_command: ?Command = null;
    var names_list = std.ArrayList([]const u8).empty;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.fs.File.stdout().writer(&stderr_buffer);
    const stderr = &stderr_writer.interface;

    var dx = Parser.Diagnostic{};
    while (p.next(.{ .diagnostic = &dx })) |positional| {
        if (positional == null) break;
        const pos = positional.?;

        if (selected_command == null) {
            if (std.meta.stringToEnum(Command, pos)) |comm| switch (comm) {
                Command.greet => |g| {
                    selected_command = g;
                    p.flags = &greet_flags;
                    continue;
                },
            };
            const note = "note: command greet accepts positionals\n";
            try stderr.print("unexpected argument {s}\n" ++ note, .{pos});
            try stderr.flush();
            return;
        }

        try names_list.append(alloc, pos);
    } else |err| {
        try printDiagnostic(stderr, err, &dx);
        return;
    }

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    if (help) try printUsage(stdout) else if (selected_command) |comm| switch (comm) {
        .greet => try printGreeting(stdout, greeting, names_list),
    } else {
        const t =
            \\Welcome to the basic example!
            \\Try "greet <name>" or "help" for usage.
        ;
        try stdout.print("{s}\n", .{t});
    }

    try stdout.flush();
}

fn printDiagnostic(w: *Writer, err: Parser.Error, dx: *Parser.Diagnostic) !void {
    try w.print("{s}: error: ", .{NAME});
    try switch (err) {
        Parser.Error.UnexpectedArgument => w.print("unexpected argument {s}", .{dx.argument}),
        Parser.Error.UnknownFlag => w.print("unrecognized flag {s}", .{dx.argument}),
        Parser.Error.MissingValue => w.print("missing value for flag {s}", .{dx.argument}),
        Parser.Error.InvalidValue => w.print("invalid value {s} for flag {s}", .{ dx.flag_value, dx.argument }),
        Parser.Error.SourceError => w.print("source inaccessible: {s}: {s}", .{ dx.source_name, dx.source_error_desc }),
    };
    _ = try w.write("\n");
    if (dx.flag_setter_error_desc.len > 0)
        try w.print("{s}\n", .{dx.source_error_desc});
    try printUsage(w);
    try w.flush();
}

fn printUsage(w: *Writer) !void {
    _ = try w.print("{s}\n", .{USAGE});
    try w.flush();
}

fn printGreeting(w: *Writer, greeting: []const u8, names: std.ArrayList([]const u8)) !void {
    if (names.items.len == 0) {
        try w.print("{s}, what is your name?\n", .{greeting});
    } else for (names.items) |name| {
        try w.print("{s}, {s}.\n", .{ greeting, name });
    }
    try w.flush();
}
