const std = @import("std");
const ArgIterator = std.process.ArgIterator;

/// Environment variable source.
/// Allows sourceopt to discover values for your flags in the environment.
pub const Env = struct {
    /// Forces the Env source to only consider environment variables that begin with this prefix,
    /// followed by an underscore.
    ///
    /// For example, a flag "port" will match the "PORT" environment variable.
    ///
    /// Setting prefix to "banana" means it will match "BANANA_PORT" instead.
    prefix: ?[]const u8,
};

/// File source.
/// Allows sourceopt to discover values for your flags in a file.
pub const File = struct {
    /// The file must have a supported extension.
    ///
    /// # Supported File Types
    ///
    /// - JSON (.json)
    path: []const u8,
};

/// Sources for sourceopt.
/// Command line arguments can always be used a source.
///
/// TODO: More information needed.
pub const Source = union(enum) {
    Env: Env,
    File: File,
};

/// Callback invoked when a flag is found.
/// Receives the value bytes associated with the flag and the context that the flag was provided,
/// if any.
///
/// # Errors
///
/// Returning an error will interrupt the parser. The same error is returned to the caller.
/// If a Diagnostic was provided to the parser, you may inspect it to discover information about
/// the flag that was being handled at the time of error.
///
/// TODO: More information needed.
pub const Setter = fn (value: []const u8, ctx: *anyopaque) anyerror!void;

pub const Flag = union(enum) {
    value: ValueFlag,
    boolean: BooleanFlag,

    pub fn @"u16"(long: ?[]const u8, short: ?u8, buf: *u16) Flag {
        const setter = struct {
            pub fn set(value: []const u8, ctx: *anyopaque) anyerror!void {
                const mem: *u16 = @ptrCast(@alignCast(ctx));
                mem.* = try std.fmt.parseUnsigned(u16, value, 10);
            }
        };
        return .{
            .value = .{
                .long = long,
                .short = short,
                .setter_ctx = buf,
                .setter = setter.set,
            },
        };
    }

    pub fn @"bool"(long: ?[]const u8, short: ?u8, buf: *bool) Flag {
        return .{
            .boolean = .{
                .long = long,
                .short = short,
                .bool = buf,
            },
        };
    }
};

/// Boolean flags do not expect a value.
/// When a boolean flag is discovered, a boolean value is toggled.
pub const BooleanFlag = struct {
    long: ?[]const u8,
    short: ?u8,
    /// Storage for this boolean flag.
    /// When this flag is discovered, the boolean will be toggled.
    bool: *bool,
};

/// Value flags expect a value.
/// When a value flag is discovered, a setter function is called with the value bytes and context,
/// if provided.
///
/// The setter function will choose how to handle the value,
/// and may return an error to indicate a problem.
///
/// For more information, see the documentation of the Setter type.
pub const ValueFlag = struct {
    long: ?[]const u8,
    short: ?u8,
    /// An opaque pointer provided to Value.setter when this flag is discovered.
    setter_ctx: ?*anyopaque,
    /// Invoked when this flag is discovered.
    /// Receives the value bytes and Value.setter_ctx.
    setter: *const Setter,
};

// This will be the container for user-reportable information.
// Because sourceopt wants to avoid enforcing any particular response to an error,
// it should contain enough information for the user to figure out what happened.

/// TODO
pub const Diagnostic = struct {
    /// The source that value was found in.
    source: Source,
    /// The flag that was being handled at the time of error.
    Flag: Flag,

    // TODO: How should this present for boolean flags -- make it optional?
    //value: ?[]const u8,
};

pub const Command = struct {
    name: []const u8,
    flags: ?Group,
};

/// Group is a set of related flags.
/// They can be associated with a Command, or parsed directly.
pub const Group = struct {
    const Self = @This();
    pub const ParseOpts = struct {
        diagnostic: ?*Diagnostic = null,
    };

    flags: []const Flag,
    commands: []const Command,

    pub fn parse(self: *Self, args: *ArgIterator, o: ParseOpts) !void {
        _ = self;
        _ = args;
        _ = o;
    }
}; // Flags

test {
    var port: u16 = 0;
    var verbose: bool = false;

    //const args = [_][]const u8{ "app", "--port", "9090" };

    // This is called "root_flags" because these are flags for the root command,
    // and sourceopt can work with subcommands, which have their own flags.
    const root_flags = [_]Flag{
        Flag.u16("port", 'p', &port),
        Flag.bool("verbose", 'v', &verbose),
    };

    // Create some sources.
    // These are additive in relation to basic command line parsing,
    // which is always enabled.
    const sources: [0]Source = .{};
    _ = sources;

    const root_commands: [0]Command = .{};

    // Create the root group and assign the flags and sources.
    // This example has no subcommands.
    var root = Group{
        .flags = &root_flags,
        .commands = &root_commands,
    };

    var args_iterator = try std.process.argsWithAllocator(std.testing.allocator);
    defer args_iterator.deinit();

    try root.parse(&args_iterator, .{});
    //try std.testing.expectEqual(9090, port);
}
