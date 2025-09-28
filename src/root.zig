const std = @import("std");
const Allocator = std.mem.Allocator;

/// An identifying long/short name,
/// and associated `Setter` to handle the value.
///
/// You may implement your own setter,
/// or use any of the built-ins provided in struct `Setter`.
/// See its documentation for more information.
pub const Flag = struct {
    /// Long name.
    /// Matched with flags of format "--name".
    long: []const u8,
    /// Short name.
    /// Matched with a single hyphen: "-s".
    /// Multiple short flags may be batched together: "-svf" == "-s -v -f".
    short: ?u8 = null,
    /// Triggered when a value is found for this flag.
    setter: Setter,
    /// Indicates that the setter for this flag was called.
    found: bool = false,
};

/// Source interface.
/// Enables a `Parser` to find flag values.
pub const Source = struct {
    value_data: *anyopaque,
    value_fn: *const fn (data: *anyopaque, key: []const u8) anyerror!?[]const u8,
    name_fn: *const fn () []const u8,
    describe_fn: *const fn (err: anyerror) []const u8,

    pub fn value(self: *Source, key: []const u8) anyerror!?[]const u8 {
        return try self.value_fn(self.value_data, key);
    }

    // ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨ Built-in ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨
    // ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨

    /// Environment variable source.
    /// Allows sourceopt to discover values in the environment.
    pub const Env = struct {
        /// Used to allocate the temporary memory needed by this source.
        /// Released in `Env.deinit`.
        arena: std.heap.ArenaAllocator,
        /// A stable view of the process environment variables.
        /// Created in `Env.init`.
        env_map: std.process.EnvMap,
        /// Forces the Env source to only consider environment variables that begin with this prefix,
        /// followed by an underscore.
        ///
        /// For example, when the prefix field is null,
        /// a flag with a long name of "port" will match the "PORT" environment variable.
        /// Setting prefix to "banana" means it will match "BANANA_PORT" instead.
        prefix: ?[]const u8,

        /// Return a new `Env`.
        /// Caller must call `Env.deinit` when done.
        pub fn init(alloc: Allocator, o: struct { prefix: ?[]const u8 = null }) !Env {
            return .{
                .arena = std.heap.ArenaAllocator.init(alloc),
                .env_map = try std.process.getEnvMap(alloc),
                .prefix = o.prefix,
            };
        }

        /// Release all allocated memory.
        /// This will invalidate references to any previously returned values.
        pub fn deinit(self: *Env) void {
            self.env_map.deinit();
            self.arena.deinit();
        }

        /// Search the environment for a value related to key.
        pub fn value(self: *Env, key: []const u8) Allocator.Error!?[]const u8 {
            const key_name = try getKeyName(self.arena.allocator(), self.prefix, key);
            return self.env_map.get(key_name);
        }

        pub fn source(self: *Env) Source {
            const builder = Builder(Env, Allocator.Error){
                .value_data = self,
                .value_fn = struct {
                    fn value(data: *Env, key: []const u8) Allocator.Error!?[]const u8 {
                        return try data.value(key);
                    }
                }.value,
                .name_fn = struct {
                    fn name() []const u8 {
                        return "env";
                    }
                }.name,
                .describe_fn = struct {
                    fn describe(err: Allocator.Error) []const u8 {
                        return switch (err) {
                            Allocator.Error.OutOfMemory => "out of memory",
                        };
                    }
                }.describe,
            };

            return builder.source();
        }

        fn getKeyName(alloc: Allocator, prefix: ?[]const u8, key: []const u8) Allocator.Error![]const u8 {
            // Need to dupe this either way.
            // Don't want any of these mods visible to other parts of the system.
            const prefixed_key = if (prefix != null and prefix.?.len > 0)
                try std.fmt.allocPrint(alloc, "{s}_{s}", .{ prefix.?, key })
            else
                try alloc.dupe(u8, key);

            // Ascii only. Probably fine.
            for (prefixed_key) |*c|
                c.* = std.ascii.toUpper(c.*);

            return prefixed_key;
        }

        test getKeyName {
            const prefix = "banana";
            const key = "port";

            const r1 = try Source.Env.getKeyName(std.testing.allocator, prefix, key);
            defer std.testing.allocator.free(r1);

            try std.testing.expectEqualSlices(u8, "BANANA_PORT", r1);
            // Make sure it didn't modify the prefix/key data.
            try std.testing.expectEqualSlices(u8, "banana", prefix);
            try std.testing.expectEqualSlices(u8, "port", key);

            // Null prefix and empty string are handled the same.
            const r2 = try Source.Env.getKeyName(std.testing.allocator, null, key);
            defer std.testing.allocator.free(r2);
            try std.testing.expectEqualSlices(u8, "PORT", r2);

            const r3 = try Source.Env.getKeyName(std.testing.allocator, "", key);
            defer std.testing.allocator.free(r3);
            try std.testing.expectEqualSlices(u8, "PORT", r3);
        }
    }; // Env

    // ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧
    // ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧ Built-in ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧

    /// Builder allows you to fill in the multiple dependent fields
    /// of a `Source` in a type-safe way,
    /// and exposes `Builder.source` to return the source.
    pub fn Builder(comptime Data: type, comptime Error: type) type {
        return struct {
            const Self = @This();

            pub fn source(self: *const Self) Source {
                return .{
                    .value_data = self.value_data,
                    .value_fn = @ptrCast(self.value_fn),
                    .name_fn = self.name_fn,
                    .describe_fn = @ptrCast(self.describe_fn),
                };
            }

            value_data: *Data,
            value_fn: *const fn (data: *Data, key: []const u8) Error!?[]const u8,
            name_fn: *const fn () []const u8,
            describe_fn: *const fn (err: Error) []const u8,
        };
    }
}; // Source

/// Setter interface.
/// This type handles the conversion of raw bytes to typed values.
///
/// Setters *must* be prepared to accept a value,
/// even if they are intended to be switch-style flags that don't need one.
/// This is because a value pulled from a `Source` may be required to have a value.
///
/// As an example, consider the built-in `Setter.@"bool"`.
/// When called without a value, it will toggle a boolean.
/// If a flag associated with this setter is pulled from a source that reads a JSON file,
/// it will almost certainly be associated with an explicit boolean value.
///
/// With this in mind, the bool setter will inspect any provided value,
/// and return an error unless it is a literal boolean: "true" or "false".
/// Assuming valid input, it will set its boolean to the according state,
/// or resort to its default toggle behavior.
pub const Setter = struct {
    set_data: *anyopaque,
    set_fn: *const fn (data: *anyopaque, value: ?[]const u8) anyerror!void,
    describe: *const fn (err: anyerror) []const u8,
    require_value: bool,

    pub fn set(self: *const Setter, value: ?[]const u8) anyerror!void {
        try self.set_fn(self.set_data, value);
    }

    // ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨ Built-in ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨
    // ∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨∨

    /// Returns an options type that can be used to customize
    /// the behavior of the built-in setters.
    pub fn Opts(comptime Error: type) type {
        return struct {
            /// Define a new error handler for the setter.
            /// This affords control over the built-in setter error messages.
            describe: ?*const fn (Error) []const u8 = null,
        };
    }

    /// Additional built-ins which allocate memory.
    /// These require a bit more care, see the doc comments for details.
    pub const Allocating = struct {
        /// TODO
        pub const Bytes = struct {
            alloc: Allocator,
            ptr: *[]const u8,
            /// Tracks the previous allocation.
            /// The setter expects this field to be initialized as null.
            /// If you allocate a `Bytes` on the heap, be sure to set this field to null,
            /// or a segfault may occur as the setter attempts to free it.
            ///
            /// Calling `Bytes.deinit` will free this slice,
            /// if the setter ever made an allocation.
            /// If the setter is called multiple times, it will free the previous allocation.
            prev_alloc: ?[]const u8 = null,

            pub fn deinit(self: *Bytes) void {
                if (self.prev_alloc) |prev| self.alloc.free(prev);
            }
        };

        /// TODO
        pub fn @"[]const u8"(bytes: *Bytes, opts: Opts(Allocator.Error)) Setter {
            const builder = Builder(Bytes, Allocator.Error){
                .set_data = bytes,
                .set_fn = struct {
                    fn set(data: *Bytes, value: ?[]const u8) Allocator.Error!void {
                        std.debug.assert(value != null);

                        const new_value = value.?;
                        const duped = try data.alloc.dupe(u8, new_value);
                        // Clean up old value.
                        if (data.prev_alloc) |prev| data.alloc.free(prev);
                        data.ptr.* = duped;
                        data.prev_alloc = duped;
                    }
                }.set,
                .describe = opts.describe orelse struct {
                    fn describe(err: Allocator.Error) []const u8 {
                        return switch (err) {
                            Allocator.Error.OutOfMemory => "out of memory",
                        };
                    }
                }.describe,
                .require_value = true,
            };
            return builder.setter();
        }

        test "allocating []const u8" {
            var name: []const u8 = "liquid";
            try std.testing.expectEqualStrings("liquid", name);
            try std.testing.expectEqual(6, name.len);

            var bytes = Setter.Allocating.Bytes{
                .alloc = std.testing.allocator,
                .ptr = &name,
            };
            // Deinit will free the duped value, but only if the setter was called.
            defer bytes.deinit();

            // Calling deinit right here will be a no-op -- "name" is static memory,
            // the setter was never called, so nothing was duped.
            // It won't try to free static memory.

            const setter1 = Setter.Allocating.@"[]const u8"(&bytes, .{});
            try setter1.set("solid");
            try std.testing.expectEqualStrings("solid", name);
            try std.testing.expectEqual(5, name.len);

            // Now deinit will run and actually free "name" because the setter knows
            // that it was actually called, and so it duped memory.
        }
    };

    /// Bytes setter.
    /// Assigns a value with no modification.
    /// This setter is infallible.
    ///
    /// For an equivalent setter that dupes all values,
    /// see `Allocating.@"[]const u8"`.
    pub fn @"[]const u8"(ptr: *[]const u8) Setter {
        const builder = Builder([]const u8, error{}){
            .set_data = @ptrCast(ptr),
            .set_fn = struct {
                fn set(data: *[]const u8, value: ?[]const u8) error{}!void {
                    std.debug.assert(value != null);
                    data.* = value.?;
                }
            }.set,
            .describe = struct {
                fn describe(_: error{}) []const u8 {
                    unreachable;
                }
            }.describe,
            .require_value = true,
        };
        return builder.setter();
    }

    test @"[]const u8" {
        var a1: []const u8 = "";
        const setter1 = Setter.@"[]const u8"(&a1);
        try setter1.set("pear");
        try std.testing.expectEqualStrings("pear", a1);
        try std.testing.expectEqual(4, a1.len);
    }

    /// Boolean setter.
    /// Converts a value to boolean.
    /// This setter works with or without a value,
    /// but if a value is provided, it must be either "true" or "false,
    /// and will set the boolean accordingly.
    ///
    /// When this setter is called with a null or empty value,
    /// it will toggle the boolean.
    pub fn @"bool"(ptr: *bool, opts: Opts(error{InvalidBoolean})) Setter {
        const builder = Builder(bool, error{InvalidBoolean}){
            .set_data = ptr,
            .set_fn = struct {
                fn set(data: *bool, value: ?[]const u8) error{InvalidBoolean}!void {
                    if (value) |v| {
                        if (std.mem.eql(u8, v, "true")) {
                            data.* = true;
                            return;
                        } else if (std.mem.eql(u8, v, "false")) {
                            data.* = false;
                            return;
                        } else if (v.len == 0) {
                            data.* = !data.*;
                            return;
                        }
                        return error.InvalidBoolean;
                    }
                    data.* = !data.*;
                }
            }.set,
            .describe = opts.describe orelse struct {
                fn describe(err: error{InvalidBoolean}) []const u8 {
                    return switch (err) {
                        error.InvalidBoolean => "explicit boolean flag value must be true or false",
                    };
                }
            }.describe,
            .require_value = false,
        };
        return builder.setter();
    }

    test @"bool" {
        var storage: bool = false;
        try std.testing.expectEqual(false, storage);

        const setter = Setter.bool(&storage, .{});

        // Toggle (no value)
        try setter.set(null);
        try std.testing.expectEqual(true, storage);

        // Toggle (empty value)
        try setter.set("");
        try std.testing.expectEqual(false, storage);

        // Set it to true twice, it should remain true.
        // This is to make sure calling the setter with a value
        // doesn't just toggle it.
        try setter.set("true");
        try std.testing.expectEqual(true, storage);
        try setter.set("true");
        try std.testing.expectEqual(true, storage);

        try setter.set("false");
        try std.testing.expectEqual(false, storage);
    }

    /// Unsigned integer setter.
    /// Converts a value to the provided type T, which may be any unsigned integer.
    pub fn unsigned(comptime T: type, ptr: *T, opts: Opts(std.fmt.ParseIntError)) Setter {
        comptime {
            const Info = @typeInfo(T);
            if (Info != .int or Info.int.signedness != .unsigned) {
                @compileError("T must be an unsigned integer");
            }
        }

        const bits = @bitSizeOf(T);
        const max_val: comptime_int = (1 << bits) - 1;

        const range = comptime blk: {
            break :blk std.fmt.comptimePrint("0..={d}", .{max_val});
        };

        const builder = Builder(T, std.fmt.ParseIntError){
            .set_data = ptr,
            .set_fn = struct {
                fn set(data: *T, value: ?[]const u8) std.fmt.ParseIntError!void {
                    std.debug.assert(value != null);
                    data.* = try std.fmt.parseUnsigned(T, value.?, 10);
                }
            }.set,
            .describe = opts.describe orelse struct {
                fn describe(err: std.fmt.ParseIntError) []const u8 {
                    return switch (err) {
                        error.Overflow => "value must be in range of " ++ range,
                        error.InvalidCharacter => "value must be an integer in range of " ++ range,
                    };
                }
            }.describe,
            .require_value = true,
        };
        return builder.setter();
    }

    test unsigned {
        var a: u8 = 1;
        const setter1 = Setter.unsigned(u8, &a, .{});
        try setter1.set_fn(&a, "255");
        try std.testing.expectEqual(255, a);
        try std.testing.expectEqual(true, setter1.require_value);
        try std.testing.expectError(error.Overflow, setter1.set_fn(&a, "256"));
        try std.testing.expectError(error.InvalidCharacter, setter1.set_fn(&a, "a1"));

        var b: u16 = 0;
        const setter2 = Setter.unsigned(u16, &b, .{});
        try setter2.set_fn(&b, "65535");
        try std.testing.expectEqual(65535, b);
        try std.testing.expectEqual(true, setter2.require_value);
        try std.testing.expectError(error.Overflow, setter2.set_fn(&b, "65536"));
        try std.testing.expectError(error.InvalidCharacter, setter2.set_fn(&b, "a1"));

        var c: u9 = 0;
        const setter3 = Setter.unsigned(u9, &c, .{});
        try setter3.set_fn(&c, "511");
        try std.testing.expectEqual(511, c);
        try std.testing.expectEqual(true, setter3.require_value);
        try std.testing.expectError(error.Overflow, setter3.set_fn(&c, "512"));
        try std.testing.expectError(error.InvalidCharacter, setter3.set_fn(&c, "a1"));
    }

    // ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧
    // ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧ Built-in ∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧∧

    /// Builder allows you to fill in the multiple dependent fields
    /// of a `Setter` in a type-safe way,
    /// and exposes `Builder.setter` to return the setter.
    pub fn Builder(comptime Data: type, comptime Error: type) type {
        return struct {
            const Self = @This();

            /// Return a `Setter` from the `Builder`.
            pub fn setter(self: *const Self) Setter {
                return .{
                    .set_data = @ptrCast(self.set_data),
                    .set_fn = @ptrCast(self.set_fn),
                    .describe = @ptrCast(self.describe),
                    .require_value = self.require_value,
                };
            }

            set_data: *Data,
            set_fn: *const fn (data: *Data, value: ?[]const u8) Error!void,
            describe: *const fn (err: Error) []const u8,
            require_value: bool,
        };
    }
}; // Env

/// The primary sourceopt type.
/// Store flags and sources inside an instance of `Parser`,
/// and then use `Parser.parse`.
pub const Parser = struct {
    flags: []Flag,
    sources: []const Source,

    pub const ParseOpts = struct {
        /// Enables error diagnostics.
        diagnostic: ?*Diagnostic = null,
        /// When a positional buffer is provided,
        /// positionals that are not registered subcommands will be appended to it.
        ///
        /// Without a buffer, all positionals are treated as unexpected arguments,
        /// and cause `ParseError.UnexpectedArgument` to be returned.
        positional_buf: ?PositionalBuf = null,
    };

    /// Positional argument buffer.
    /// The allocator may be null, in which case, appending to buf will use `ArrayList.appendAssumeCapacity`.
    /// Otherwise, the typical `ArrayList.append` is used with the allocator.
    pub const PositionalBuf = struct {
        alloc: ?Allocator,
        buf: *std.ArrayList([]const u8),

        pub fn append(self: *PositionalBuf, arg: []const u8) Allocator.Error!void {
            var buf = self.buf;
            if (self.alloc) |alloc| try buf.append(alloc, arg) else {
                if (buf.items.len == buf.capacity) return Allocator.Error.OutOfMemory;
                buf.appendAssumeCapacity(arg);
            }
        }
    };

    pub const Diagnostic = struct {
        /// The raw argument text.
        /// Always set.
        argument: []const u8 = "",
        /// Flag setter error description.
        /// Set by `Setter.describe` when argument is related to a known flag,
        /// and the flag setter was called and returned an error.
        flag_setter_error_desc: []const u8 = "",
        /// Flag value.
        /// Set when argument is related to a known flag,
        /// and the value of that flag was known at time of error.
        flag_value: []const u8 = "",
        /// Name of source being used at time of error.
        /// Empty when an error was returned while handling arguments
        /// from the provided iterator.
        source_name: []const u8 = "",
        /// Source error description.
        /// Set by `Source.describe` when a source has returned an error.
        source_error_desc: []const u8 = "",
    };

    pub const ParseError = error{
        /// Found an unexpected argument.
        UnexpectedArgument,
        /// Found a flag not described in the flag scope.
        UnknownFlag,
        /// Flag requires a value, but a value was not found in the arguments
        /// or any provided source.
        MissingValue,
        /// Flag received an invalid value.
        /// This means the `Setter` registered to the flag has returned an error.
        InvalidValue,
        /// Source returned an error.
        SourceError,
    };

    pub fn parse(self: *const Parser, args: Iterator, o: ParseOpts) ParseError!void {
        const flag_scope = self.flags;

        // First stage.
        // Handle arguments first.
        var iter = args;
        while (iter.next()) |arg| {
            if (!std.mem.startsWith(u8, arg, "-")) {
                // Argument is a positional.
                if (o.positional_buf) |buf| {
                    var bb = buf;
                    bb.append(arg) catch {
                        if (o.diagnostic) |d| d.argument = arg;
                        return ParseError.UnexpectedArgument;
                    };
                    continue;
                }
                if (o.diagnostic) |d| d.argument = arg;
                return ParseError.UnexpectedArgument;
            }

            // Argument is a flag.
            var chunker = ArgChunker{ .arg = arg };
            while (chunker.next()) |chunk| {
                var flag = getFlagEquals(flag_scope, chunk.name) orelse {
                    if (o.diagnostic) |d| d.argument = chunk.name;
                    return ParseError.UnexpectedArgument;
                };

                const setter = flag.setter;

                // Only attempt to read another argument when the setter requires a value,
                // and one was not already contained in the chunk.
                const value = chunk.value orelse
                    if (setter.require_value) iter.next() else null;

                // If the setter needs a value, lets make sure it has one.
                // Additionally, if the value happens to look like a flag, something is probably wrong.
                if (setter.require_value and (value == null or std.mem.startsWith(u8, value.?, "-"))) {
                    if (o.diagnostic) |d| d.argument = chunk.name;
                    return ParseError.MissingValue;
                }

                // At this point, if the setter requires a value,
                // value should never be null.
                if (setter.require_value) std.debug.assert(value != null);

                setter.set(value) catch |err| {
                    if (o.diagnostic) |d| {
                        d.argument = chunk.name;
                        d.flag_setter_error_desc = setter.describe(err);
                        d.flag_value = value orelse "";
                    }
                    return ParseError.InvalidValue;
                };
                flag.found = true;
            }
        }

        // Second stage.
        // Pass any unset flags through the sources.
        // This is the "source" in sourceopt!
        iter_flag: for (flag_scope) |*flag| {
            // Sources only receive the long name.
            // Seems reasonable, but could also pass both and let the source decide.
            if (flag.found) continue;

            const long = flag.long;
            const setter = flag.setter;

            // Sources at the head of the slice are highest priority.
            // For example, with sources [A, B],
            // If a value is found for flag in A, B is never checked.
            var value: ?[]const u8 = null;
            for (self.sources) |source| {
                var source_mut = source;
                value = source_mut.value(long) catch |err| {
                    if (o.diagnostic) |d| {
                        d.argument = long;
                        d.source_error_desc = source.describe_fn(err);
                        d.source_name = source.name_fn();
                    }
                    return ParseError.SourceError;
                };

                if (value) |v| {
                    setter.set(v) catch |err| {
                        if (o.diagnostic) |d| {
                            d.argument = long;
                            d.flag_setter_error_desc = setter.describe(err);
                            d.flag_value = v;
                        }
                        return ParseError.InvalidValue;
                    };
                    flag.found = true;
                    // Continue at the next unset flag.
                    continue :iter_flag;
                }
            }
        }
    } // parse

    /// Linear O(n) search through a set of flags,
    /// comparing name to the long and short name of each flag.
    /// The name must exactly match.
    fn getFlagEquals(flags: []Flag, name: []const u8) ?*Flag {
        for (flags) |*flag| {
            if (std.mem.eql(u8, name, flag.long))
                return flag;

            if (flag.short) |short_char| {
                if (name.len == 1 and name[0] == short_char)
                    return flag;
            }
        }

        return null;
    }

    test getFlagEquals {
        const help_flag = Flag{
            .long = "help",
            .short = 'h',
            .setter = undefined,
        };
        var flags = [_]Flag{
            help_flag,
        };

        try std.testing.expectEqualDeep(&help_flag, getFlagEquals(&flags, "help"));
        try std.testing.expectEqualDeep(&help_flag, getFlagEquals(&flags, "h"));
        try std.testing.expectEqual(null, getFlagEquals(&flags, "thing"));
    }
}; // Parser

/// Iterator interface.
/// Used by `Parser` to iterate over arguments.
pub const Iterator = struct {
    next_data: *anyopaque,
    next_fn: *const fn (data: *anyopaque) ?[]const u8,

    pub fn next(self: *Iterator) ?[]const u8 {
        return self.next_fn(self.next_data);
    }

    /// Process iterator.
    /// Iterates over the process arguments.
    pub const Process = struct {
        const InnerType = std.process.ArgIterator;
        inner_iterator: InnerType,

        /// Initialize a new `Process` iterator.
        /// You must call `Process.deinit` when done.
        pub fn init(allocator: Allocator) !Process {
            const inner_iterator = try std.process.argsWithAllocator(allocator);
            return .{
                .inner_iterator = inner_iterator,
            };
        }

        /// Deinitialize the `Process`.
        /// Releases all allocated memory.
        pub fn deinit(self: *Process) void {
            self.inner_iterator.deinit();
        }

        pub fn interface(self: *Process) Iterator {
            return Iterator{
                .next_fn = &Process.next,
                .next_data = &self.inner_iterator,
            };
        }

        fn next(data: *anyopaque) ?[]const u8 {
            const it: *InnerType = @ptrCast(@alignCast(data));
            return it.next();
        }
    };

    /// Fixed iterator.
    /// Iterates over a comptime known set of arguments.
    pub const Fixed = struct {
        items: []const []const u8,
        index: usize = 0,

        pub fn iterator(self: *Fixed) Iterator {
            return Iterator{
                .next_fn = &Fixed.next,
                .next_data = self,
            };
        }

        fn next(data: *anyopaque) ?[]const u8 {
            var self: *Fixed = @ptrCast(@alignCast(data));
            if (self.index >= self.items.len) return null;
            const arg = self.items[self.index];
            self.index += 1;
            return arg;
        }
    };

    test Fixed {
        var fixed = Fixed{ .items = &[2][]const u8{ "a", "b" } };
        var iterator = fixed.iterator();

        const a = iterator.next_fn(iterator.next_data);
        const b = iterator.next_fn(iterator.next_data);
        const null1 = iterator.next_fn(iterator.next_data);
        const null2 = iterator.next_fn(iterator.next_data);

        try std.testing.expectEqualSlices(u8, a.?, "a");
        try std.testing.expectEqualSlices(u8, b.?, "b");
        try std.testing.expectEqual(null1, null);
        try std.testing.expectEqual(null2, null);
    }

    /// An empty `Fixed` iterator.
    /// Useful when you want to parse from sources only.
    pub const Empty = Iterator{
        .next_fn = struct {
            fn next(_: *anyopaque) ?[]const u8 {
                return null;
            }
        }.next,
        .next_data = &.{},
    };
}; // Iterator

const ArgChunker = struct {
    arg: []const u8,
    pos: usize = 0,
    state: ?enum { short, long } = null,

    pub const Chunk = struct {
        name: []const u8,
        value: ?[]const u8,
    };

    pub fn next(self: *ArgChunker) ?Chunk {
        std.debug.assert(self.arg.len > 0);
        if (self.pos >= self.arg.len) return null;

        // One-time initialization.
        if (self.state == null)
            self.state = if (std.mem.startsWith(u8, self.arg, "--")) .long else .short;

        switch (self.state.?) {
            .long => {
                if (self.pos > 0) return null;
                self.pos = self.arg.len;

                return if (std.mem.indexOfScalar(u8, self.arg, '=')) |eq_index|
                    .{
                        .name = self.arg[2..eq_index],
                        .value = self.arg[(eq_index + 1)..],
                    }
                else
                    .{
                        .name = self.arg[2..],
                        .value = null,
                    };
            },
            .short => {
                self.pos += 1;
                if (self.pos >= self.arg.len) return null;

                return .{
                    .name = self.arg[self.pos .. self.pos + 1],
                    .value = null,
                };
            },
        }
    }
};

test ArgChunker {
    var chunker = ArgChunker{ .arg = "--verbose" };
    const chunk1 = chunker.next() orelse unreachable;
    try std.testing.expectEqualStrings("verbose", chunk1.name);
    try std.testing.expectEqual(null, chunk1.value);
    try std.testing.expect(chunker.next() == null);

    var chunker2 = ArgChunker{ .arg = "--port=8080" };
    const chunk2 = chunker2.next() orelse unreachable;
    try std.testing.expectEqualStrings("port", chunk2.name);
    try std.testing.expectEqualStrings("8080", chunk2.value.?);
    try std.testing.expect(chunker2.next() == null);

    var chunker3 = ArgChunker{ .arg = "-la" };
    const chunk3a = chunker3.next() orelse unreachable;
    try std.testing.expectEqualStrings("l", chunk3a.name);
    try std.testing.expectEqual(null, chunk3a.value);
    const chunk3b = chunker3.next() orelse unreachable;
    try std.testing.expectEqualStrings("a", chunk3b.name);
    try std.testing.expectEqual(null, chunk3b.value);
    try std.testing.expect(chunker3.next() == null);
}

// Examples

const PROG_NAME = "example";

const HELP =
    \\\example
    \\\
    \\\FLAGS:
    \\\    ...
;

// Basic parser usage with simple built-in flag setters.
test "basic flags" {
    var help: bool = false;
    const help_setter = Setter.bool(&help, .{});
    const help_flag = Flag{ .long = "help", .short = 'h', .setter = help_setter };

    var verbose: bool = false;
    const verbose_setter = Setter.bool(&verbose, .{});
    const verbose_flag = Flag{ .long = "verbose", .short = 'v', .setter = verbose_setter };

    var port: u16 = 8080;
    const port_setter = Setter.unsigned(u16, &port, .{});
    const port_flag = Flag{ .long = "port", .setter = port_setter };

    try std.testing.expectEqual(false, help);
    try std.testing.expectEqual(false, verbose);
    try std.testing.expectEqual(8080, port);

    var fixed = Iterator.Fixed{
        .items = &[_][]const u8{ "-hv", "--port", "9000" },
    };

    var root_flags = [_]Flag{
        help_flag,
        verbose_flag,
        port_flag,
    };
    var p = Parser{
        .flags = &root_flags,
        .sources = &.{},
    };

    try p.parse(fixed.iterator(), .{});
    try std.testing.expectEqual(true, help);
    try std.testing.expectEqual(true, verbose);
    try std.testing.expectEqual(9000, port);
}

// Building and using a source.
// This example creates a source that pulls values from a hash map,
// which is pretty contrived, but you can imagine pulling values from a config file,
// or something more useful!
test "using sources" {
    // This first part is completely unrelated to sourceopt.
    // Just make a regular old map and stuff some data in there.
    const Map = std.StringHashMap([]const u8);
    var map = Map.init(std.testing.allocator);
    defer map.deinit();

    try map.put("port", "9000");
    try map.put("verbose", "true");

    // This setter wants to receive `*Map` as data,
    // and happens to be infallible, so use an empty error set.
    var builder = Source.Builder(Map, error{}){
        .value_data = &map,
        .value_fn = struct {
            fn value(data: *Map, key: []const u8) error{}!?[]const u8 {
                return data.get(key);
            }
        }.value,
        .describe_fn = struct {
            fn describe(_: error{}) []const u8 {
                // No error to describe, so this will never be called.
                unreachable;
            }
        }.describe,
        .name_fn = struct {
            fn name() []const u8 {
                return "map";
            }
        }.name,
    };

    var port: u16 = 8080;
    const port_setter = Setter.unsigned(u16, &port, .{});
    const port_flag = Flag{ .long = "port", .setter = port_setter };

    var verbose: bool = false;
    const verbose_setter = Setter.bool(&verbose, .{});
    const verbose_flag = Flag{ .long = "verbose", .setter = verbose_setter };

    try std.testing.expectEqual(8080, port);
    try std.testing.expectEqual(false, verbose);

    // Flags must be var, because sourceopt will set the "found" variable in each flag
    // to true if it calls the setter for that flag.
    var root_flags = [_]Flag{
        port_flag,
        verbose_flag,
    };
    // Sources must be const, because sourceopt will not modify the source in any way.
    const root_sources = [_]Source{
        builder.source(),
    };
    const p = Parser{
        .flags = &root_flags,
        .sources = &root_sources,
    };

    // No arguments are provided...
    try p.parse(Iterator.Empty, .{});

    // But the values are still set, thanks to the map source!
    try std.testing.expectEqual(9000, port);
    try std.testing.expectEqual(true, verbose);
}

// TODO
test {
    std.testing.refAllDeclsRecursive(@This());
}
