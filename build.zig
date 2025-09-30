const std = @import("std");

const EXAMPLES_DIR = "examples/";

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("sourceopt", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    const Example = enum {
        basic,
    };

    const example_option = b.option(Example, "example", "Example to run") orelse .basic;
    const example_step = b.step("example", "Run example");

    const example = b.addExecutable(.{
        .name = "example",
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                b.fmt("{s}/{s}.zig", .{ EXAMPLES_DIR, @tagName(example_option) }),
            ),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "sourceopt", .module = mod },
            },
        }),
    });

    const example_run = b.addRunArtifact(example);
    example_step.dependOn(&example_run.step);
    if (b.args) |args| example_run.addArgs(args);
}
