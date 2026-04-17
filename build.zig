const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Dependencies
    // ++++++++++++++++++++++++++++++++++++++++++++

    const zbor_dep = b.dependency("zbor", .{
        .target = target,
        .optimize = optimize,
    });
    const zbor_module = zbor_dep.module("zbor");

    const hidapi_dep = b.dependency("hidapi", .{
        .target = target,
        .optimize = optimize,
    });

    const uuid_dep = b.dependency("uuid", .{
        .target = target,
        .optimize = optimize,
    });
    const uuid_module = uuid_dep.module("uuid");

    const clap_dep = b.dependency("clap", .{
        .target = target,
        .optimize = optimize,
    });

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Module
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Authenticator Module
    // ------------------------------------------------

    const keylib_module = b.addModule("keylib", .{
        .root_source_file = b.path("lib/main.zig"),
        .imports = &.{
            .{ .name = "zbor", .module = zbor_module },
            .{ .name = "uuid", .module = uuid_module },
        },
        .target = target,
        .optimize = optimize,
    });

    var uhid_module_exists: bool = false;
    const uhid_module = if (target.result.os.tag == .linux) blk: {
        uhid_module_exists = true;
        const uhid_module = b.addModule("uhid", .{
            .root_source_file = b.path("bindings/linux/src/uhid.zig"),
            .imports = &.{},
            .target = target,
            .optimize = optimize,
        });
        break :blk uhid_module;
    } else blk: {
        const uhid_module = b.addModule("uhid", .{
            .target = target,
            .optimize = optimize,
        });
        break :blk uhid_module;
    };

    // Re-export zbor module
    try b.modules.put(b.allocator, b.dupe("zbor"), zbor_module);

    // Client Module
    // ------------------------------------------------

    const client_module = b.addModule("clientlib", .{
        .root_source_file = b.path("lib/client.zig"),
        .imports = &.{
            .{ .name = "zbor", .module = zbor_module },
            .{ .name = "keylib", .module = keylib_module },
        },
        .target = target,
        .optimize = optimize,
    });
    client_module.linkLibrary(hidapi_dep.artifact("hidapi"));

    // Examples
    // ------------------------------------------------

    // Client Examples
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    const client_examples: []const [2][]const u8 = &.{
        .{ "example/client/info.zig", "info" },
        .{ "example/client/manifest.zig", "manifest" },
        .{ "example/client/select.zig", "select" },
        .{ "example/client/setpin.zig", "setpin" },
        .{ "example/client/reset.zig", "reset" },
        .{ "example/client/cred.zig", "cred" },
        .{ "example/client/metadata.zig", "metadata" },
        .{ "example/client/enumrp.zig", "enumrp" },
        .{ "example/client/enumcred.zig", "enumcred" },
        .{ "example/client/delete.zig", "delete" },
        .{ "example/client/assert.zig", "assert" },
    };

    for (client_examples) |entry| {
        const path, const name = entry;

        const ce_mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
        });

        var ce = b.addExecutable(.{
            .name = name,
            .root_module = ce_mod,
        });
        ce.root_module.addImport("client", client_module);

        ce.root_module.addImport("clap", clap_dep.module("clap"));

        b.installArtifact(ce);
    }

    // Authenticator Examples
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    const authenticator_example_mod = b.createModule(.{
        .root_source_file = b.path("example/authenticator.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    var authenticator_example = b.addExecutable(.{
        .name = "authenticator",
        .root_module = authenticator_example_mod,
    });
    authenticator_example.root_module.addImport("keylib", keylib_module);
    if (uhid_module_exists) {
        authenticator_example.root_module.addImport("uhid", uhid_module);
    }
    authenticator_example.root_module.addImport("zbor", zbor_dep.module("zbor"));

    const authenticator_example_step = b.step("auth-example", "Build the authenticator example");
    authenticator_example_step.dependOn(&b.addInstallArtifact(authenticator_example, .{}).step);

    // C bindings
    // ------------------------------------------------

    //const c_bindings = b.addStaticLibrary(.{
    //    .name = "keylib",
    //    .root_source_file = .{ .path = "bindings/c/src/keylib.zig" },
    //    .target = target,
    //    .optimize = optimize,
    //});
    //c_bindings.root_module.addImport("keylib", keylib_module);
    //c_bindings.linkLibC();
    //c_bindings.installHeadersDirectory(
    //    b.path("bindings/c/include"),
    //    "keylib",
    //    .{
    //        .exclude_extensions = &.{},
    //        .include_extensions = &.{".h"},
    //    },
    //);
    //b.installArtifact(c_bindings);

    //const uhid_mod = b.createModule(.{
    //    .root_source_file = b.path("bindings/linux/src/uhid-c.zig"),
    //    .target = target,
    //    .optimize = optimize,
    //});

    //const uhid = b.addLibrary(.{
    //    .linkage = .static,
    //    .name = "uhid",
    //    .root_module = uhid_mod,
    //});
    //uhid.linkLibC();
    //uhid.installHeadersDirectory(
    //    b.path("bindings/linux/include"),
    //    "keylib",
    //    .{
    //        .exclude_extensions = &.{},
    //        .include_extensions = &.{".h"},
    //    },
    //);
    //b.installArtifact(uhid);

    // ++++++++++++++++++++++++++++++++++++++++++++
    // Tests
    // ++++++++++++++++++++++++++++++++++++++++++++

    // Creates a step for unit testing.
    const lib_tests = b.addTest(.{
        .root_module = keylib_module,
    });

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
}
