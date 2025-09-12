const std = @import("std");

pub fn build(b: *std.Build) void {
    // options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // modules
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("lib/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // compilation
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "www",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // build steps
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = lib_mod })).step);
}
