/*
 * reload.c - reload daemons
 *
 * Copyright (c) 2020 dora2ios
 *
 * BUILD
 *
 * xcrun -sdk iphoneos clang reload.c -arch armv7 -framework CoreFoundation -o CrashHousekeeping && strip CrashHousekeeping && codesign -f -s - -i com.apple.CrashHousekeeping CrashHousekeeping
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <spawn.h>

int main(int argc, const char **argv)
{
    
    const char *jl;
    pid_t pd = 0;
    
    // 1, run dirhelper (substrate, openssl etc.)
    jl = "/.jbd/patchd/helper";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    // 2, load /Library/LaunchDaemons
    jl = "/.jbd/launchctl";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/Library/LaunchDaemons", NULL }, NULL);
    waitpid(pd, NULL, 0);

    // 3, load backboardd
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/.jbd/LaunchDaemons/com.apple.backboardd.plist", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    // 4, load SpringBoard
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, "load", "/.jbd/LaunchDaemons/com.apple.SpringBoard.plist", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    // 5, run originaldaemon
    jl = "/usr/libexec/CrashHousekeeping";
    posix_spawn(&pd, jl, NULL, NULL, (char **)&(const char*[]){ jl, NULL }, NULL);
    waitpid(pd, NULL, 0);

    return 0;
}

