/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <linux/fs.h>

#include "cutils/misc.h"
#include "cutils/properties.h"
#include "edify/expr.h"
#include "mincrypt/sha.h"
#include "minzip/DirUtil.h"
#include "minelf/Retouch.h"
#include "mtdutils/mounts.h"
#include "mtdutils/mtdutils.h"
#include "updater.h"
#include "applypatch/applypatch.h"
#include "mtdutils/mounts.c"

#ifdef USE_EXT4
#include "make_ext4fs.h"
#endif

static char last_file[PATH_MAX];
// mount(fs_type, partition_type, location, mount_point)
//
//    fs_type="yaffs2" partition_type="MTD"     location=partition
//    fs_type="ext4"   partition_type="EMMC"    location=device
Value* MountFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    if (argc != 4) {
        return ErrorAbort(state, "%s() expects 4 args, got %d", name, argc);
    }
    char* fs_type;
    char* partition_type;
    char* location;
    char* mount_point;
    if (ReadArgs(state, argv, 4, &fs_type, &partition_type,
                 &location, &mount_point) < 0) {
        return NULL;
    }

    if (strlen(fs_type) == 0) {
        ErrorAbort(state, "fs_type argument to %s() can't be empty", name);
        goto done;
    }
    if (strlen(partition_type) == 0) {
        ErrorAbort(state, "partition_type argument to %s() can't be empty",
                   name);
        goto done;
    }
    if (strlen(location) == 0) {
        ErrorAbort(state, "location argument to %s() can't be empty", name);
        goto done;
    }
    if (strlen(mount_point) == 0) {
        ErrorAbort(state, "mount_point argument to %s() can't be empty", name);
        goto done;
    }

#ifdef HAVE_SELINUX
    char *secontext = NULL;

    if (sehandle) {
        selabel_lookup(sehandle, &secontext, mount_point, 0755);
        setfscreatecon(secontext);
    }
#endif

    mkdir(mount_point, 0755);

#ifdef HAVE_SELINUX
    if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
    }
#endif

    if (strcmp(partition_type, "MTD") == 0) {
        mtd_scan_partitions();
        const MtdPartition* mtd;
        mtd = mtd_find_partition_by_name(location);
        if (mtd == NULL) {
            fprintf(stderr, "%s: no mtd partition named \"%s\"",
                    name, location);
            result = strdup("");
            goto done;
        }
        if (mtd_mount_partition(mtd, mount_point, fs_type, 0 /* rw */) != 0) {
            fprintf(stderr, "mtd mount of %s failed: %s\n",
                    location, strerror(errno));
            result = strdup("");
            goto done;
        }
        result = mount_point;
    } else {
        if (mount(location, mount_point, fs_type,
                  MS_NOATIME | MS_NODEV | MS_NODIRATIME, "") < 0) {
            fprintf(stderr, "%s: failed to mount %s at %s: %s\n",
                    name, location, mount_point, strerror(errno));
            result = strdup("");
        } else {
            result = mount_point;
        }
    }

done:
    free(fs_type);
    free(partition_type);
    free(location);
    if (result != mount_point) free(mount_point);
    return StringValue(result);
}


// is_mounted(mount_point)
Value* IsMountedFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    if (argc != 1) {
        return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
    }
    char* mount_point;
    if (ReadArgs(state, argv, 1, &mount_point) < 0) {
        return NULL;
    }
    if (strlen(mount_point) == 0) {
        ErrorAbort(state, "mount_point argument to unmount() can't be empty");
        goto done;
    }

    scan_mounted_volumes();
    const MountedVolume* vol = find_mounted_volume_by_mount_point(mount_point);
    if (vol == NULL) {
        result = strdup("");
    } else {
        result = mount_point;
    }

done:
    if (result != mount_point) free(mount_point);
    return StringValue(result);
}


Value* UnmountFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    if (argc != 1) {
        return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
    }
    char* mount_point;
    if (ReadArgs(state, argv, 1, &mount_point) < 0) {
        return NULL;
    }
    if (strlen(mount_point) == 0) {
        ErrorAbort(state, "mount_point argument to unmount() can't be empty");
        goto done;
    }

    scan_mounted_volumes();
    const MountedVolume* vol = find_mounted_volume_by_mount_point(mount_point);
    if (vol == NULL) {
        fprintf(stderr, "unmount of %s failed; no such volume\n", mount_point);
        result = strdup("");
    } else {
        unmount_mounted_volume(vol);
        result = mount_point;
    }

done:
    if (result != mount_point) free(mount_point);
    return StringValue(result);
}


// format(fs_type, partition_type, location, fs_size, mount_point)
//
//    fs_type="yaffs2" partition_type="MTD"     location=partition fs_size=<bytes> mount_point=<location>
//    fs_type="ext4"   partition_type="EMMC"    location=device    fs_size=<bytes> mount_point=<location>
//    if fs_size == 0, then make_ext4fs uses the entire partition.
//    if fs_size > 0, that is the size to use
//    if fs_size < 0, then reserve that many bytes at the end of the partition
Value* FormatFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    if (argc != 5) {
        return ErrorAbort(state, "%s() expects 5 args, got %d", name, argc);
    }
    char* fs_type;
    char* partition_type;
    char* location;
    char* fs_size;
    char* mount_point;
    int wait_sec = 5;

    if (ReadArgs(state, argv, 5, &fs_type, &partition_type, &location, &fs_size, &mount_point) < 0) {
        return NULL;
    }

    if (strlen(fs_type) == 0) {
        ErrorAbort(state, "fs_type argument to %s() can't be empty", name);
        goto done;
    }
    if (strlen(partition_type) == 0) {
        ErrorAbort(state, "partition_type argument to %s() can't be empty",
                   name);
        goto done;
    }
    if (strlen(location) == 0) {
        ErrorAbort(state, "location argument to %s() can't be empty", name);
        goto done;
    }

    if (strlen(mount_point) == 0) {
        ErrorAbort(state, "mount_point argument to %s() can't be empty", name);
        goto done;
    }

    // The format operation after the WriteMbr may fail because ueventd hasn't create the device node.
    while (wait_sec--) {
        if (access(location, F_OK) == 0)
            break;
        sleep(1);
    }
    if (wait_sec == 0) {
        printf("Time out.\nCan't format %s.(%s)\n", location, strerror(errno));
        ErrorAbort(state, "device %s not exist.", location);
        goto done;
    }
    if (strcmp(partition_type, "MTD") == 0) {
        mtd_scan_partitions();
        const MtdPartition* mtd = mtd_find_partition_by_name(location);
        if (mtd == NULL) {
            fprintf(stderr, "%s: no mtd partition named \"%s\"",
                    name, location);
            result = strdup("");
            goto done;
        }
        MtdWriteContext* ctx = mtd_write_partition(mtd);
        if (ctx == NULL) {
            fprintf(stderr, "%s: can't write \"%s\"", name, location);
            result = strdup("");
            goto done;
        }
        if (mtd_erase_blocks(ctx, -1) == -1) {
            mtd_write_close(ctx);
            fprintf(stderr, "%s: failed to erase \"%s\"", name, location);
            result = strdup("");
            goto done;
        }
        if (mtd_write_close(ctx) != 0) {
            fprintf(stderr, "%s: failed to close \"%s\"", name, location);
            result = strdup("");
            goto done;
        }
        result = location;
#ifdef USE_EXT4
    } else if (strcmp(fs_type, "ext4") == 0) {
        int status = make_ext4fs(location, atoll(fs_size), mount_point, sehandle);
        if (status != 0) {
            fprintf(stderr, "%s: make_ext4fs failed (%d) on %s",
                    name, status, location);
            result = strdup("");
            goto done;
        }
        result = location;
#endif
    } else {
        fprintf(stderr, "%s: unsupported fs_type \"%s\" partition_type \"%s\"",
                name, fs_type, partition_type);
    }

done:
    free(fs_type);
    free(partition_type);
    if (result != location) free(location);
    return StringValue(result);
}


Value* DeleteFn(const char* name, State* state, int argc, Expr* argv[]) {
    char** paths = malloc(argc * sizeof(char*));
    int i;
    for (i = 0; i < argc; ++i) {
        paths[i] = Evaluate(state, argv[i]);
        if (paths[i] == NULL) {
            int j;
            for (j = 0; j < i; ++i) {
                free(paths[j]);
            }
            free(paths);
            return NULL;
        }
    }

    bool recursive = (strcmp(name, "delete_recursive") == 0);

    int success = 0;
    for (i = 0; i < argc; ++i) {
        if ((recursive ? dirUnlinkHierarchy(paths[i]) : unlink(paths[i])) == 0)
            ++success;
        free(paths[i]);
    }
    free(paths);

    char buffer[10];
    sprintf(buffer, "%d", success);
    return StringValue(strdup(buffer));
}


Value* ShowProgressFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc != 2) {
        return ErrorAbort(state, "%s() expects 2 args, got %d", name, argc);
    }
    char* frac_str;
    char* sec_str;
    if (ReadArgs(state, argv, 2, &frac_str, &sec_str) < 0) {
        return NULL;
    }

    double frac = strtod(frac_str, NULL);
    int sec = strtol(sec_str, NULL, 10);

    UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);
    fprintf(ui->cmd_pipe, "progress %f %d\n", frac, sec);

    free(sec_str);
    return StringValue(frac_str);
}

Value* SetProgressFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc != 1) {
        return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
    }
    char* frac_str;
    if (ReadArgs(state, argv, 1, &frac_str) < 0) {
        return NULL;
    }

    double frac = strtod(frac_str, NULL);

    UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);
    fprintf(ui->cmd_pipe, "set_progress %f\n", frac);

    return StringValue(frac_str);
}

// package_extract_dir(package_path, destination_path)
Value* PackageExtractDirFn(const char* name, State* state,
                          int argc, Expr* argv[]) {
    if (argc != 2) {
        return ErrorAbort(state, "%s() expects 2 args, got %d", name, argc);
    }
    char* zip_path;
    char* dest_path;
    if (ReadArgs(state, argv, 2, &zip_path, &dest_path) < 0) return NULL;

    ZipArchive* za = ((UpdaterInfo*)(state->cookie))->package_zip;

    // To create a consistent system image, never use the clock for timestamps.
    struct utimbuf timestamp = { 1217592000, 1217592000 };  // 8/1/2008 default

    bool success = mzExtractRecursive(za, zip_path, dest_path,
                                      MZ_EXTRACT_FILES_ONLY, &timestamp,
                                      NULL, NULL, sehandle);
    free(zip_path);
    free(dest_path);
    return StringValue(strdup(success ? "t" : ""));
}


// package_extract_file(package_path, destination_path)
//   or
// package_extract_file(package_path)
//   to return the entire contents of the file as the result of this
//   function (the char* returned is actually a FileContents*).
Value* PackageExtractFileFn(const char* name, State* state,
                           int argc, Expr* argv[]) {
    if (argc != 1 && argc != 2) {
        return ErrorAbort(state, "%s() expects 1 or 2 args, got %d",
                          name, argc);
    }
    bool success = false;
    if (argc == 2) {
        // The two-argument version extracts to a file.

        char* zip_path;
        char* dest_path;
        if (ReadArgs(state, argv, 2, &zip_path, &dest_path) < 0) return NULL;

        ZipArchive* za = ((UpdaterInfo*)(state->cookie))->package_zip;
        const ZipEntry* entry = mzFindZipEntry(za, zip_path);
        if (entry == NULL) {
            fprintf(stderr, "%s: no %s in package\n", name, zip_path);
            goto done2;
        }

        FILE* f = fopen(dest_path, "wb");
        if (f == NULL) {
            fprintf(stderr, "%s: can't open %s for write: %s\n",
                    name, dest_path, strerror(errno));
            goto done2;
        }
        success = mzExtractZipEntryToFile(za, entry, fileno(f));
        fclose(f);

      done2:
        free(zip_path);
        free(dest_path);
        return StringValue(strdup(success ? "t" : ""));
    } else {
        // The one-argument version returns the contents of the file
        // as the result.

        char* zip_path;
        Value* v = malloc(sizeof(Value));
        v->type = VAL_BLOB;
        v->size = -1;
        v->data = NULL;

        if (ReadArgs(state, argv, 1, &zip_path) < 0) return NULL;

        ZipArchive* za = ((UpdaterInfo*)(state->cookie))->package_zip;
        const ZipEntry* entry = mzFindZipEntry(za, zip_path);
        if (entry == NULL) {
            fprintf(stderr, "%s: no %s in package\n", name, zip_path);
            goto done1;
        }

        v->size = mzGetZipEntryUncompLen(entry);
        v->data = malloc(v->size);
        if (v->data == NULL) {
            fprintf(stderr, "%s: failed to allocate %ld bytes for %s\n",
                    name, (long)v->size, zip_path);
            goto done1;
        }

        success = mzExtractZipEntryToBuffer(za, entry,
                                            (unsigned char *)v->data);

      done1:
        free(zip_path);
        if (!success) {
            free(v->data);
            v->data = NULL;
            v->size = -1;
        }
        return v;
    }
}


// retouch_binaries(lib1, lib2, ...)
Value* RetouchBinariesFn(const char* name, State* state,
                         int argc, Expr* argv[]) {
    UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);

    char **retouch_entries  = ReadVarArgs(state, argc, argv);
    if (retouch_entries == NULL) {
        return StringValue(strdup("t"));
    }

    // some randomness from the clock
    int32_t override_base;
    bool override_set = false;
    int32_t random_base = time(NULL) % 1024;
    // some more randomness from /dev/random
    FILE *f_random = fopen("/dev/urandom", "rb");
    uint16_t random_bits = 0;
    if (f_random != NULL) {
        fread(&random_bits, 2, 1, f_random);
        random_bits = random_bits % 1024;
        fclose(f_random);
    }
    random_base = (random_base + random_bits) % 1024;
    fprintf(ui->cmd_pipe, "ui_print Random offset: 0x%x\n", random_base);
    fprintf(ui->cmd_pipe, "ui_print\n");

    // make sure we never randomize to zero; this let's us look at a file
    // and know for sure whether it has been processed; important in the
    // crash recovery process
    if (random_base == 0) random_base = 1;
    // make sure our randomization is page-aligned
    random_base *= -0x1000;
    override_base = random_base;

    int i = 0;
    bool success = true;
    while (i < (argc - 1)) {
        success = success && retouch_one_library(retouch_entries[i],
                                                 retouch_entries[i+1],
                                                 random_base,
                                                 override_set ?
                                                   NULL :
                                                   &override_base);
        if (!success)
            ErrorAbort(state, "Failed to retouch '%s'.", retouch_entries[i]);

        free(retouch_entries[i]);
        free(retouch_entries[i+1]);
        i += 2;

        if (success && override_base != 0) {
            random_base = override_base;
            override_set = true;
        }
    }
    if (i < argc) {
        free(retouch_entries[i]);
        success = false;
    }
    free(retouch_entries);

    if (!success) {
      Value* v = malloc(sizeof(Value));
      v->type = VAL_STRING;
      v->data = NULL;
      v->size = -1;
      return v;
    }
    return StringValue(strdup("t"));
}


// undo_retouch_binaries(lib1, lib2, ...)
Value* UndoRetouchBinariesFn(const char* name, State* state,
                             int argc, Expr* argv[]) {
    UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);

    char **retouch_entries  = ReadVarArgs(state, argc, argv);
    if (retouch_entries == NULL) {
        return StringValue(strdup("t"));
    }

    int i = 0;
    bool success = true;
    int32_t override_base;
    while (i < (argc-1)) {
        success = success && retouch_one_library(retouch_entries[i],
                                                 retouch_entries[i+1],
                                                 0 /* undo => offset==0 */,
                                                 NULL);
        if (!success)
            ErrorAbort(state, "Failed to unretouch '%s'.",
                       retouch_entries[i]);

        free(retouch_entries[i]);
        free(retouch_entries[i+1]);
        i += 2;
    }
    if (i < argc) {
        free(retouch_entries[i]);
        success = false;
    }
    free(retouch_entries);

    if (!success) {
      Value* v = malloc(sizeof(Value));
      v->type = VAL_STRING;
      v->data = NULL;
      v->size = -1;
      return v;
    }
    return StringValue(strdup("t"));
}


// symlink target src1 src2 ...
//    unlinks any previously existing src1, src2, etc before creating symlinks.
Value* SymlinkFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc == 0) {
        return ErrorAbort(state, "%s() expects 1+ args, got %d", name, argc);
    }
    char* target;
    target = Evaluate(state, argv[0]);
    if (target == NULL) return NULL;

    char** srcs = ReadVarArgs(state, argc-1, argv+1);
    if (srcs == NULL) {
        free(target);
        return NULL;
    }

    int bad = 0;
    int i;
    for (i = 0; i < argc-1; ++i) {
        if (unlink(srcs[i]) < 0) {
            if (errno != ENOENT) {
                fprintf(stderr, "%s: failed to remove %s: %s\n",
                        name, srcs[i], strerror(errno));
                ++bad;
            }
        }
        if (symlink(target, srcs[i]) < 0) {
            fprintf(stderr, "%s: failed to symlink %s to %s: %s\n",
                    name, srcs[i], target, strerror(errno));
            ++bad;
        }
        free(srcs[i]);
    }
    free(srcs);
    if (bad) {
        return ErrorAbort(state, "%s: some symlinks failed", name);
    }
    return StringValue(strdup(""));
}


Value* SetPermFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    bool recursive = (strcmp(name, "set_perm_recursive") == 0);

    int min_args = 4 + (recursive ? 1 : 0);
    if (argc < min_args) {
        return ErrorAbort(state, "%s() expects %d+ args, got %d", name, argc);
    }

    char** args = ReadVarArgs(state, argc, argv);
    if (args == NULL) return NULL;

    char* end;
    int i;
    int bad = 0;

    int uid = strtoul(args[0], &end, 0);
    if (*end != '\0' || args[0][0] == 0) {
        ErrorAbort(state, "%s: \"%s\" not a valid uid", name, args[0]);
        goto done;
    }

    int gid = strtoul(args[1], &end, 0);
    if (*end != '\0' || args[1][0] == 0) {
        ErrorAbort(state, "%s: \"%s\" not a valid gid", name, args[1]);
        goto done;
    }

    if (recursive) {
        int dir_mode = strtoul(args[2], &end, 0);
        if (*end != '\0' || args[2][0] == 0) {
            ErrorAbort(state, "%s: \"%s\" not a valid dirmode", name, args[2]);
            goto done;
        }

        int file_mode = strtoul(args[3], &end, 0);
        if (*end != '\0' || args[3][0] == 0) {
            ErrorAbort(state, "%s: \"%s\" not a valid filemode",
                       name, args[3]);
            goto done;
        }

        for (i = 4; i < argc; ++i) {
            dirSetHierarchyPermissions(args[i], uid, gid, dir_mode, file_mode);
        }
    } else {
        int mode = strtoul(args[2], &end, 0);
        if (*end != '\0' || args[2][0] == 0) {
            ErrorAbort(state, "%s: \"%s\" not a valid mode", name, args[2]);
            goto done;
        }

        for (i = 3; i < argc; ++i) {
            if (chown(args[i], uid, gid) < 0) {
                fprintf(stderr, "%s: chown of %s to %d %d failed: %s\n",
                        name, args[i], uid, gid, strerror(errno));
                ++bad;
            }
            if (chmod(args[i], mode) < 0) {
                fprintf(stderr, "%s: chmod of %s to %o failed: %s\n",
                        name, args[i], mode, strerror(errno));
                ++bad;
            }
        }
    }
    result = strdup("");

done:
    for (i = 0; i < argc; ++i) {
        free(args[i]);
    }
    free(args);

    if (bad) {
        free(result);
        return ErrorAbort(state, "%s: some changes failed", name);
    }
    return StringValue(result);
}


Value* GetPropFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc != 1) {
        return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
    }
    char* key;
    key = Evaluate(state, argv[0]);
    if (key == NULL) return NULL;

    char value[PROPERTY_VALUE_MAX];
    property_get(key, value, "");
    free(key);

    return StringValue(strdup(value));
}


// file_getprop(file, key)
//
//   interprets 'file' as a getprop-style file (key=value pairs, one
//   per line, # comment lines and blank lines okay), and returns the value
//   for 'key' (or "" if it isn't defined).
Value* FileGetPropFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;
    char* buffer = NULL;
    char* filename;
    char* key;
    if (ReadArgs(state, argv, 2, &filename, &key) < 0) {
        return NULL;
    }

    struct stat st;
    if (stat(filename, &st) < 0) {
        ErrorAbort(state, "%s: failed to stat \"%s\": %s",
                   name, filename, strerror(errno));
        goto done;
    }

#define MAX_FILE_GETPROP_SIZE    65536

    if (st.st_size > MAX_FILE_GETPROP_SIZE) {
        ErrorAbort(state, "%s too large for %s (max %d)",
                   filename, name, MAX_FILE_GETPROP_SIZE);
        goto done;
    }

    buffer = malloc(st.st_size+1);
    if (buffer == NULL) {
        ErrorAbort(state, "%s: failed to alloc %d bytes", name, st.st_size+1);
        goto done;
    }

    FILE* f = fopen(filename, "rb");
    if (f == NULL) {
        ErrorAbort(state, "%s: failed to open %s: %s",
                   name, filename, strerror(errno));
        goto done;
    }

    if (fread(buffer, 1, st.st_size, f) != st.st_size) {
        ErrorAbort(state, "%s: failed to read %d bytes from %s",
                   name, st.st_size+1, filename);
        fclose(f);
        goto done;
    }
    buffer[st.st_size] = '\0';

    fclose(f);

    char* line = strtok(buffer, "\n");
    do {
        // skip whitespace at start of line
        while (*line && isspace(*line)) ++line;

        // comment or blank line: skip to next line
        if (*line == '\0' || *line == '#') continue;

        char* equal = strchr(line, '=');
        if (equal == NULL) {
            ErrorAbort(state, "%s: malformed line \"%s\": %s not a prop file?",
                       name, line, filename);
            goto done;
        }

        // trim whitespace between key and '='
        char* key_end = equal-1;
        while (key_end > line && isspace(*key_end)) --key_end;
        key_end[1] = '\0';

        // not the key we're looking for
        if (strcmp(key, line) != 0) continue;

        // skip whitespace after the '=' to the start of the value
        char* val_start = equal+1;
        while(*val_start && isspace(*val_start)) ++val_start;

        // trim trailing whitespace
        char* val_end = val_start + strlen(val_start)-1;
        while (val_end > val_start && isspace(*val_end)) --val_end;
        val_end[1] = '\0';

        result = strdup(val_start);
        break;

    } while ((line = strtok(NULL, "\n")));

    if (result == NULL) result = strdup("");

  done:
    free(filename);
    free(key);
    free(buffer);
    return StringValue(result);
}


static bool write_raw_image_cb(const unsigned char* data,
                               int data_len, void* ctx) {
    int r = mtd_write_data((MtdWriteContext*)ctx, (const char *)data, data_len);
    if (r == data_len) return true;
    fprintf(stderr, "%s\n", strerror(errno));
    return false;
}

// write_raw_image(filename_or_blob, partition)
Value* WriteRawImageFn(const char* name, State* state, int argc, Expr* argv[]) {
    char* result = NULL;

    Value* partition_value;
    Value* contents;
    if (ReadValueArgs(state, argv, 2, &contents, &partition_value) < 0) {
        return NULL;
    }

    char* partition = NULL;
    if (partition_value->type != VAL_STRING) {
        ErrorAbort(state, "partition argument to %s must be string", name);
        goto done;
    }
    partition = partition_value->data;
    if (strlen(partition) == 0) {
        ErrorAbort(state, "partition argument to %s can't be empty", name);
        goto done;
    }
    if (contents->type == VAL_STRING && strlen((char*) contents->data) == 0) {
        ErrorAbort(state, "file argument to %s can't be empty", name);
        goto done;
    }

    mtd_scan_partitions();
    const MtdPartition* mtd = mtd_find_partition_by_name(partition);
    if (mtd == NULL) {
        fprintf(stderr, "%s: no mtd partition named \"%s\"\n", name, partition);
        result = strdup("");
        goto done;
    }

    MtdWriteContext* ctx = mtd_write_partition(mtd);
    if (ctx == NULL) {
        fprintf(stderr, "%s: can't write mtd partition \"%s\"\n",
                name, partition);
        result = strdup("");
        goto done;
    }

    bool success;

    if (contents->type == VAL_STRING) {
        // we're given a filename as the contents
        char* filename = contents->data;
        FILE* f = fopen(filename, "rb");
        if (f == NULL) {
            fprintf(stderr, "%s: can't open %s: %s\n",
                    name, filename, strerror(errno));
            result = strdup("");
            goto done;
        }

        success = true;
        char* buffer = malloc(BUFSIZ);
        int read;
        while (success && (read = fread(buffer, 1, BUFSIZ, f)) > 0) {
            int wrote = mtd_write_data(ctx, buffer, read);
            success = success && (wrote == read);
        }
        free(buffer);
        fclose(f);
    } else {
        // we're given a blob as the contents
        ssize_t wrote = mtd_write_data(ctx, contents->data, contents->size);
        success = (wrote == contents->size);
    }
    if (!success) {
        fprintf(stderr, "mtd_write_data to %s failed: %s\n",
                partition, strerror(errno));
    }

    if (mtd_erase_blocks(ctx, -1) == -1) {
        fprintf(stderr, "%s: error erasing blocks of %s\n", name, partition);
    }
    if (mtd_write_close(ctx) != 0) {
        fprintf(stderr, "%s: error closing write of %s\n", name, partition);
    }

    printf("%s %s partition\n",
           success ? "wrote" : "failed to write", partition);

    result = success ? partition : strdup("");

done:
    if (result != partition) FreeValue(partition_value);
    FreeValue(contents);
    return StringValue(result);
}

// apply_patch_space(bytes)
Value* ApplyPatchSpaceFn(const char* name, State* state,
                         int argc, Expr* argv[]) {
    char* bytes_str;
    if (ReadArgs(state, argv, 1, &bytes_str) < 0) {
        return NULL;
    }

    char* endptr;
    size_t bytes = strtol(bytes_str, &endptr, 10);
    if (bytes == 0 && endptr == bytes_str) {
        ErrorAbort(state, "%s(): can't parse \"%s\" as byte count\n\n",
                   name, bytes_str);
        free(bytes_str);
        return NULL;
    }

    return StringValue(strdup(CacheSizeCheck(bytes) ? "" : "t"));
}


// apply_patch(srcfile, tgtfile, tgtsha1, tgtsize, sha1_1, patch_1, ...)
Value* ApplyPatchFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc < 6 || (argc % 2) == 1) {
        return ErrorAbort(state, "%s(): expected at least 6 args and an "
                                 "even number, got %d",
                          name, argc);
    }

    char* source_filename;
    char* target_filename;
    char* target_sha1;
    char* target_size_str;
    if (ReadArgs(state, argv, 4, &source_filename, &target_filename,
                 &target_sha1, &target_size_str) < 0) {
        return NULL;
    }

    char* endptr;
    size_t target_size = strtol(target_size_str, &endptr, 10);
    if (target_size == 0 && endptr == target_size_str) {
        ErrorAbort(state, "%s(): can't parse \"%s\" as byte count",
                   name, target_size_str);
        free(source_filename);
        free(target_filename);
        free(target_sha1);
        free(target_size_str);
        return NULL;
    }

    int patchcount = (argc-4) / 2;
    Value** patches = ReadValueVarArgs(state, argc-4, argv+4);

    int i;
    for (i = 0; i < patchcount; ++i) {
        if (patches[i*2]->type != VAL_STRING) {
            ErrorAbort(state, "%s(): sha-1 #%d is not string", name, i);
            break;
        }
        if (patches[i*2+1]->type != VAL_BLOB) {
            ErrorAbort(state, "%s(): patch #%d is not blob", name, i);
            break;
        }
    }
    if (i != patchcount) {
        for (i = 0; i < patchcount*2; ++i) {
            FreeValue(patches[i]);
        }
        free(patches);
        return NULL;
    }

    char** patch_sha_str = malloc(patchcount * sizeof(char*));
    for (i = 0; i < patchcount; ++i) {
        patch_sha_str[i] = patches[i*2]->data;
        patches[i*2]->data = NULL;
        FreeValue(patches[i*2]);
        patches[i] = patches[i*2+1];
    }

    int result = applypatch(source_filename, target_filename,
                            target_sha1, target_size,
                            patchcount, patch_sha_str, patches);

    for (i = 0; i < patchcount; ++i) {
        FreeValue(patches[i]);
    }
    free(patch_sha_str);
    free(patches);

    return StringValue(strdup(result == 0 ? "t" : ""));
}

// apply_patch_check(file, [sha1_1, ...])
Value* ApplyPatchCheckFn(const char* name, State* state,
                         int argc, Expr* argv[]) {
    int result = 0;
    if (argc < 1) {
        return ErrorAbort(state, "%s(): expected at least 1 arg, got %d",
                          name, argc);
    }

    char* filename;
    if (ReadArgs(state, argv, 1, &filename) < 0) {
        return NULL;
    }

    printf("Checking %s ...\n", filename);
    /*
     * Some of the symbolic links to shared libraries are created at runtime
     * based on hw being used as these are created at runtime sha1 would be
     * different compared to the one generated by updater-script. As we anyway
     * update the actual file the sym link points to, we can skip ahead sym links.
     */
    if (!CheckSymLink(filename)) {
        printf("%s is a symlink\n", filename);
        result = 0;
        goto ret;
    }

    int patchcount = argc-1;
    char** sha1s = ReadVarArgs(state, argc-1, argv+1);

    result = applypatch_check(filename, patchcount, sha1s);

    int i;
    for (i = 0; i < patchcount; ++i) {
        free(sha1s[i]);
    }
    free(sha1s);

ret:
    return StringValue(strdup(result == 0 ? "t" : ""));
}

Value* UIPrintFn(const char* name, State* state, int argc, Expr* argv[]) {
    char** args = ReadVarArgs(state, argc, argv);
    if (args == NULL) {
        return NULL;
    }

    int size = 0;
    int i;
    for (i = 0; i < argc; ++i) {
        size += strlen(args[i]);
    }
    char* buffer = malloc(size+1);
    size = 0;
    for (i = 0; i < argc; ++i) {
        strcpy(buffer+size, args[i]);
        size += strlen(args[i]);
        free(args[i]);
    }
    free(args);
    buffer[size] = '\0';

    char* line = strtok(buffer, "\n");
    while (line) {
        fprintf(((UpdaterInfo*)(state->cookie))->cmd_pipe,
                "ui_print %s\n", line);
        line = strtok(NULL, "\n");
    }
    fprintf(((UpdaterInfo*)(state->cookie))->cmd_pipe, "ui_print\n");

    return StringValue(buffer);
}

Value* WipeCacheFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc != 0) {
        return ErrorAbort(state, "%s() expects no args, got %d", name, argc);
    }
    fprintf(((UpdaterInfo*)(state->cookie))->cmd_pipe, "wipe_cache\n");
    return StringValue(strdup("t"));
}

Value* RunProgramFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc < 1) {
        return ErrorAbort(state, "%s() expects at least 1 arg", name);
    }
    char** args = ReadVarArgs(state, argc, argv);
    if (args == NULL) {
        return NULL;
    }

    char** args2 = malloc(sizeof(char*) * (argc+1));
    memcpy(args2, args, sizeof(char*) * argc);
    args2[argc] = NULL;

    fprintf(stderr, "about to run program [%s] with %d args\n", args2[0], argc);

    pid_t child = fork();
    if (child == 0) {
        execv(args2[0], args2);
        fprintf(stderr, "run_program: execv failed: %s\n", strerror(errno));
        _exit(1);
    }
    int status;
    waitpid(child, &status, 0);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) != 0) {
            fprintf(stderr, "run_program: child exited with status %d\n",
                    WEXITSTATUS(status));
        }
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "run_program: child terminated by signal %d\n",
                WTERMSIG(status));
    }

    int i;
    for (i = 0; i < argc; ++i) {
        free(args[i]);
    }
    free(args);
    free(args2);

    char buffer[20];
    sprintf(buffer, "%d", status);

    return StringValue(strdup(buffer));
}

// Take a sha-1 digest and return it as a newly-allocated hex string.
static char* PrintSha1(uint8_t* digest) {
    char* buffer = malloc(SHA_DIGEST_SIZE*2 + 1);
    int i;
    const char* alphabet = "0123456789abcdef";
    for (i = 0; i < SHA_DIGEST_SIZE; ++i) {
        buffer[i*2] = alphabet[(digest[i] >> 4) & 0xf];
        buffer[i*2+1] = alphabet[digest[i] & 0xf];
    }
    buffer[i*2] = '\0';
    return buffer;
}

// sha1_check(data)
//    to return the sha1 of the data (given in the format returned by
//    read_file).
//
// sha1_check(data, sha1_hex, [sha1_hex, ...])
//    returns the sha1 of the file if it matches any of the hex
//    strings passed, or "" if it does not equal any of them.
//
Value* Sha1CheckFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc < 1) {
        return ErrorAbort(state, "%s() expects at least 1 arg", name);
    }

    Value** args = ReadValueVarArgs(state, argc, argv);
    if (args == NULL) {
        return NULL;
    }

    if (args[0]->size < 0) {
        fprintf(stderr, "%s(): no file contents received", name);
		fprintf(stderr, "last file is %s\n", last_file);
        return StringValue(strdup(""));
    }
    uint8_t digest[SHA_DIGEST_SIZE];
    SHA(args[0]->data, args[0]->size, digest);
    FreeValue(args[0]);

    if (argc == 1) {
        return StringValue(PrintSha1(digest));
    }

    int i;
    uint8_t* arg_digest = malloc(SHA_DIGEST_SIZE);
    for (i = 1; i < argc; ++i) {
        if (args[i]->type != VAL_STRING) {
            fprintf(stderr, "%s(): arg %d is not a string; skipping",
                    name, i);
        } else if (ParseSha1(args[i]->data, arg_digest) != 0) {
            // Warn about bad args and skip them.
            fprintf(stderr, "%s(): error parsing \"%s\" as sha-1; skipping",
                    name, args[i]->data);
        } else if (memcmp(digest, arg_digest, SHA_DIGEST_SIZE) == 0) {
            break;
        }
        FreeValue(args[i]);
    }
    if (i >= argc) {
        // Didn't match any of the hex strings; return false.
		fprintf(stderr, "Sha1Check error. Last file is %s.\n", last_file);
        return StringValue(strdup(""));
    }
    // Found a match; free all the remaining arguments and return the
    // matched one.
    int j;
    for (j = i+1; j < argc; ++j) {
        FreeValue(args[j]);
    }
    return args[i];
}

#define TABLE_SIGNATURE 0x1FE
#define MBR_BLOCK_SIZE  512
#define OFFSET_TYPE 0x4
#define OFFSET_FIRST_SEC    0x8
#define TABLE_ENTRY_0   0x1BE
#define TABLE_ENTRY_1   0x1CE
#define TABLE_ENTRY_SIZE    0x10
#define MBR_EBR_TYPE    0x5
#define MBR_EBR_SIZE_OFFSET 0x1FA // The offset indicating size of EBR table in MBR partition
#define EBR_SIZE_OFFSET 0x1CA   // The offset indicatiing size of extended partition in EBR table
#define MMC_MBR_SIGNATURE_BYTE_0  0x55
#define MMC_MBR_SIGNATURE_BYTE_1  0xAA

#define FORCE_FLASH_EBR_IN_TOLERANCE
#define FORCE_FLASH_GROW_IN_TOLERANCE

static int force_install = -1;

int prompt_force_install(State* state, char *header) {

    char temp[10];
    if (force_install == -1) {
        UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);

        // Write the command to recovery to prompt a dialog.
        fprintf(ui->cmd_pipe, "force_install %s\n", header);
        if (fgets(temp, sizeof(temp), ui->ret_pipe) == NULL) {
            fprintf(stderr, "fgets return NULL.(%s)\n", strerror(errno));
            return -1;
        }
        if (strncmp(temp, "Okay", 4) == 0) {
            fprintf(stdout, "Got Okay from recovery\n");
            force_install = 1;
        } else if (strncmp(temp, "Fail", 4) == 0) {
            fprintf(stdout, "Got Fail from recovery\n");
            force_install = 0;
        } else {
            fprintf(stderr, "Got unexpected (%s) from recovery\n",temp);
        }
    }
    return force_install;
}

// Check if the data in the device same as that of the image
// length write OK
// -1 not write
#define EBR_TOLERANCE_SIZE 0x20000 // 64MB
static int check_and_write(State* state, int fd, off_t offset, char *image, int length, int (*func)(State* state, char*)) {
    int ret = 0;
    char *buf = (char*)malloc(length);
    if (buf == NULL) {
        fprintf(stderr, "Can't malloc %d bytes.(%s)\n", length, strerror(errno));
        return -1;
    }
    ret = lseek(fd, offset, SEEK_SET);
    if (ret < 0) {
        fprintf(stderr, "Can't seek to %ld.(%s)\n", offset, strerror(errno));
        return -1;
    }
    ret = read(fd, buf, length);
    if (ret < length) {
        fprintf(stderr, "Read %d bytes from fd failed.(%s)\n", length, strerror(errno));
        return -1;
    }

    if (memcmp(buf, image, length) != 0) {

        if (func) {
            ret = func(state, "Partition changed. Your data may lost. Continue?");
            if (ret != 1) {
                fprintf(stdout, "Partition table flash aborted.\n");
                return -1;
            }
        }

        // XXX Assuming force install if func is NULL
        printf("Writing to %d\n", offset);
        lseek(fd, offset, SEEK_SET);
        ret = write(fd, image, length);
        if (ret != length) {
            // Your phone may have been bricked. :(
            fprintf(stderr, "Write image failed. (%s)\n", strerror(errno));
            return -1;
        }
    } else {
        printf("Skip same partition table at %d\n", offset);
    }
    return length;
}


Value* WriteMbrFn(const char* name, State* state, int argc, Expr* argv[]) {
    int fd = -1;
    int len;
    int i;
    int type = 0;
    char *image = NULL;
    char *image_end = NULL;
    int image_size;
    char *disk = NULL;
    unsigned int ebr_sector_offset;
    unsigned int dfirst_sector;
    int flag = 0;
    char value[PROPERTY_VALUE_MAX];
    char buf[MBR_BLOCK_SIZE];
    int count = 3;
    off_t offset;
    char *result = strdup("Okay");;
    int (*prompt_call_back)(State* state, char*) = prompt_force_install;

    if (argc < 2) {
        return ErrorAbort(state, "%s() expects at least 2 arg", name);
    }

    Value** args = ReadValueVarArgs(state, argc, argv);
    if (args == NULL) {
        return NULL;
    }

    UpdaterInfo* ui = (UpdaterInfo*)(state->cookie);
    if (ui->ret_pipe == NULL) {
        fprintf(ui->cmd_pipe, "ui_print Recovery doesn't support interactive mode\n");
        fprintf(ui->cmd_pipe, "ui_print Please update your recovery.img\n");
        return NULL;
    }
    // FIXME Stop the services may open the device. Hard coded here
    // for killing programs opening the device is also not a good idea.
    property_get("init.svc.rmt_storage", value, "");
    if (strcmp(value, "running") == 0) {
        flag = 1;
        property_set("ctl.stop", "rmt_storage");
        while(count--) {
            property_get("init.svc.rmt_storage", value, "");
            if (strcmp(value, "stopped") == 0)
                break;
            sleep(1);
        }
        if (count == 0) {
            fprintf(stderr, "rmt_storage couldn't be stopped");
            return StringValue(strdup(""));
        }
    }


    image = args[0]->data;
    image_size = args[0]->size;
    image_end = image + image_size;
    disk = args[1]->data;

    if (image_size < 0) {
        fprintf(stderr, "%s(): no file contents received", name);
        result = strdup("");
        goto out;
    }

    // Check if any partition is mounted
    scan_mounted_volumes();
    if (find_mounted_volume_by_device(disk) != NULL) {
        fprintf(stderr, "%s is mounted. WriteMbr aborted.\n", disk);
        result = strdup("");
        goto out;
    }

    // Verify the mbr signature
    if (TABLE_SIGNATURE + 1 > image_size) {
        fprintf(stderr, "Invalid MBR size\n");
        result = strdup("");
        goto out;
    }

    if ((image[TABLE_SIGNATURE] != MMC_MBR_SIGNATURE_BYTE_0) || (image[TABLE_SIGNATURE + 1] != MMC_MBR_SIGNATURE_BYTE_1)) {
        fprintf(stderr, "Invalid MBR signature\n");
        result = strdup("");
        goto out;
    }

    // Write MBR to the corresponding sector
    fd = open(disk, O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "Open %s failed (%s)\n", args[1]->data, strerror(errno));
        result = strdup("");
        goto out;
    }

    // The EBR table in MBR may vary in different EMMC devices. We can skip these changes if the IGNORE_MINOR_MBR_CHANGE
    // defined.
#ifdef FORCE_FLASH_EBR_IN_TOLERANCE
    len = read(fd, buf, MBR_BLOCK_SIZE);
    if (len < MBR_BLOCK_SIZE) {
        fprintf(stderr, "read %d bytes from the device failed.(%s)\n", MBR_BLOCK_SIZE, strerror(errno));
        result = strdup("");
        goto out;
    }
    printf("EBR sectors: 0x%x/0x%x (image/device)\n",
            *(int*)&image[MBR_EBR_SIZE_OFFSET], *(int*)&buf[MBR_EBR_SIZE_OFFSET]);
    if ((image[TABLE_SIGNATURE] == 0x55) &&
            (image[TABLE_SIGNATURE + 1] == 0xAA) &&
            (memcmp(buf, image, MBR_EBR_SIZE_OFFSET) == 0) &&
            (abs(((*(int*)&image[MBR_EBR_SIZE_OFFSET]) - (*(int*)&buf[MBR_EBR_SIZE_OFFSET]))) < EBR_TOLERANCE_SIZE)) {
        printf("Force flash EBR table for the EBR size change is in tolerance\n");
        prompt_call_back = NULL;
    }
#endif

    len = check_and_write(state, fd, 0, image, MBR_BLOCK_SIZE, prompt_call_back);
    if (len < MBR_BLOCK_SIZE) {
        fprintf(stderr, "Write %d bytes to %s failed. (%s)\n", MBR_BLOCK_SIZE, disk, strerror(errno));
        close(fd);
        result = strdup("");
        goto out;
    }

    for (i = 0; i < 4; i++) {
        type = image[TABLE_ENTRY_0 + i * TABLE_ENTRY_SIZE + OFFSET_TYPE];
        if (type == MBR_EBR_TYPE) {
            printf("EBR found\n");
            break;
        }
    }

    if (type != MBR_EBR_TYPE) {
        printf("EBR not found.\n");
        result = strdup("Okay");
        goto out;
    }

    ebr_sector_offset = *(unsigned int*)&image[TABLE_ENTRY_0 + i * TABLE_ENTRY_SIZE + OFFSET_FIRST_SEC];
    image += MBR_BLOCK_SIZE;
    dfirst_sector = 0;
    printf("The first ebr sector will be written to 0x%x\n", ebr_sector_offset);
    while (image < image_end) {
        offset = (off_t)(ebr_sector_offset + dfirst_sector) * MBR_BLOCK_SIZE; //XXX There're big emmc devices
        prompt_call_back = prompt_force_install;

#ifdef FORCE_FLASH_GROW_IN_TOLERANCE
        // The last partition table maybe the grow partition
        if (image_end - image == MBR_BLOCK_SIZE) {
            len = read(fd, buf, MBR_BLOCK_SIZE);
            if (len < MBR_BLOCK_SIZE) {
                fprintf(stderr, "read %d bytes from the device failed.(%s)\n", MBR_BLOCK_SIZE, strerror(errno));
                result = strdup("");
                goto out;
            }
            printf("EBR sectors: 0x%x/0x%x (image/device)\n",
                    *(int*)&image[EBR_SIZE_OFFSET], *(int*)&buf[EBR_SIZE_OFFSET]);
            if ((image[TABLE_SIGNATURE] == 0x55) &&
                    (image[TABLE_SIGNATURE + 1] == 0xAA) &&
                    (memcmp(buf, image, EBR_SIZE_OFFSET) == 0) &&
                    (abs(((*(int*)&image[EBR_SIZE_OFFSET]) - (*(int*)&buf[EBR_SIZE_OFFSET]))) < EBR_TOLERANCE_SIZE)) {
                printf("force install grow partition for the size change is in tolerance\n");
                prompt_call_back = NULL;
            }
        }
#endif
        if(check_and_write(state, fd, offset, image, MBR_BLOCK_SIZE, prompt_call_back) < 0) {
            fprintf(stderr, "Writing to 0x%x failed.(%s)\n", ebr_sector_offset * MBR_BLOCK_SIZE, strerror(errno));
            result = strdup("");
            goto out;
        }

        dfirst_sector = *(unsigned int*)&image[TABLE_ENTRY_1 + OFFSET_FIRST_SEC];
        image += MBR_BLOCK_SIZE;
    }

    // Re-read the partition table
    // Scan if the partition table changed
    // XXX Note: The force install operation of minor changes to EBR size or grow partition size needn't
    // to re-scan the partition table.
    if (force_install == 1) {
        if (ioctl(fd, BLKRRPART, NULL) < 0) {
            fprintf(stderr, "re-scan partition table failed.(%s)\n", strerror(errno));
            result = strdup("");
            goto out;
        }
    }

out:
    // Start the rmt_storage if needed
    if (flag) {
        property_set("ctl.start", "rmt_storage");
    }
    if (fd != -1)
        close(fd);
    return StringValue(strdup(result));
}

static int mtd_partitions_scanned = 0;
enum PartitionType { MTD, EMMC };
Value* VerifyPartitionFn(const char* name, State* state, int argc, Expr* argv[]) {
	char *result;
	enum PartitionType type;
	FileContents file;

	if (argc != 1) {
		return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
	}

	char* filename;
    if (ReadArgs(state, argv, 1, &filename) < 0) return NULL;

	strcpy(last_file, filename);

	char* copy = strdup(filename);
	const char* magic = strtok(copy, ":");

    if (strcmp(magic, "MTD") == 0) {
        type = MTD;
    } else if (strcmp(magic, "EMMC") == 0) {
        type = EMMC;
    } else {
        printf("%s called with bad filename (%s)\n", __FUNCTION__,
               filename);
		result = strdup("");
		goto out_no_free;
    }

	const char* partition = strtok(NULL, ":");

	int colons = 0;
	int i;
	for (i = 0; filename[i] != '\0'; ++i) {
		if (filename[i] == ':') {
			++colons;
		}
	}
	if (colons != 3) {
		printf("VerifyPartition called with bad filename (%s)\n",
				filename);
	}

	int index;
	size_t size;
	char* sha1sum;

	const char* size_str = strtok(NULL, ":");
	size = strtol(size_str, NULL, 10);
	if (size == 0) {
		printf("VerifyPartition called with bad size (%s)\n", filename);
		result = strdup("");
		goto out_no_free;
	}
	sha1sum = strtok(NULL, ":");

	MtdReadContext* ctx = NULL;
	FILE* dev = NULL;

	switch (type) {
		case MTD:
			if (!mtd_partitions_scanned) {
				mtd_scan_partitions();
				mtd_partitions_scanned = 1;
			}

			const MtdPartition* mtd = mtd_find_partition_by_name(partition);
			if (mtd == NULL) {
				printf("mtd partition \"%s\" not found (loading %s)\n",
						partition, filename);
				result = strdup("");
				goto out_no_free;
			}

			ctx = mtd_read_partition(mtd);
			if (ctx == NULL) {
				printf("failed to initialize read of mtd partition \"%s\"\n",
						partition);
				result = strdup("");
				goto out_no_free;
			}
			break;

		case EMMC:
			dev = fopen(partition, "rb");
			if (dev == NULL) {
				printf("failed to open emmc partition \"%s\": %s\n",
						partition, strerror(errno));
				result = strdup("");
				goto out_no_free;
			}
	}

	SHA_CTX sha_ctx;
	SHA_init(&sha_ctx);
	uint8_t parsed_sha[SHA_DIGEST_SIZE];

	// allocate enough memory to hold the largest size.
	file.data = malloc(size);
	char* p = (char*)file.data;
	file.size = 0;                // # bytes read so far

	// Read enough additional bytes to get us up to the next size
	// (again, we're trying the possibilities in order of increasing
	// size).
	size_t read = 0;
	switch (type) {
		case MTD:
			read = mtd_read_data(ctx, p, size);
			break;

		case EMMC:
			read = fread(p, 1, size, dev);
			break;
	}
	if (size != read) {
		printf("short read (%d bytes of %d) for partition \"%s\"\n",
				read, size, partition);
		result = strdup("");
		goto out;
	}
	SHA_update(&sha_ctx, p, read);
	file.size += read;

	// Duplicate the SHA context and finalize the duplicate so we can
	// check it against this pair's expected hash.
	SHA_CTX temp_ctx;
	memcpy(&temp_ctx, &sha_ctx, sizeof(SHA_CTX));
	const uint8_t* sha_so_far = SHA_final(&temp_ctx);

	if (ParseSha1(sha1sum, parsed_sha) != 0) {
		printf("failed to parse sha1 %s in %s\n",
				sha1sum, filename);
		free(file.data);
		file.data = NULL;
		result = strdup("");
		goto out;
	}

	if (memcmp(sha_so_far, parsed_sha, SHA_DIGEST_SIZE) == 0) {
		// we have a match.  stop reading the partition; we'll return
		// the data we've read so far.
		printf("partition read matched size %d sha %s\n",
				size, sha1sum);
		result = strdup(sha1sum);
	}else {
		fprintf(stderr, "Partition verification error %s.", filename);
		result = strdup("");
	}


	switch (type) {
		case MTD:
			mtd_read_close(ctx);
			break;

		case EMMC:
			fclose(dev);
			break;
	}

out:
	free(file.data);
	file.data = NULL;
out_no_free:
//  save_sha1_item(ID_BOOT, success, reason);
	return StringValue(result);

}

// Read a local file and return its contents (the Value* returned
// is actually a FileContents*).
Value* ReadFileFn(const char* name, State* state, int argc, Expr* argv[]) {
    if (argc != 1) {
        return ErrorAbort(state, "%s() expects 1 arg, got %d", name, argc);
    }
    char* filename;
    if (ReadArgs(state, argv, 1, &filename) < 0) return NULL;

	strcpy(last_file, filename);
    Value* v = malloc(sizeof(Value));
    v->type = VAL_BLOB;

    FileContents fc;
    if (LoadFileContents(filename, &fc, RETOUCH_DONT_MASK) != 0) {
        ErrorAbort(state, "%s() loading \"%s\" failed: %s",
                   name, filename, strerror(errno));
        free(filename);
        free(v);
        free(fc.data);
        return NULL;
    }

    v->size = fc.size;
    v->data = (char*)fc.data;

    free(filename);
    return v;
}

void RegisterInstallFunctions() {
    RegisterFunction("mount", MountFn);
    RegisterFunction("is_mounted", IsMountedFn);
    RegisterFunction("unmount", UnmountFn);
    RegisterFunction("format", FormatFn);
    RegisterFunction("show_progress", ShowProgressFn);
    RegisterFunction("set_progress", SetProgressFn);
    RegisterFunction("delete", DeleteFn);
    RegisterFunction("delete_recursive", DeleteFn);
    RegisterFunction("package_extract_dir", PackageExtractDirFn);
    RegisterFunction("package_extract_file", PackageExtractFileFn);
    RegisterFunction("retouch_binaries", RetouchBinariesFn);
    RegisterFunction("undo_retouch_binaries", UndoRetouchBinariesFn);
    RegisterFunction("symlink", SymlinkFn);
    RegisterFunction("set_perm", SetPermFn);
    RegisterFunction("set_perm_recursive", SetPermFn);

    RegisterFunction("getprop", GetPropFn);
    RegisterFunction("file_getprop", FileGetPropFn);
    RegisterFunction("write_raw_image", WriteRawImageFn);

    RegisterFunction("apply_patch", ApplyPatchFn);
    RegisterFunction("apply_patch_check", ApplyPatchCheckFn);
    RegisterFunction("apply_patch_space", ApplyPatchSpaceFn);

    RegisterFunction("read_file", ReadFileFn);
    RegisterFunction("sha1_check", Sha1CheckFn);
    RegisterFunction("verify_partition", VerifyPartitionFn);
    RegisterFunction("write_mbr", WriteMbrFn);

    RegisterFunction("wipe_cache", WipeCacheFn);

    RegisterFunction("ui_print", UIPrintFn);

    RegisterFunction("run_program", RunProgramFn);
}
