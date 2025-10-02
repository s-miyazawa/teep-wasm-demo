/*
 * Copyright (c) 2020-2023 SECOM CO., LTD. All Rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/stat.h>
#include <sys/types.h> // mkdir
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <utmp.h>
#include <grp.h> // getgrnam
#include <errno.h>
#include "suit_examples_common.h"

ssize_t read_from_file(const char *file_path,
                      uint8_t *buf,
                      const size_t buf_len)
{
    ssize_t read_len = 0;
    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    read_len = read(fd, buf, buf_len);
    int res = close(fd);
    if (read_len < 0 || res < 0) {
        return 0;
    }
    return read_len;
}

#ifdef _WIN32
const char sep = '\\';
#else
const char sep = '/';
#endif
ssize_t write_to_file(const char *file_path,
                      const void *buf,
                      const size_t buf_len)
{
    ssize_t write_len = 0;
    char dir_name[SUIT_MAX_NAME_LENGTH];
    char *next_sep;
    next_sep = (char *)file_path - 1;

    while ((next_sep = strchr(next_sep + 1, sep)) != NULL) {
        const int dir_name_len = next_sep - file_path;
        memcpy(dir_name, file_path, dir_name_len);
        dir_name[dir_name_len] = '\0';
        mkdir(dir_name, 0775);
    }

    int fd = creat(file_path, 0777);
    write_len = write(fd, buf, buf_len);
    close(fd);
    return write_len;
}

uid_t suit_get_user_id_from_actor_id(const suit_actor_id_t actor)
{
    switch (actor.type) {
    case SUIT_ACTOR_TYPE_INT:
        if (actor.actor_id_i64 < 0 || UINT_MAX <= actor.actor_id_i64) {
            return UINT_MAX;
        }
        return actor.actor_id_i64;
    case SUIT_ACTOR_TYPE_TSTR:
        return getlogin_r((char *)actor.actor_id_str.ptr, actor.actor_id_str.len);
    default:
        return UINT_MAX;
    }
}

gid_t suit_get_group_id_from_actor_id(const suit_actor_id_t actor)
{
    char name[UT_NAMESIZE];
    struct group *group;
    switch (actor.type) {
    case SUIT_ACTOR_TYPE_INT:
        if (actor.actor_id_i64 < 0 || UINT_MAX <= actor.actor_id_i64) {
            return UINT_MAX;
        }
        return actor.actor_id_i64;
    case SUIT_ACTOR_TYPE_TSTR:
        memcpy(name, actor.actor_id_str.ptr, actor.actor_id_str.len);
        name[actor.actor_id_str.len] = '\0';
        group = getgrnam(name);
        return group->gr_gid;
    default:
        return UINT_MAX;
    }
}

ssize_t write_to_file_component_metadata(const char *file_path,
                                         const void *buf,
                                         const size_t buf_len,
                                         const suit_component_metadata_t *component_metadata)
{
    int result = 0;
    int fd = 0;
    int terrno = 0;
    ssize_t write_len = -1;
    char dir_name[SUIT_MAX_NAME_LENGTH];
    char *next_sep;
    next_sep = (char *)file_path - 1;

    uid_t user_id = UINT_MAX;
    gid_t group_id = UINT_MAX;
    if (component_metadata->creator.type != SUIT_ACTOR_TYPE_INVALID) {
        user_id = suit_get_user_id_from_actor_id(component_metadata->creator);
        group_id = suit_get_group_id_from_actor_id(component_metadata->creator);
    }

    mode_t dir_permissions = 0775;
    mode_t file_permissions = 0777;
    if (component_metadata->default_permissions.val != 0) {
        dir_permissions = 0;
        file_permissions = 0;
        if (component_metadata->default_permissions.list_read) {
            dir_permissions |= S_IRUSR | S_IRGRP | S_IROTH;
            file_permissions |= S_IRUSR | S_IRGRP | S_IROTH;
        }
        if (component_metadata->default_permissions.create_write) {
            dir_permissions |= S_IWUSR | S_IWGRP | S_IROTH;
            file_permissions |= S_IWUSR | S_IWGRP | S_IROTH;
        }
        if (component_metadata->default_permissions.traverse_exec) {
            dir_permissions |= S_IXUSR | S_IXGRP | S_IXOTH;
            file_permissions |= S_IXUSR | S_IXGRP | S_IXOTH;
        }
    }
    if (component_metadata->user_permissions.len > 0) {
        /* TODO: the default libcsuit handler doesn't handle multiple users */
        suit_permission_pair_t *permission_pair = NULL;
        for (size_t i = 0; i < component_metadata->user_permissions.len; i++) {
            uid_t tmp_user_id = suit_get_user_id_from_actor_id(component_metadata->user_permissions.permission_map[i].actor);
            if (tmp_user_id < 0) {
                return -1;
            }
            if (user_id == tmp_user_id) {
                /* creator matches to user */
                permission_pair = (suit_permission_pair_t *)&component_metadata->user_permissions.permission_map[i];
            }
        }
        if (permission_pair == NULL) {
            /* fallthrough, we regard the first user is the creator */
            permission_pair = (suit_permission_pair_t *)&component_metadata->user_permissions.permission_map[0];
            user_id = suit_get_user_id_from_actor_id(permission_pair->actor);
        }
        if (permission_pair->permissions.list_read) {
            dir_permissions |= S_IRUSR; // allow
            file_permissions |= S_IRUSR; // allow
        }
        else {
            dir_permissions &= ~S_IRUSR; // prohibit
            file_permissions &= ~S_IRUSR; // prohibit
        }
        if (permission_pair->permissions.create_write) {
            dir_permissions |= S_IWUSR; // allow
            file_permissions |= S_IWUSR; // allow
        }
        else {
            dir_permissions &= ~S_IWUSR; // prohibit
            file_permissions &= ~S_IWUSR; // prohibit
        }
        if (permission_pair->permissions.traverse_exec) {
            dir_permissions |= S_IXUSR; // allow
            file_permissions |= S_IXUSR; // allow
        }
        else {
            dir_permissions &= ~S_IXUSR; // prohibit
            file_permissions &= ~S_IXUSR; // prohibit
        }
    }

    if (component_metadata->group_permissions.len > 0) {
        /* TODO: the default libcsuit handler doesn't handle multiple groups */
        suit_permission_pair_t *permission_pair = NULL;
        for (size_t i = 0; i < component_metadata->group_permissions.len; i++) {
            gid_t tmp_group_id = suit_get_group_id_from_actor_id(component_metadata->group_permissions.permission_map[i].actor);
            if (tmp_group_id == UINT_MAX) {
                return -1;
            }
            if (group_id == tmp_group_id) {
                /* creator matches to group */
                permission_pair = (suit_permission_pair_t *)&component_metadata->group_permissions.permission_map[i];
            }
        }
        if (permission_pair == NULL) {
            /* fallthrough, we regard the first group is the creator */
            permission_pair = (suit_permission_pair_t *)&component_metadata->group_permissions.permission_map[0];
            group_id = suit_get_user_id_from_actor_id(permission_pair->actor);
        }
        if (permission_pair->permissions.list_read) {
            dir_permissions |= S_IRGRP; // allow
            file_permissions |= S_IRGRP; // allow
        }
        else {
            dir_permissions &= ~S_IRGRP; // prohibit
            file_permissions &= ~S_IRGRP; // prohibit
        }
        if (permission_pair->permissions.create_write) {
            dir_permissions |= S_IWGRP; // allow
            file_permissions |= S_IWGRP; // allow
        }
        else {
            dir_permissions &= ~S_IWGRP; // prohibit
            file_permissions &= ~S_IWGRP; // prohibit
        }
        if (permission_pair->permissions.traverse_exec) {
            dir_permissions |= S_IXGRP; // allow
            file_permissions |= S_IXGRP; // allow
        }
        else {
            dir_permissions &= ~S_IXGRP; // prohibit
            file_permissions &= ~S_IXGRP; // prohibit
        }
    }

    if (component_metadata->role_permissions.len > 0) {
        /* TODO: the default libcsuit handler doesn't handle roles' permission */
        return -1;
    }

    while ((next_sep = strchr(next_sep + 1, sep)) != NULL) {
        const int dir_name_len = next_sep - file_path;
        if (dir_name_len == 0) {
            // e.g.  /usr/local/bin
            //       ^
            //    hit here
            continue;
        }
        memcpy(dir_name, file_path, dir_name_len);
        dir_name[dir_name_len] = '\0';
        result = mkdir(dir_name, dir_permissions);
        if (result != 0) {
            terrno = errno;
            if (terrno != EEXIST) {
                printf("mkdir(%s) = %d(%s)\n", dir_name, terrno, strerror(terrno));
                return -1;
            }
        }
        result = chown(dir_name, user_id, group_id);
        if (result != 0) {
            terrno = errno;
            printf("chown(%s) = %d(%s)\n", dir_name, terrno, strerror(terrno));
            return -1;
        }
    }

    switch (component_metadata->filetype) {
    case SUIT_FILETYPE_DIRECTORY:
        result = mkdir(file_path, dir_permissions);
        if (result != 0) {
            terrno = errno;
            if (terrno != EEXIST) {
                printf("mkdir(%s) = %d(%s)\n", file_path, terrno, strerror(terrno));
                return -1;
            }
        }
        result = chown(file_path, user_id, group_id);
        if (result != 0) {
            terrno = errno;
            printf("chown(%s) = %d(%s)\n", dir_name, terrno, strerror(terrno));
            return -1;
        }
        write_len = buf_len;
        break;
    case SUIT_FILETYPE_SYMBOLIC:
        memcpy(dir_name, buf, buf_len);
        dir_name[buf_len] = '\0';
        result = symlink(dir_name, file_path);
        if (result != 0) {
            terrno = errno;
            if (terrno != EEXIST) {
                printf("symlink(%s, %s) = %d(%s)\n", dir_name, file_path, terrno, strerror(terrno));
                return -1;
            }
        }
        write_len = buf_len;
        break;
    case SUIT_FILETYPE_REGULAR:
    default:
        fd = creat(file_path, file_permissions);
        if (result != 0) {
            terrno = errno;
            printf("creat(%s) = %d(%s)\n", file_path, terrno, strerror(terrno));
            return -1;
        }
        write_len = write(fd, buf, buf_len);
        result = close(fd);
        if (result != 0) {
            terrno = errno;
            printf("close(%s) = %d(%s)\n", file_path, terrno, strerror(terrno));
            return -1;
        }
        result = chown(file_path, user_id, group_id);
        if (result != 0) {
            terrno = errno;
            printf("chown(%s) = %d(%s)\n", file_path, terrno, strerror(terrno));
            return -1;
        }
        break;
    }
    return write_len;
}
