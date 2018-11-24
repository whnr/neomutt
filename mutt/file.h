/**
 * @file
 * File management functions
 *
 * @authors
 * Copyright (C) 2017 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MUTT_LIB_FILE_H
#define MUTT_LIB_FILE_H

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

struct stat;
extern char *Tmpdir;

/* Flags for mutt_file_read_line() */
#define MUTT_CONT (1 << 0) /**< \-continuation */
#define MUTT_EOL  (1 << 1) /**< don't strip `\n` / `\r\n` */

/* State record for mutt_file_iter_line() */
struct MuttFileIter
{
  char *line;   /**< the line data */
  size_t size;  /**< allocated size of line data */
  int line_num; /**< line number */
};

/* Type of mapping functions for mutt_file_map_lines().
 * d is the usual "user data" passed to callbacks.
 */
typedef bool (*mutt_file_map_t)(char *line, int line_num, void *user_data);

int         mutt_file_check_empty(const char *path);
int         mutt_file_chmod(const char *path, mode_t mode);
int         mutt_file_chmod_add(const char *path, mode_t mode);
int         mutt_file_chmod_add_stat(const char *path, mode_t mode, struct stat *st);
int         mutt_file_chmod_rm(const char *path, mode_t mode);
int         mutt_file_chmod_rm_stat(const char *path, mode_t mode, struct stat *st);
int         mutt_file_copy_bytes(FILE *in, FILE *out, size_t size);
int         mutt_file_copy_stream(FILE *fin, FILE *fout);
time_t      mutt_file_decrease_mtime(const char *f, struct stat *st);
void        mutt_file_expand_fmt(char *dest, size_t destlen, const char *fmt, const char *src);
void        mutt_file_expand_fmt_quote(char *dest, size_t destlen, const char *fmt, const char *src);
int         mutt_file_fclose(FILE **f);
FILE *      mutt_file_fopen(const char *path, const char *mode);
int         mutt_file_fsync_close(FILE **f);
long        mutt_file_get_size(const char *path);
bool        mutt_file_iter_line(struct MuttFileIter *iter, FILE *fp, int flags);
int         mutt_file_lock(int fd, bool excl, bool timeout);
bool        mutt_file_map_lines(mutt_file_map_t func, void *user_data, FILE *fp, int flags);
int         mutt_file_mkdir(const char *path, mode_t mode);
FILE *      mutt_file_mkstemp_full(const char *file, int line, const char *func);
#define     mutt_file_mkstemp() mutt_file_mkstemp_full(__FILE__, __LINE__, __func__)
int         mutt_file_open(const char *path, int flags);
size_t      mutt_file_quote_filename(const char *filename, char *buf, size_t buflen);
char *      mutt_file_read_keyword(const char *file, char *buf, size_t buflen);
char *      mutt_file_read_line(char *s, size_t *size, FILE *fp, int *line, int flags);
int         mutt_file_rename(char *oldfile, char *newfile);
int         mutt_file_rmtree(const char *path);
int         mutt_file_safe_rename(const char *src, const char *target);
void        mutt_file_sanitize_filename(char *f, bool slash);
int         mutt_file_sanitize_regex(char *dest, size_t destlen, const char *src);
void        mutt_file_set_mtime(const char *from, const char *to);
int         mutt_file_symlink(const char *oldpath, const char *newpath);
void        mutt_file_touch_atime(int fd);
void        mutt_file_unlink(const char *s);
void        mutt_file_unlink_empty(const char *path);
int         mutt_file_unlock(int fd);

#endif /* MUTT_LIB_FILE_H */
