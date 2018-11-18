/**
 * @file
 * Handling for email address groups
 *
 * @authors
 * Copyright (C) 2006 Thomas Roessler <roessler@does-not-exist.org>
 * Copyright (C) 2009 Rocco Rutte <pdmef@gmx.net>
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

#ifndef MUTT_GROUP_H
#define MUTT_GROUP_H

#include <stdbool.h>
#include "queue.h"
#include "regex3.h"

struct Address;
struct Buffer;
struct Hash;

#define MUTT_GROUP   0
#define MUTT_UNGROUP 1

/**
 * struct Group - A set of email addresses
 */
struct Group
{
  struct Address *as;
  struct RegexList rs;
  char *name;
};

/**
 * struct GroupNode - A node in a GroupNode
 */
struct GroupNode
{
  struct Group *g;
  STAILQ_ENTRY(GroupNode) entries;
};

STAILQ_HEAD(GroupList, GroupNode);

void mutt_group_context_add(struct GroupList *head, struct Group *group);
void mutt_group_context_destroy(struct GroupList *head);
void mutt_group_context_add_addrlist(struct GroupList *head, struct Address *a);
int mutt_group_context_add_regex(struct GroupList *head, const char *s,
                                 int flags, struct Buffer *err);

bool mutt_group_match(struct Group *g, const char *s);

void mutt_group_context_clear(struct GroupList *head);
int mutt_group_context_remove_regex(struct GroupList *head, const char *s);
int mutt_group_context_remove_addrlist(struct GroupList *head, struct Address *a);

struct Group *mutt_pattern_group(const char *k);

void mutt_groups_init(void);
void mutt_groups_free(void);

#endif /* MUTT_GROUP_H */
