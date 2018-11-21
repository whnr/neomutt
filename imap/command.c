/**
 * @file
 * Send/receive commands to/from an IMAP server
 *
 * @authors
 * Copyright (C) 1996-1998,2010,2012 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 1996-1999 Brandon Long <blong@fiction.net>
 * Copyright (C) 1999-2009,2011 Brendan Cully <brendan@kublai.com>
 * Copyright (C) 2018 Richard Russon <rich@flatcap.org>
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

/**
 * @page imap_command Send/receive commands to/from an IMAP server
 *
 * Send/receive commands to/from an IMAP server
 */

#include "config.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "imap_private.h"
#include "mutt/mutt.h"
#include "config/lib.h"
#include "email/lib.h"
#include "conn/conn.h"
#include "mutt.h"
#include "context.h"
#include "globals.h"
#include "imap/imap.h"
#include "mailbox.h"
#include "menu.h"
#include "message.h"
#include "mutt_account.h"
#include "mutt_logging.h"
#include "mutt_socket.h"
#include "mx.h"

/* These Config Variables are only used in imap/command.c */
bool ImapServernoise; ///< Config: (imap) Display server warnings as error messages

#define IMAP_CMD_BUFSIZE 512

/**
 * Capabilities - Server capabilities strings that we understand
 *
 * @note This must be kept in the same order as ImapCaps.
 *
 * @note Gmail documents one string but use another, so we support both.
 */
static const char *const Capabilities[] = {
  "IMAP4",       "IMAP4rev1",      "STATUS",
  "ACL",         "NAMESPACE",      "AUTH=CRAM-MD5",
  "AUTH=GSSAPI", "AUTH=ANONYMOUS", "AUTH=OAUTHBEARER",
  "STARTTLS",    "LOGINDISABLED",  "IDLE",
  "SASL-IR",     "ENABLE",         "CONDSTORE",
  "QRESYNC",     "X-GM-EXT-1",     "X-GM-EXT1",
  NULL,
};

/**
 * cmd_queue_full - Is the IMAP command queue full?
 * @param adata Imap Account data
 * @retval true Queue is full
 */
static bool cmd_queue_full(struct ImapAccountData *adata)
{
  if ((adata->nextcmd + 1) % adata->cmdslots == adata->lastcmd)
    return true;

  return false;
}

/**
 * cmd_new - Create and queue a new command control block
 * @param adata Imap Account data
 * @retval NULL if the pipeline is full
 * @retval ptr New command
 */
static struct ImapCommand *cmd_new(struct ImapAccountData *adata)
{
  struct ImapCommand *cmd = NULL;

  if (cmd_queue_full(adata))
  {
    mutt_debug(3, "IMAP command queue full\n");
    return NULL;
  }

  cmd = adata->cmds + adata->nextcmd;
  adata->nextcmd = (adata->nextcmd + 1) % adata->cmdslots;

  snprintf(cmd->seq, sizeof(cmd->seq), "a%04u", adata->seqno++);
  if (adata->seqno > 9999)
    adata->seqno = 0;

  cmd->state = IMAP_CMD_NEW;

  return cmd;
}

/**
 * cmd_queue - Add a IMAP command to the queue
 * @param adata Imap Account data
 * @param cmdstr Command string
 * @param flags  Server flags, e.g. #IMAP_CMD_POLL
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 *
 * If the queue is full, attempts to drain it.
 */
static int cmd_queue(struct ImapAccountData *adata, const char *cmdstr, int flags)
{
  if (cmd_queue_full(adata))
  {
    mutt_debug(3, "Draining IMAP command pipeline\n");

    const int rc = imap_exec(adata, NULL, flags & IMAP_CMD_POLL);

    if (rc == IMAP_EXEC_ERROR)
      return IMAP_CMD_BAD;
  }

  struct ImapCommand *cmd = cmd_new(adata);
  if (!cmd)
    return IMAP_CMD_BAD;

  if (mutt_buffer_add_printf(adata->cmdbuf, "%s %s\r\n", cmd->seq, cmdstr) < 0)
    return IMAP_CMD_BAD;

  return 0;
}

/**
 * cmd_handle_fatal - When ImapAccountData is in fatal state, do what we can
 * @param adata Imap Account data
 */
static void cmd_handle_fatal(struct ImapAccountData *adata)
{
  adata->status = IMAP_FATAL;

  if (!adata->mailbox)
    return;

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  if (adata->state >= IMAP_SELECTED && (mdata->reopen & IMAP_REOPEN_ALLOW))
  {
    mx_fastclose_mailbox(mdata->ctx);
    mutt_socket_close(adata->conn);
    mutt_error(_("Mailbox %s@%s closed"), adata->conn->account.user,
               adata->conn->account.host);
    adata->state = IMAP_DISCONNECTED;
  }

  imap_close_connection(adata);
  if (!adata->recovering)
  {
    adata->recovering = true;
    if (imap_login(adata))
      mutt_clear_error();
    adata->recovering = false;
  }
}

/**
 * cmd_start - Start a new IMAP command
 * @param adata Imap Account data
 * @param cmdstr Command string
 * @param flags  Command flags, e.g. #IMAP_CMD_QUEUE
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 */
static int cmd_start(struct ImapAccountData *adata, const char *cmdstr, int flags)
{
  int rc;

  if (adata->status == IMAP_FATAL)
  {
    cmd_handle_fatal(adata);
    return -1;
  }

  if (cmdstr && ((rc = cmd_queue(adata, cmdstr, flags)) < 0))
    return rc;

  if (flags & IMAP_CMD_QUEUE)
    return 0;

  if (adata->cmdbuf->dptr == adata->cmdbuf->data)
    return IMAP_CMD_BAD;

  rc = mutt_socket_send_d(adata->conn, adata->cmdbuf->data,
                          (flags & IMAP_CMD_PASS) ? IMAP_LOG_PASS : IMAP_LOG_CMD);
  adata->cmdbuf->dptr = adata->cmdbuf->data;

  /* unidle when command queue is flushed */
  if (adata->state == IMAP_IDLE)
    adata->state = IMAP_SELECTED;

  return (rc < 0) ? IMAP_CMD_BAD : 0;
}

/**
 * cmd_status - parse response line for tagged OK/NO/BAD
 * @param s Status string from server
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 */
static int cmd_status(const char *s)
{
  s = imap_next_word((char *) s);

  if (mutt_str_startswith(s, "OK", CASE_IGNORE))
    return IMAP_CMD_OK;
  if (mutt_str_startswith(s, "NO", CASE_IGNORE))
    return IMAP_CMD_NO;

  return IMAP_CMD_BAD;
}

/**
 * cmd_parse_expunge - Parse expunge command
 * @param adata Imap Account data
 * @param s     String containing MSN of message to expunge
 *
 * cmd_parse_expunge: mark headers with new sequence ID and mark adata to be
 * reopened at our earliest convenience
 */
static void cmd_parse_expunge(struct ImapAccountData *adata, const char *s)
{
  unsigned int exp_msn;
  struct Email *e = NULL;

  mutt_debug(2, "Handling EXPUNGE\n");

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  if (mutt_str_atoui(s, &exp_msn) < 0 || exp_msn < 1 || exp_msn > mdata->max_msn)
    return;

  e = mdata->msn_index[exp_msn - 1];
  if (e)
  {
    /* imap_expunge_mailbox() will rewrite e->index.
     * It needs to resort using SORT_ORDER anyway, so setting to INT_MAX
     * makes the code simpler and possibly more efficient. */
    e->index = INT_MAX;
    imap_edata_get(e)->msn = 0;
  }

  /* decrement seqno of those above. */
  for (unsigned int cur = exp_msn; cur < mdata->max_msn; cur++)
  {
    e = mdata->msn_index[cur];
    if (e)
      imap_edata_get(e)->msn--;
    mdata->msn_index[cur - 1] = e;
  }

  mdata->msn_index[mdata->max_msn - 1] = NULL;
  mdata->max_msn--;

  mdata->reopen |= IMAP_EXPUNGE_PENDING;
}

/**
 * cmd_parse_vanished - Parse vanished command
 * @param adata Imap Account data
 * @param s     String containing MSN of message to expunge
 *
 * Handle VANISHED (RFC7162), which is like expunge, but passes a seqset of UIDs.
 * An optional (EARLIER) argument specifies not to decrement subsequent MSNs.
 */
static void cmd_parse_vanished(struct ImapAccountData *adata, char *s)
{
  bool earlier = false;
  int rc;
  unsigned int uid = 0;

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  mutt_debug(2, "Handling VANISHED\n");

  if (mutt_str_startswith(s, "(EARLIER)", CASE_IGNORE))
  {
    /* The RFC says we should not decrement msns with the VANISHED EARLIER tag.
     * My experimentation says that's crap. */
    earlier = true;
    s = imap_next_word(s);
  }

  char *end_of_seqset = s;
  while (*end_of_seqset)
  {
    if (!strchr("0123456789:,", *end_of_seqset))
      *end_of_seqset = '\0';
    else
      end_of_seqset++;
  }

  struct SeqsetIterator *iter = mutt_seqset_iterator_new(s);
  if (!iter)
  {
    mutt_debug(2, "VANISHED: empty seqset [%s]?\n", s);
    return;
  }

  while ((rc = mutt_seqset_iterator_next(iter, &uid)) == 0)
  {
    struct Email *e = mutt_hash_int_find(mdata->uid_hash, uid);
    if (!e)
      continue;

    unsigned int exp_msn = imap_edata_get(e)->msn;

    /* imap_expunge_mailbox() will rewrite e->index.
     * It needs to resort using SORT_ORDER anyway, so setting to INT_MAX
     * makes the code simpler and possibly more efficient. */
    e->index = INT_MAX;
    imap_edata_get(e)->msn = 0;

    if ((exp_msn < 1) || (exp_msn > mdata->max_msn))
    {
      mutt_debug(1, "VANISHED: msn for UID %u is incorrect.\n", uid);
      continue;
    }
    if (mdata->msn_index[exp_msn - 1] != e)
    {
      mutt_debug(1, "VANISHED: msn_index for UID %u is incorrect.\n", uid);
      continue;
    }

    mdata->msn_index[exp_msn - 1] = NULL;

    if (!earlier)
    {
      /* decrement seqno of those above. */
      for (unsigned int cur = exp_msn; cur < mdata->max_msn; cur++)
      {
        e = mdata->msn_index[cur];
        if (e)
          imap_edata_get(e)->msn--;
        mdata->msn_index[cur - 1] = e;
      }

      mdata->msn_index[mdata->max_msn - 1] = NULL;
      mdata->max_msn--;
    }
  }

  if (rc < 0)
    mutt_debug(1, "VANISHED: illegal seqset %s\n", s);

  mdata->reopen |= IMAP_EXPUNGE_PENDING;

  mutt_seqset_iterator_free(&iter);
}

/**
 * cmd_parse_fetch - Load fetch response into ImapAccountData
 * @param adata Imap Account data
 * @param s     String containing MSN of message to fetch
 *
 * Currently only handles unanticipated FETCH responses, and only FLAGS data.
 * We get these if another client has changed flags for a mailbox we've
 * selected.  Of course, a lot of code here duplicates code in message.c.
 */
static void cmd_parse_fetch(struct ImapAccountData *adata, char *s)
{
  unsigned int msn, uid;
  struct Email *e = NULL;
  char *flags = NULL;
  int uid_checked = 0;
  int server_changes = 0;

  struct ImapMboxData *mdata = adata->mailbox->mdata;

  mutt_debug(3, "Handling FETCH\n");

  if (mutt_str_atoui(s, &msn) < 0)
  {
    mutt_debug(3, "Skipping FETCH response - illegal MSN\n");
    return;
  }

  if ((msn < 1) || (msn > mdata->max_msn))
  {
    mutt_debug(3, "Skipping FETCH response - MSN %u out of range\n", msn);
    return;
  }

  e = mdata->msn_index[msn - 1];
  if (!e || !e->active)
  {
    mutt_debug(3, "Skipping FETCH response - MSN %u not in msn_index\n", msn);
    return;
  }

  mutt_debug(2, "Message UID %u updated\n", imap_edata_get(e)->uid);
  /* skip FETCH */
  s = imap_next_word(s);
  s = imap_next_word(s);

  if (*s != '(')
  {
    mutt_debug(1, "Malformed FETCH response\n");
    return;
  }
  s++;

  while (*s)
  {
    SKIPWS(s);
    size_t plen = mutt_str_startswith(s, "FLAGS", CASE_IGNORE);
    if (plen != 0)
    {
      flags = s;
      if (uid_checked)
        break;

      s += plen;
      SKIPWS(s);
      if (*s != '(')
      {
        mutt_debug(1, "bogus FLAGS response: %s\n", s);
        return;
      }
      s++;
      while (*s && *s != ')')
        s++;
      if (*s == ')')
        s++;
      else
      {
        mutt_debug(1, "Unterminated FLAGS response: %s\n", s);
        return;
      }
    }
    else if ((plen = mutt_str_startswith(s, "UID", CASE_IGNORE)))
    {
      s += plen;
      SKIPWS(s);
      if (mutt_str_atoui(s, &uid) < 0)
      {
        mutt_debug(1, "Illegal UID.  Skipping update.\n");
        return;
      }
      if (uid != imap_edata_get(e)->uid)
      {
        mutt_debug(1, "UID vs MSN mismatch.  Skipping update.\n");
        return;
      }
      uid_checked = 1;
      if (flags)
        break;
      s = imap_next_word(s);
    }
    else if ((plen = mutt_str_startswith(s, "MODSEQ", CASE_IGNORE)))
    {
      s += plen;
      SKIPWS(s);
      if (*s != '(')
      {
        mutt_debug(1, "bogus MODSEQ response: %s\n", s);
        return;
      }
      s++;
      while (*s && *s != ')')
        s++;
      if (*s == ')')
        s++;
      else
      {
        mutt_debug(1, "Unterminated MODSEQ response: %s\n", s);
        return;
      }
    }
    else if (*s == ')')
      break; /* end of request */
    else if (*s)
    {
      mutt_debug(2, "Only handle FLAGS updates\n");
      break;
    }
  }

  if (flags)
  {
    imap_set_flags(adata, e, flags, &server_changes);
    if (server_changes)
    {
      /* If server flags could conflict with mutt's flags, reopen the mailbox. */
      if (e->changed)
        mdata->reopen |= IMAP_EXPUNGE_PENDING;
      else
        mdata->check_status = IMAP_FLAGS_PENDING;
    }
  }
}

/**
 * cmd_parse_capability - set capability bits according to CAPABILITY response
 * @param adata Imap Account data
 * @param s     Command string with capabilities
 */
static void cmd_parse_capability(struct ImapAccountData *adata, char *s)
{
  mutt_debug(3, "Handling CAPABILITY\n");

  s = imap_next_word(s);
  char *bracket = strchr(s, ']');
  if (bracket)
    *bracket = '\0';
  FREE(&adata->capstr);
  adata->capstr = mutt_str_strdup(s);

  memset(adata->capabilities, 0, sizeof(adata->capabilities));

  while (*s)
  {
    for (int i = 0; i < CAPMAX; i++)
    {
      if (mutt_str_word_casecmp(Capabilities[i], s) == 0)
      {
        mutt_bit_set(adata->capabilities, i);
        mutt_debug(4, " Found capability \"%s\": %d\n", Capabilities[i], i);
        break;
      }
    }
    s = imap_next_word(s);
  }
}

/**
 * cmd_parse_list - Parse a server LIST command (list mailboxes)
 * @param adata Imap Account data
 * @param s     Command string with folder list
 */
static void cmd_parse_list(struct ImapAccountData *adata, char *s)
{
  struct ImapList *list = NULL;
  struct ImapList lb;
  char delimbuf[5]; /* worst case: "\\"\0 */
  unsigned int litlen;

  if (adata->cmdresult)
    list = adata->cmdresult;
  else
    list = &lb;

  memset(list, 0, sizeof(struct ImapList));

  /* flags */
  s = imap_next_word(s);
  if (*s != '(')
  {
    mutt_debug(1, "Bad LIST response\n");
    return;
  }
  s++;
  while (*s)
  {
    if (mutt_str_startswith(s, "\\NoSelect", CASE_IGNORE))
      list->noselect = true;
    else if (mutt_str_startswith(s, "\\NoInferiors", CASE_IGNORE))
      list->noinferiors = true;
    /* See draft-gahrns-imap-child-mailbox-?? */
    else if (mutt_str_startswith(s, "\\HasNoChildren", CASE_IGNORE))
      list->noinferiors = true;

    s = imap_next_word(s);
    if (*(s - 2) == ')')
      break;
  }

  /* Delimiter */
  if (!mutt_str_startswith(s, "NIL", CASE_IGNORE))
  {
    delimbuf[0] = '\0';
    mutt_str_strcat(delimbuf, 5, s);
    imap_unquote_string(delimbuf);
    list->delim = delimbuf[0];
  }

  /* Name */
  s = imap_next_word(s);
  /* Notes often responds with literals here. We need a real tokenizer. */
  if (imap_get_literal_count(s, &litlen) == 0)
  {
    if (imap_cmd_step(adata) != IMAP_CMD_CONTINUE)
    {
      adata->status = IMAP_FATAL;
      return;
    }
    list->name = adata->buf;
  }
  else
  {
    imap_unmunge_mbox_name(adata->unicode, s);
    list->name = s;
  }

  if (list->name[0] == '\0')
  {
    adata->delim = list->delim;
    mutt_debug(3, "Root delimiter: %c\n", adata->delim);
  }
}

/**
 * cmd_parse_lsub - Parse a server LSUB (list subscribed mailboxes)
 * @param adata Imap Account data
 * @param s     Command string with folder list
 */
static void cmd_parse_lsub(struct ImapAccountData *adata, char *s)
{
  char buf[STRING];
  char errstr[STRING];
  struct Buffer err, token;
  struct Url url;
  struct ImapList list;

  if (adata->cmdresult)
  {
    /* caller will handle response itself */
    cmd_parse_list(adata, s);
    return;
  }

  if (!ImapCheckSubscribed)
    return;

  adata->cmdresult = &list;
  cmd_parse_list(adata, s);
  adata->cmdresult = NULL;
  /* noselect is for a gmail quirk (#3445) */
  if (!list.name || list.noselect)
    return;

  mutt_debug(3, "Subscribing to %s\n", list.name);

  mutt_str_strfcpy(buf, "mailboxes \"", sizeof(buf));
  mutt_account_tourl(&adata->conn->account, &url);
  /* escape \ and " */
  imap_quote_string(errstr, sizeof(errstr), list.name, true);
  url.path = errstr + 1;
  url.path[strlen(url.path) - 1] = '\0';
  if (mutt_str_strcmp(url.user, ImapUser) == 0)
    url.user = NULL;
  url_tostring(&url, buf + 11, sizeof(buf) - 11, 0);
  mutt_str_strcat(buf, sizeof(buf), "\"");
  mutt_buffer_init(&token);
  mutt_buffer_init(&err);
  err.data = errstr;
  err.dsize = sizeof(errstr);
  if (mutt_parse_rc_line(buf, &token, &err))
    mutt_debug(1, "Error adding subscribed mailbox: %s\n", errstr);
  FREE(&token.data);
}

/**
 * cmd_parse_myrights - Set rights bits according to MYRIGHTS response
 * @param adata Imap Account data
 * @param s     Command string with rights info
 */
static void cmd_parse_myrights(struct ImapAccountData *adata, const char *s)
{
  mutt_debug(2, "Handling MYRIGHTS\n");

  s = imap_next_word((char *) s);
  s = imap_next_word((char *) s);

  /* zero out current rights set */
  memset(adata->mailbox->rights, 0, sizeof(adata->mailbox->rights));

  while (*s && !isspace((unsigned char) *s))
  {
    switch (*s)
    {
      case 'a':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_ADMIN);
        break;
      case 'e':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_EXPUNGE);
        break;
      case 'i':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_INSERT);
        break;
      case 'k':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_CREATE);
        break;
      case 'l':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_LOOKUP);
        break;
      case 'p':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_POST);
        break;
      case 'r':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_READ);
        break;
      case 's':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_SEEN);
        break;
      case 't':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_DELETE);
        break;
      case 'w':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_WRITE);
        break;
      case 'x':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_DELMX);
        break;

      /* obsolete rights */
      case 'c':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_CREATE);
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_DELMX);
        break;
      case 'd':
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_DELETE);
        mutt_bit_set(adata->mailbox->rights, MUTT_ACL_EXPUNGE);
        break;
      default:
        mutt_debug(1, "Unknown right: %c\n", *s);
    }
    s++;
  }
}

/**
 * cmd_parse_search - store SEARCH response for later use
 * @param adata Imap Account data
 * @param s     Command string with search results
 */
static void cmd_parse_search(struct ImapAccountData *adata, const char *s)
{
  unsigned int uid;
  struct Email *e = NULL;
  struct ImapMboxData *mdata = adata->mailbox->mdata;

  mutt_debug(2, "Handling SEARCH\n");

  while ((s = imap_next_word((char *) s)) && *s != '\0')
  {
    if (mutt_str_atoui(s, &uid) < 0)
      continue;
    e = mutt_hash_int_find(mdata->uid_hash, uid);
    if (e)
      e->matched = true;
  }
}

/**
 * cmd_parse_status - Parse status from server
 * @param adata Imap Account data
 * @param s     Command string with status info
 *
 * first cut: just do mailbox update. Later we may wish to cache all mailbox
 * information, even that not desired by mailbox
 */
static void cmd_parse_status(struct ImapAccountData *adata, char *s)
{
  char *value = NULL;
  unsigned int olduv, oldun;
  unsigned int litlen;
  short new = 0;

  char *mailbox = imap_next_word(s);

  /* We need a real tokenizer. */
  if (imap_get_literal_count(mailbox, &litlen) == 0)
  {
    if (imap_cmd_step(adata) != IMAP_CMD_CONTINUE)
    {
      adata->status = IMAP_FATAL;
      return;
    }

    if (strlen(adata->buf) < litlen)
    {
      mutt_debug(1, "Error parsing STATUS mailbox\n");
      return;
    }

    mailbox = adata->buf;
    s = mailbox + litlen;
    *s = '\0';
    s++;
    SKIPWS(s);
  }
  else
  {
    s = imap_next_word(mailbox);
    *(s - 1) = '\0';
    imap_unmunge_mbox_name(adata->unicode, mailbox);
  }

  struct Url url;
  mutt_account_tourl(&adata->conn_account, &url);
  url.path = mailbox;
  char path[PATH_MAX];
  url_tostring(&url, path, sizeof(path), 0);

  struct Mailbox *m = mx_mbox_find2(path);
  if (!m || !m->mdata)
  {
    mutt_debug(3, "Received status for an unexpected mailbox: %s\n", mailbox);
    return;
  }
  struct ImapMboxData *mdata = m->mdata;
  olduv = mdata->uid_validity;
  oldun = mdata->uid_next;

  if (*s++ != '(')
  {
    mutt_debug(1, "Error parsing STATUS\n");
    return;
  }
  while (*s && *s != ')')
  {
    value = imap_next_word(s);

    errno = 0;
    const unsigned long ulcount = strtoul(value, &value, 10);
    if (((errno == ERANGE) && (ulcount == ULONG_MAX)) || ((unsigned int) ulcount != ulcount))
    {
      mutt_debug(1, "Error parsing STATUS number\n");
      return;
    }
    const unsigned int count = (unsigned int) ulcount;

    if (mutt_str_startswith(s, "MESSAGES", CASE_MATCH))
      mdata->messages = count;
    else if (mutt_str_startswith(s, "RECENT", CASE_MATCH))
      mdata->recent = count;
    else if (mutt_str_startswith(s, "UIDNEXT", CASE_MATCH))
      mdata->uid_next = count;
    else if (mutt_str_startswith(s, "UIDVALIDITY", CASE_MATCH))
      mdata->uid_validity = count;
    else if (mutt_str_startswith(s, "UNSEEN", CASE_MATCH))
      mdata->unseen = count;

    s = value;
    if (*s && *s != ')')
      s = imap_next_word(s);
  }
  mutt_debug(3, "%s (UIDVALIDITY: %u, UIDNEXT: %u) %d messages, %d recent, %d unseen\n",
             mdata->name, mdata->uid_validity, mdata->uid_next, mdata->messages,
             mdata->recent, mdata->unseen);

  mutt_debug(3, "Running default STATUS handler\n");

  mutt_debug(3, "Found %s in mailbox list (OV: %u ON: %u U: %d)\n", mailbox,
             olduv, oldun, mdata->unseen);

  if (MailCheckRecent)
  {
    if (olduv && olduv == mdata->uid_validity)
    {
      if (oldun < mdata->uid_next)
        new = (mdata->unseen > 0);
    }
    else if (!olduv && !oldun)
    {
      /* first check per session, use recent. might need a flag for this. */
      new = (mdata->recent > 0);
    }
    else
      new = (mdata->unseen > 0);
  }
  else
    new = (mdata->unseen > 0);

#ifdef USE_SIDEBAR
  if ((m->has_new != new) || (m->msg_count != mdata->messages) ||
      (m->msg_unread != mdata->unseen))
    mutt_menu_set_current_redraw(REDRAW_SIDEBAR);
#endif

  m->has_new = new;
  m->msg_count = mdata->messages;
  m->msg_unread = mdata->unseen;

  // force back to keep detecting new mail until the mailbox is opened
  if (m->has_new)
    mdata->uid_next = oldun;
}

/**
 * cmd_parse_enabled - Record what the server has enabled
 * @param adata Imap Account data
 * @param s     Command string containing acceptable encodings
 */
static void cmd_parse_enabled(struct ImapAccountData *adata, const char *s)
{
  mutt_debug(2, "Handling ENABLED\n");

  while ((s = imap_next_word((char *) s)) && *s != '\0')
  {
    if (mutt_str_startswith(s, "UTF8=ACCEPT", CASE_IGNORE) ||
        mutt_str_startswith(s, "UTF8=ONLY", CASE_IGNORE))
    {
      adata->unicode = true;
    }
    if (mutt_str_startswith(s, "QRESYNC", CASE_IGNORE))
      adata->qresync = true;
  }
}

/**
 * cmd_handle_untagged - fallback parser for otherwise unhandled messages
 * @param adata Imap Account data
 * @retval  0 Success
 * @retval -1 Failure
 */
static int cmd_handle_untagged(struct ImapAccountData *adata)
{
  unsigned int count = 0;
  char *s = imap_next_word(adata->buf);
  char *pn = imap_next_word(s);

  if ((adata->state >= IMAP_SELECTED) && isdigit((unsigned char) *s))
  {
    pn = s;
    s = imap_next_word(s);

    /* EXISTS and EXPUNGE are always related to the SELECTED mailbox for the
     * connection, so update that one.
     */
    if (mutt_str_startswith(s, "EXISTS", CASE_IGNORE))
    {
      mutt_debug(2, "Handling EXISTS\n");

      /* new mail arrived */
      if (mutt_str_atoui(pn, &count) < 0)
      {
        mutt_debug(1, "Malformed EXISTS: '%s'\n", pn);
      }

      if (adata->mailbox)
      {
        struct ImapMboxData *mdata = adata->mailbox->mdata;

        if (!(mdata->reopen & IMAP_EXPUNGE_PENDING) && count < mdata->max_msn)
        {
          /* Notes 6.0.3 has a tendency to report fewer messages exist than
           * it should. */
          mutt_debug(1, "Message count is out of sync\n");
          return 0;
        }
        /* at least the InterChange server sends EXISTS messages freely,
         * even when there is no new mail */
        else if (count == mdata->max_msn)
          mutt_debug(3, "superfluous EXISTS message.\n");
        else
        {
          if (!(mdata->reopen & IMAP_EXPUNGE_PENDING))
          {
            mutt_debug(2, "New mail in %s - %d messages total.\n", mdata->name, count);
            mdata->reopen |= IMAP_NEWMAIL_PENDING;
          }
          mdata->new_mail_count = count;
        }
      }
    }
    /* pn vs. s: need initial seqno */
    else if (mutt_str_startswith(s, "EXPUNGE", CASE_IGNORE))
      cmd_parse_expunge(adata, pn);
    else if (mutt_str_startswith(s, "FETCH", CASE_IGNORE))
      cmd_parse_fetch(adata, pn);
  }
  else if ((adata->state >= IMAP_SELECTED) && mutt_str_startswith(s, "VANISHED", CASE_IGNORE))
    cmd_parse_vanished(adata, pn);
  else if (mutt_str_startswith(s, "CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, s);
  else if (mutt_str_startswith(s, "OK [CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, pn);
  else if (mutt_str_startswith(pn, "OK [CAPABILITY", CASE_IGNORE))
    cmd_parse_capability(adata, imap_next_word(pn));
  else if (mutt_str_startswith(s, "LIST", CASE_IGNORE))
    cmd_parse_list(adata, s);
  else if (mutt_str_startswith(s, "LSUB", CASE_IGNORE))
    cmd_parse_lsub(adata, s);
  else if (mutt_str_startswith(s, "MYRIGHTS", CASE_IGNORE))
    cmd_parse_myrights(adata, s);
  else if (mutt_str_startswith(s, "SEARCH", CASE_IGNORE))
    cmd_parse_search(adata, s);
  else if (mutt_str_startswith(s, "STATUS", CASE_IGNORE))
    cmd_parse_status(adata, s);
  else if (mutt_str_startswith(s, "ENABLED", CASE_IGNORE))
    cmd_parse_enabled(adata, s);
  else if (mutt_str_startswith(s, "BYE", CASE_IGNORE))
  {
    mutt_debug(2, "Handling BYE\n");

    /* check if we're logging out */
    if (adata->status == IMAP_BYE)
      return 0;

    /* server shut down our connection */
    s += 3;
    SKIPWS(s);
    mutt_error("%s", s);
    cmd_handle_fatal(adata);

    return -1;
  }
  else if (ImapServernoise && mutt_str_startswith(s, "NO", CASE_IGNORE))
  {
    mutt_debug(2, "Handling untagged NO\n");

    /* Display the warning message from the server */
    mutt_error("%s", s + 2);
  }

  return 0;
}

/**
 * imap_cmd_start - Given an IMAP command, send it to the server
 * @param adata Imap Account data
 * @param cmdstr Command string to send
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 *
 * If cmdstr is NULL, sends queued commands.
 */
int imap_cmd_start(struct ImapAccountData *adata, const char *cmdstr)
{
  return cmd_start(adata, cmdstr, 0);
}

/**
 * imap_cmd_step - Reads server responses from an IMAP command
 * @param adata Imap Account data
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 *
 * detects tagged completion response, handles untagged messages, can read
 * arbitrarily large strings (using malloc, so don't make it _too_ large!).
 */
int imap_cmd_step(struct ImapAccountData *adata)
{
  if (!adata)
    return -1;

  size_t len = 0;
  int c;
  int rc;
  int stillrunning = 0;
  struct ImapCommand *cmd = NULL;

  if (adata->status == IMAP_FATAL)
  {
    cmd_handle_fatal(adata);
    return IMAP_CMD_BAD;
  }

  /* read into buffer, expanding buffer as necessary until we have a full
   * line */
  do
  {
    if (len == adata->blen)
    {
      mutt_mem_realloc(&adata->buf, adata->blen + IMAP_CMD_BUFSIZE);
      adata->blen = adata->blen + IMAP_CMD_BUFSIZE;
      mutt_debug(3, "grew buffer to %u bytes\n", adata->blen);
    }

    /* back up over '\0' */
    if (len)
      len--;
    c = mutt_socket_readln(adata->buf + len, adata->blen - len, adata->conn);
    if (c <= 0)
    {
      mutt_debug(1, "Error reading server response.\n");
      cmd_handle_fatal(adata);
      return IMAP_CMD_BAD;
    }

    len += c;
  }
  /* if we've read all the way to the end of the buffer, we haven't read a
   * full line (mutt_socket_readln strips the \r, so we always have at least
   * one character free when we've read a full line) */
  while (len == adata->blen);

  /* don't let one large string make cmd->buf hog memory forever */
  if ((adata->blen > IMAP_CMD_BUFSIZE) && (len <= IMAP_CMD_BUFSIZE))
  {
    mutt_mem_realloc(&adata->buf, IMAP_CMD_BUFSIZE);
    adata->blen = IMAP_CMD_BUFSIZE;
    mutt_debug(3, "shrank buffer to %u bytes\n", adata->blen);
  }

  adata->lastread = time(NULL);

  /* handle untagged messages. The caller still gets its shot afterwards. */
  if ((mutt_str_startswith(adata->buf, "* ", CASE_MATCH) ||
       mutt_str_startswith(imap_next_word(adata->buf), "OK [", CASE_MATCH)) &&
      cmd_handle_untagged(adata))
  {
    return IMAP_CMD_BAD;
  }

  /* server demands a continuation response from us */
  if (adata->buf[0] == '+')
    return IMAP_CMD_RESPOND;

  /* Look for tagged command completions.
   *
   * Some response handlers can end up recursively calling
   * imap_cmd_step() and end up handling all tagged command
   * completions.
   * (e.g. FETCH->set_flag->set_header_color->~h pattern match.)
   *
   * Other callers don't even create an adata->cmds entry.
   *
   * For both these cases, we default to returning OK */
  rc = IMAP_CMD_OK;
  c = adata->lastcmd;
  do
  {
    cmd = &adata->cmds[c];
    if (cmd->state == IMAP_CMD_NEW)
    {
      if (mutt_str_startswith(adata->buf, cmd->seq, CASE_MATCH))
      {
        if (!stillrunning)
        {
          /* first command in queue has finished - move queue pointer up */
          adata->lastcmd = (adata->lastcmd + 1) % adata->cmdslots;
        }
        cmd->state = cmd_status(adata->buf);
        /* bogus - we don't know which command result to return here. Caller
         * should provide a tag. */
        rc = cmd->state;
      }
      else
        stillrunning++;
    }

    c = (c + 1) % adata->cmdslots;
  } while (c != adata->nextcmd);

  if (stillrunning)
    rc = IMAP_CMD_CONTINUE;
  else
  {
    mutt_debug(3, "IMAP queue drained\n");
    imap_cmd_finish(adata);
  }

  return rc;
}

/**
 * imap_code - Was the command successful
 * @param s IMAP command status
 * @retval 1 Command result was OK
 * @retval 0 If NO or BAD
 */
bool imap_code(const char *s)
{
  return cmd_status(s) == IMAP_CMD_OK;
}

/**
 * imap_cmd_trailer - Extra information after tagged command response if any
 * @param adata Imap Account data
 * @retval ptr Extra command information (pointer into adata->buf)
 * @retval ""  Error (static string)
 */
const char *imap_cmd_trailer(struct ImapAccountData *adata)
{
  static const char *notrailer = "";
  const char *s = adata->buf;

  if (!s)
  {
    mutt_debug(2, "not a tagged response\n");
    return notrailer;
  }

  s = imap_next_word((char *) s);
  if (!s || (!mutt_str_startswith(s, "OK", CASE_IGNORE) &&
             !mutt_str_startswith(s, "NO", CASE_IGNORE) &&
             !mutt_str_startswith(s, "BAD", CASE_IGNORE)))
  {
    mutt_debug(2, "not a command completion: %s\n", adata->buf);
    return notrailer;
  }

  s = imap_next_word((char *) s);
  if (!s)
    return notrailer;

  return s;
}

/**
 * imap_exec - Execute a command and wait for the response from the server
 * @param adata Imap Account data
 * @param cmdstr Command to execute
 * @param flags  Flags (see below)
 * @retval #IMAP_EXEC_SUCCESS Command successful or queued
 * @retval #IMAP_EXEC_ERROR   Command returned an error
 * @retval #IMAP_EXEC_FATAL   Imap connection failure
 *
 * Also, handle untagged responses.
 *
 * Flags:
 * * #IMAP_CMD_PASS: Command contains a password. Suppress logging.
 * * #IMAP_CMD_QUEUE: Only queue command, do not execute.
 * * #IMAP_CMD_POLL: Poll the socket for a response before running imap_cmd_step().
 */
int imap_exec(struct ImapAccountData *adata, const char *cmdstr, int flags)
{
  int rc;

  rc = cmd_start(adata, cmdstr, flags);
  if (rc < 0)
  {
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  if (flags & IMAP_CMD_QUEUE)
    return IMAP_EXEC_SUCCESS;

  if ((flags & IMAP_CMD_POLL) && (ImapPollTimeout > 0) &&
      (mutt_socket_poll(adata->conn, ImapPollTimeout)) == 0)
  {
    mutt_error(_("Connection to %s timed out"), adata->conn->account.host);
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  /* Allow interruptions, particularly useful if there are network problems. */
  mutt_sig_allow_interrupt(1);
  do
    rc = imap_cmd_step(adata);
  while (rc == IMAP_CMD_CONTINUE);
  mutt_sig_allow_interrupt(0);

  if (rc == IMAP_CMD_NO)
    return IMAP_EXEC_ERROR;
  else if (rc != IMAP_CMD_OK)
  {
    if (adata->status != IMAP_FATAL)
      return IMAP_EXEC_ERROR;

    mutt_debug(1, "command failed: %s\n", adata->buf);
    return IMAP_EXEC_FATAL;
  }

  return IMAP_EXEC_SUCCESS;
}

/**
 * imap_cmd_finish - Attempt to perform cleanup
 * @param adata Imap Account data
 *
 * Attempts to perform cleanup (eg fetch new mail if detected, do expunge).
 * Called automatically by imap_cmd_step(), but may be called at any time.
 * Called by imap_check_mailbox() just before the index is refreshed, for
 * instance.
 */
void imap_cmd_finish(struct ImapAccountData *adata)
{
  struct ImapMboxData *mdata = NULL;

  if (!adata)
    return;

  if (adata->mailbox)
    mdata = adata->mailbox->mdata;

  if (adata->status == IMAP_FATAL)
  {
    adata->closing = false;
    cmd_handle_fatal(adata);
    return;
  }

  if (!(adata->state >= IMAP_SELECTED) || (adata->mailbox && adata->closing))
  {
    adata->closing = false;
    return;
  }

  adata->closing = false;

  if (mdata && mdata->reopen & IMAP_REOPEN_ALLOW)
  {
    unsigned int count = mdata->new_mail_count;

    if (!(mdata->reopen & IMAP_EXPUNGE_PENDING) &&
        (mdata->reopen & IMAP_NEWMAIL_PENDING) && count > mdata->max_msn)
    {
      /* read new mail messages */
      mutt_debug(2, "Fetching new mail\n");
      /* check_status: index uses imap_check_mailbox to detect
       *   whether the index needs updating */
      mdata->check_status = IMAP_NEWMAIL_PENDING;
      imap_read_headers(adata, mdata->max_msn + 1, count, false);
    }
    else if (mdata->reopen & IMAP_EXPUNGE_PENDING)
    {
      mutt_debug(2, "Expunging mailbox\n");
      imap_expunge_mailbox(adata);
      /* Detect whether we've gotten unexpected EXPUNGE messages */
      if ((mdata->reopen & IMAP_EXPUNGE_PENDING) && !(mdata->reopen & IMAP_EXPUNGE_EXPECTED))
        mdata->check_status = IMAP_EXPUNGE_PENDING;
      mdata->reopen &=
          ~(IMAP_EXPUNGE_PENDING | IMAP_NEWMAIL_PENDING | IMAP_EXPUNGE_EXPECTED);
    }
  }

  adata->status = 0;
}

/**
 * imap_cmd_idle - Enter the IDLE state
 * @param adata Imap Account data
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 */
int imap_cmd_idle(struct ImapAccountData *adata)
{
  int rc;

  if (cmd_start(adata, "IDLE", IMAP_CMD_POLL) < 0)
  {
    cmd_handle_fatal(adata);
    return -1;
  }

  if ((ImapPollTimeout > 0) && (mutt_socket_poll(adata->conn, ImapPollTimeout)) == 0)
  {
    mutt_error(_("Connection to %s timed out"), adata->conn->account.host);
    cmd_handle_fatal(adata);
    return -1;
  }

  do
    rc = imap_cmd_step(adata);
  while (rc == IMAP_CMD_CONTINUE);

  if (rc == IMAP_CMD_RESPOND)
  {
    /* successfully entered IDLE state */
    adata->state = IMAP_IDLE;
    /* queue automatic exit when next command is issued */
    mutt_buffer_addstr(adata->cmdbuf, "DONE\r\n");
    rc = IMAP_CMD_OK;
  }
  if (rc != IMAP_CMD_OK)
  {
    mutt_debug(1, "error starting IDLE\n");
    return -1;
  }

  return 0;
}
