/* Copyright (C) 2012 Monty Program Ab
   Copyright (C) 2021 Amazon.com, Inc. or its affiliates.
   SPDX-License-Identifier: GPL-2.0


   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA */

#ifndef FLOGGER_SKIP_INCLUDES
#include <my_sys.h>
#include <m_string.h>
#include <my_thread.h>
#include <my_config.h>
#include <stdio.h>
#include <fcntl.h>
#include "mysql/components/services/bits/psi_bits.h"
#include "my_io.h"
#include "sql/mysqld.h"
#include "my_thread_local.h"
#include "mysql/service_mysql_alloc.h"
#include "mysql/psi/mysql_mutex.h"
#include "service_logger.h"
#endif /*FLOGGER_SKIP_INCLUDES*/

#undef flogger_mutex_init
#undef flogger_mutex_destroy
#undef flogger_mutex_lock
#undef flogger_mutex_unlock
#undef mysql_mutex_real_mutex

#define mysql_mutex_real_mutex(A) &(A)->lock.m_mutex.m_u.m_native

#define flogger_mutex_init(A, B, C) pthread_mutex_init(mysql_mutex_real_mutex(B), C)

#define flogger_mutex_destroy(A) pthread_mutex_destroy(mysql_mutex_real_mutex(A))

#define flogger_mutex_lock(A) pthread_mutex_lock(mysql_mutex_real_mutex(A))

#define flogger_mutex_unlock(A) pthread_mutex_unlock(mysql_mutex_real_mutex(A))

#ifdef HAVE_PSI_INTERFACE
/* These belong to the service initialization */
static PSI_memory_key key_memory_server_audit_logger_handle;
static PSI_mutex_key key_LOCK_logger_service;

static PSI_mutex_info mutex_list[] = {
  {&key_LOCK_logger_service, "logger_handle_st::lock",
   PSI_FLAG_SINGLETON, 0, PSI_DOCUMENT_ME}
};

#else
#define key_memory_server_audit_logger_handle PSI_NOT_INSTRUMENTED
#endif

#define LOG_FLAGS (O_APPEND | O_CREAT | O_WRONLY)

static unsigned int n_dig(unsigned int i)
{
  return (i == 0) ? 0 : ((i < 10) ? 1 : ((i < 100) ? 2 : 3));
}


LOGGER_HANDLE *logger_open(const char *path,
                           unsigned long long size_limit,
                           unsigned int rotations)
{
  LOGGER_HANDLE new_log, *l_perm;
  /*
    I don't think we ever need more rotations,
    but if it's so, the rotation procedure should be adapted to it.
  */
  if (rotations > 999){
    fprintf(stderr, "Number of rotations is greater than 999, skipping..\n");
    return 0;
  }

  new_log.rotations= rotations;
  new_log.size_limit= size_limit;
  new_log.path_len= strlen(fn_format(new_log.path, path,
        mysql_data_home, "", MY_UNPACK_FILENAME));

  if (new_log.path_len+n_dig(rotations)+1 > FN_REFLEN)
  {
    errno= ENAMETOOLONG;
    /* File path too long */
    return 0;
  }
  if ((new_log.file= my_open(new_log.path, LOG_FLAGS, MYF(0))) < 0)
  {
    errno= my_errno();
    /* Check errno for the cause */
    return 0;
  }

  if (!(l_perm= (LOGGER_HANDLE *) my_malloc(key_memory_server_audit_logger_handle, sizeof(LOGGER_HANDLE), MYF(0))))
  {
    my_close(new_log.file, MYF(0));
    new_log.file= -1;
    return 0; /* End of memory */
  }
  *l_perm= new_log;
  flogger_mutex_init(key_LOCK_logger_service, l_perm,
                     MY_MUTEX_INIT_FAST);
  return l_perm;
}

int logger_close(LOGGER_HANDLE *log)
{
  int result;
  File file= log->file;
  flogger_mutex_destroy(log);
  my_free(log);
  if ((result= my_close(file, MYF(0))))
    errno= my_errno();
  return result;
}


static char *logname(LOGGER_HANDLE *log, char *buf, unsigned int n_log)
{
  int count_dig= n_dig(log->rotations);
  int suffix_len= (count_dig == 0) ? 3 : count_dig+2;
  snprintf(buf+log->path_len, suffix_len, ".%0*u", count_dig, n_log);
  return buf;
}

/*
  do_rotate returns either 0 or 1
*/
static int do_rotate(LOGGER_HANDLE *log)
{
  char namebuf[FN_REFLEN];
  int result;
  unsigned int i;
  char *buf_old, *buf_new, *tmp;

  if (log->rotations == 0)
    return 0;

  memcpy(namebuf, log->path, log->path_len);

  buf_new= logname(log, namebuf, log->rotations);
  buf_old= log->path;
  for (i=log->rotations-1; i>0; i--)
  {
    logname(log, buf_old, i);
    if (!access(buf_old, F_OK) &&
        (result= my_rename(buf_old, buf_new, MYF(0))))
      goto exit;
    tmp= buf_old;
    buf_old= buf_new;
    buf_new= tmp;
  }
  if ((result= my_close(log->file, MYF(0))))
    goto exit;
  namebuf[log->path_len]= 0;
  result= my_rename(namebuf, logname(log, log->path, 1), MYF(0));
  log->file= my_open(namebuf, LOG_FLAGS, MYF(0));
exit:
  errno= my_errno();
  return log->file < 0 || result;
}

/*
   Return 1 if we should rotate the log
*/

bool logger_time_to_rotate(LOGGER_HANDLE *log)
{
  my_off_t filesize;
  if (log->rotations > 0 &&
      (filesize= my_tell(log->file, MYF(0))) != (my_off_t) -1 &&
      ((ulonglong) filesize >= log->size_limit))
    return 1;
  return 0;
}


int logger_write_r(LOGGER_HANDLE *log, bool allow_rotations,
                          const char *buffer, size_t size)
{
  int result;

  flogger_mutex_lock(log);
  if (allow_rotations && logger_time_to_rotate(log) && do_rotate(log))
  {
    result= -1;
    errno= my_errno();
    goto exit; /* Log rotation needed but failed */
  }

  result= (int)my_write(log->file, (const uchar *)buffer, size, MYF(0));

exit:
  flogger_mutex_unlock(log);
  return result;
}

int logger_rotate(LOGGER_HANDLE *log)
{
  int result;
  flogger_mutex_lock(log);
  result= do_rotate(log);
  flogger_mutex_unlock(log);
  return result;
}


void logger_init_mutexes()
{
#if defined(HAVE_PSI_INTERFACE) && !defined(FLOGGER_NO_PSI)
    mysql_mutex_register("audit_logger", mutex_list, array_elements(mutex_list));
#endif
}
