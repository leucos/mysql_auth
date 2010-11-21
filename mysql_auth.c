/*
 *  mysql_auth.c
 *
 *  Copyright 1998 Frank Liu (frank@ctcqnx4.ctc.cummins.com)
 *  Copyright 2006 Michel Blanc / ERASME (mblanc@erasme.org)
 *
 *  Distributed under the GPL
 *
 *  6 Dec 2006, version 3, mblanc:
 *    1. Ported to MySQL 4.x
 *    2. Removed in while mysql_open/mysql_close calls
 *    2. Added select timeout so connection is reopenend afetr some
 *       configurable time
 *
 *  26 Sep 1999, version 2, frank:
 *    1. fixed a bug where A_TABLE is defined but never used.
 *       (thanks to luciano.ghezzi@linux.it)
 *    2. now you can choose to use either clear text password or
 *       encrypted password in the MySQL table.
 *
 *  13 Nov 1998, version 1, frank:
 *    initial release
 * 
 *  Needs to be compiled/linked with MySQL libs and libconfuse
 * 
 *  On my Linux box:
 *
 *  gcc  -I /usr/include/mysql/ -O -o mysql_auth mysql_auth.c -lmysqlclient -lconfuse
 *
 *  Then modify the squid.conf to use this external auth program:
 *
 authenticate_program /usr/local/squid/libexec/mysql_auth /path/to/config/file
 auth_param basic program /usr/local/squid/libexec/mysql_auth
 auth_param basic children 10
 auth_param basic realm "Cache Cluster"
 auth_param basic credentialsttl 24 hours
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <confuse.h>
#include <mysql.h>

#define TIMEOUT         10800
#define CONNECT_TIMEOUT     2

#define BUFSIZE           256
#define MESSAGESIZE      1024

/*
 * Logging related stuff
 */
enum log_level {
    DEBUG_LEVEL,
    INFO_LEVEL,
    ALERT_LEVEL,
};

static pid_t self;

/*
 * Options will be filled from config file
 */
cfg_bool_t doReconnect = cfg_false;
int logLevel = 3;

char *dbHost = NULL;
int dbPort = 0;
char *dbUser = NULL;
char *dbPassword = NULL;

char *dbBase = NULL;
char *dbTableName = NULL;
char *dbUserColName = NULL;
char *dbPasswordColName = NULL;

cfg_bool_t check_config();
cfg_bool_t file_exists(const char *);
void log_msg (enum log_level, char *);

cfg_bool_t check_config() {
  cfg_bool_t conferror = cfg_false;
  char message[MESSAGESIZE];

  if (! dbHost) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }
  
  if (! dbUser) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  if (! dbPassword) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  if (! dbBase) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  if (! dbTableName) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  if (! dbUserColName) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  if (! dbPasswordColName) {
    snprintf (message, MESSAGESIZE, "fatal error : beside 'reconnect', 'loglevel', 'hostname' and 'port', all options are mandatory\n");
    log_msg(ALERT_LEVEL, message);
    conferror = cfg_true;
  }

  return conferror;
}

cfg_bool_t file_exists(const char * filename) {
  FILE *file;

  if (file = fopen(filename, "r")) {
    fclose(file);
    return cfg_true;
  }
  
  char message[MESSAGESIZE];
  int error = errno;

  snprintf (message, MESSAGESIZE, "unable to open file, error %d : %s\n", error, strerror(error));
  log_msg(ALERT_LEVEL, message);
  return cfg_false;
}

void log_msg (enum log_level lvl, char * message) {
  time_t t;
  struct tm *tmp;
  char sym=0;
  char datestr[200];

  /* 
   * no log if level is below debug level
   * always log if level is alert
   */

  if ((lvl < logLevel) && lvl != ALERT_LEVEL) {
    return;
  }

  if (lvl == DEBUG_LEVEL) {
    sym = '@';
  } else if (lvl == ALERT_LEVEL) {
    sym = '!';
  }

  t = time(NULL);
  tmp = localtime(&t);
  
  if (tmp == NULL) {
    perror("localtime");
    exit(EXIT_FAILURE);
  }

  if (strftime(datestr, sizeof(datestr), "%Y/%m/%d %H:%M:%S", tmp) == 0) {
    fprintf(stderr, "strftime returned 0");
    exit(EXIT_FAILURE);
  }

  if (sym) {
    fprintf(stderr,"%s| mysql_auth(%d): /%c\\%s\n", datestr, (int) self, sym, message);
  } else {
    fprintf(stderr,"%s| mysql_auth(%d): %s\n", datestr, (int) self, message);
  }
}

MYSQL* establish_connection()
{
  MYSQL* sock = NULL;
  char message[MESSAGESIZE];
  int server_version = 0;
  int major_version,minor_version, sub_version;

  /* initialisation de la structure mysql */
  sock = mysql_init(sock);

  /* CONNECT_TIMEOUT seconds max for connection and i/o before we give up
   * so squid doesn't hand waiting for mysql_auth when database host is down
   */
  mysql_options(sock,MYSQL_OPT_CONNECT_TIMEOUT, "CONNECT_TIMEOUT");

  /*
   * doesn't work on linux ?
   * */
  mysql_options(sock,MYSQL_OPT_READ_TIMEOUT, "CONNECT_TIMEOUT");
  mysql_options(sock,MYSQL_OPT_WRITE_TIMEOUT, "CONNECT_TIMEOUT");

  /*
   * unsupported as of 4.1.20 ??
   * mysql_options(sock,MYSQL_OPT_RECONNECT, "0");
   */

  /* we read options from my.cnf, section mysql_auth */
  mysql_options(sock,MYSQL_READ_DEFAULT_GROUP,"mysql_auth");

  //log_msg(INFO_LEVEL, "opening db connection"); 

  if (! mysql_real_connect(sock, dbHost, dbUser, dbPassword, dbBase, 0, NULL, 0)) 
    {
      /* couldn't connect to database server */
      snprintf(message, MESSAGESIZE, 
               "connection error to %s : %s",
               dbHost, mysql_error (sock));
      log_msg(ALERT_LEVEL, message);
      sock = NULL;
    } else {
    server_version = mysql_get_server_version(sock);
    major_version = (int)server_version/10000;
    minor_version = (int)((server_version-major_version*10000)/100);
    sub_version = server_version-major_version*10000-minor_version*100;

    log_msg(DEBUG_LEVEL, "connection opened successfully");
    snprintf(message, MESSAGESIZE,
             "talking with mysqld version %d.%d.%d", 
             major_version,minor_version, sub_version);
    log_msg(INFO_LEVEL, message);
  }
  
  return sock;
}

MYSQL* check_connection(MYSQL *sock)
{
  /* 
   * checks if db connection is alive
   * reopens if not 
   */
  log_msg(DEBUG_LEVEL, "checking connection");

  if (!sock) {
    log_msg(DEBUG_LEVEL, "sock is null");
    sock = establish_connection();
  } else if (mysql_ping(sock)) {
    log_msg(DEBUG_LEVEL, "connection seems dead");
    mysql_close(sock);
    sock = establish_connection();
  }
  return sock;
}

int main(int argc, char *argv[])
{
  const char version[] = "2.0";

  char buf[BUFSIZE], qbuf[BUFSIZE];
  char message[MESSAGESIZE];
  char *p = NULL;
  
  MYSQL *sock;
  MYSQL_RES *res;
  
  fd_set rfds;
  struct timeval tv;
  int retval;

  cfg_opt_t opts[] = {
    CFG_SIMPLE_BOOL("reconnect", &doReconnect),
    CFG_SIMPLE_INT("loglevel", &logLevel),
    CFG_SIMPLE_STR("hostname", &dbHost),
    CFG_SIMPLE_INT("port", &dbPort),
    CFG_SIMPLE_STR("user", &dbUser),
    CFG_SIMPLE_STR("password", &dbPassword),
    CFG_SIMPLE_STR("database", &dbBase),
    CFG_SIMPLE_STR("table", &dbTableName),
    CFG_SIMPLE_STR("usercolumn", &dbUserColName),
    CFG_SIMPLE_STR("passwordcolumn", &dbPasswordColName),
    CFG_END()
  };
  cfg_t *cfg;

  self = getpid();

  /* logLevel is used in log_msg, so initialization musr occur
   * before first call to log_msg
   */
  dbHost = strdup("localhost");
  dbPort = 3306;
  logLevel = 3;
  doReconnect = cfg_false;

  snprintf(message, MESSAGESIZE, "version %s starting (pid %d) with config file %s", version, (int) self, argv[1]);
  log_msg(ALERT_LEVEL, message);

  if (! file_exists(argv[1]) ) {
    snprintf(message, MESSAGESIZE, "fatal error : unable to open configuration file %s", argv[1]);
    log_msg(ALERT_LEVEL, message);
    exit(EXIT_FAILURE);
  }

  cfg = cfg_init(opts, 0);
  cfg_parse(cfg, argv[1]);

  if (! check_config)
    exit(EXIT_FAILURE);

  /* make standard output line buffered */
  if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
    return 1;
 
  /* do necessary stuff to open connection */
  sock = establish_connection();

  while (1) {
    /* select stuff checks if there is something to read on stdin
       if there is nothing for N seconds, the mysql connection is closed
       and reopened so it doesn't time out
    */

    /* clear rfds and watch STDIN */
    FD_ZERO(&rfds);
    FD_SET(0,&rfds);

    /* check for TIMEOUT secs */
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;

    retval = select(1, &rfds, NULL, NULL, &tv);
    
    if (retval == -1)
      perror("select sent retval = -1");
    else if (!retval) {
      // nothing to read past TIMEOUT seconds
      log_msg(ALERT_LEVEL, "time out waiting for data"); 
      
      // close mysql
      log_msg(INFO_LEVEL, "closing db connection"); 
      mysql_close(sock);
      sock = NULL;
      continue;
    }

    /* Read and parse data from stdin */
    if (fgets(buf, BUFSIZE, stdin) == NULL)
      break;
    if ((p = strchr(buf, '\n')) != NULL)
      *p = '\0';          /* strip \n */
    if ((p = strchr(buf, ' ')) == NULL) {
      log_msg(INFO_LEVEL, "invalid data");
      printf("ERR\n");
      continue;
    }
    *p++ = '\0';

    /* buf is username and p is password now */
    snprintf(message, MESSAGESIZE, "checking %s/****** ", buf);
    log_msg(ALERT_LEVEL, message);

		if (doReconnect) {
			/* close the connection... */
			log_msg(INFO_LEVEL, "MYSQL_SUX mode on - closing db connection"); 
			if (sock) {
				mysql_close(sock);
				sock = NULL;
			}
			/* ... and ... reopen thanks to the sordid blocking API
			 * and unsupported MYSQL_OPT_*_TIMEOUTs options
			 */
		}
  
    /* check if db connection is ok */
    sock = check_connection(sock);
    if (!sock) {
      log_msg(DEBUG_LEVEL, "no connection - check aborted");
      printf("ERR\n");
      continue; 
    }

    sprintf(qbuf, "SELECT %s FROM %s WHERE %s ='%s' AND %s ='%s'", 
            dbUserColName, dbTableName, dbUserColName, buf, dbPasswordColName, p);

    if(mysql_query(sock,qbuf) || !(res=mysql_store_result(sock)))
      {
        /* query failed */
        if (mysql_errno(sock)) {
          snprintf(message, MESSAGESIZE, "database connection error : %d %s", mysql_errno(sock), mysql_error(sock));
          log_msg(ALERT_LEVEL, message);
        } else {
          log_msg(ALERT_LEVEL, "database connection error : query failed but mysql error not set !!");
        }
        log_msg(ALERT_LEVEL, "auth failed");
        printf("ERR\n");
        mysql_close(sock);
        sock = NULL;
        continue;
      }
    if ( res->row_count !=0 ) {
      log_msg(ALERT_LEVEL, "auth succeeded");
      printf("OK\n");
    } else {
      log_msg(ALERT_LEVEL, "auth failed");
      printf("ERR\n");
    }
  }
  mysql_free_result(res);
  mysql_close(sock);
  exit(EXIT_SUCCESS);
}
