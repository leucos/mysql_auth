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
 *  Needs to be compiled/linked with MySQL libs.
 *  Assuming MySQL header files are installed in /usr/local/mysql/include
 *  and MySQL libs in /usr/local/mysql/lib
 * 
 *  On my Linux box:
 *
 *  gcc  -I /usr/include/mysql/ -O -o mysql_auth mysql_auth.c -lmysqlclient
 *
 *  Then modify the squid.conf to use this external auth program:
 *
 authenticate_program /usr/local/squid/libexec/mysql_auth
 auth_param basic program /usr/local/squid/libexec/mysql_auth
 auth_param basic children 10
 auth_param basic realm "Cache Cluster"
 auth_param basic credentialsttl 24 hours
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
//#include "mysql.h"
#include <mysql.h>


#define TIMEOUT         10800
#define CONNECT_TIMEOUT 	2

#define BUFSIZE           256

#define MESSAGESIZE      1024

#define MYSQL_SUX			1

enum log_level 
	{
		DEBUG_LEVEL, INFO_LEVEL, ALERT_LEVEL
	};

#define LOG_LEVEL	ALERT_LEVEL

static pid_t self;

char *dbHost = NULL;
char *dbUser = NULL;
char *dbPassword = NULL;

char *dbBase = NULL;

char *dbTableName = NULL;
char *dbUserColName = NULL;
char *dbPasswordColName = NULL;

void logmsg (enum log_level lvl, char * message) {
  time_t t;
  struct tm *tmp;
  char sym=0;
  char datestr[200];

  /* 
   * no log if level is below debug level
   * always log if level is alert
   */

  if ((lvl < LOG_LEVEL) && lvl != ALERT_LEVEL) {
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

  //logmsg(INFO_LEVEL, "opening db connection"); 

  if (! mysql_real_connect(sock, dbHost, dbUser, dbPassword, dbBase, 0, NULL, 0)) 
		{
			/* couldn't connect to database server */
			snprintf(message, MESSAGESIZE, 
							 "connection error to %s : %s",
							 dbHost, mysql_error (sock));
			logmsg(ALERT_LEVEL, message);
			sock = NULL;
		} else {
		server_version = mysql_get_server_version(sock);
		major_version = (int)server_version/10000;
		minor_version = (int)((server_version-major_version*10000)/100);
		sub_version = server_version-major_version*10000-minor_version*100;

		logmsg(DEBUG_LEVEL, "connection opened successfully");
		snprintf(message, MESSAGESIZE,
						 "talking with mysqld version %d.%d.%d", 
						 major_version,minor_version, sub_version);
		logmsg(INFO_LEVEL, message);
  }
  
  return sock;
}

MYSQL* check_connection(MYSQL *sock)
{
  /* 
   * checks if db connection is alive
   * reopens if not 
   */
  logmsg(DEBUG_LEVEL, "checking connection");

  if (!sock) {
		logmsg(DEBUG_LEVEL, "sock is null");
		sock = establish_connection();
  } else if (mysql_ping(sock)) {
		logmsg(DEBUG_LEVEL, "connection seems dead");
		mysql_close(sock);
		sock = establish_connection();
  }
  return sock;
}

int main(int argc, char *argv[])
{
  const char version[] = "1.0";

  char buf[BUFSIZE], qbuf[BUFSIZE];
  char message[MESSAGESIZE];
  char *p = NULL;
  
  MYSQL *sock;
  MYSQL_RES *res;
  
  fd_set rfds;
  struct timeval tv;
  int retval;

	char c;

  self = getpid();

  snprintf(message, MESSAGESIZE, "version %s starting (pid %d)", version, (int) self);
  logmsg(ALERT_LEVEL, message);

  while ((c = getopt(argc, argv, "h:u:p:U:P:T:t:c:b:")) != -1 ) {
    switch (c) {
		case 'h':
			dbHost = malloc(strlen(optarg));
			strcpy(dbHost, optarg);
			break;
		case 'u':
			dbUser = malloc(strlen(optarg));
			strcpy(dbUser, optarg);
			break;
		case 'p':
			dbPassword = malloc(strlen(optarg));
			strcpy(dbPassword, optarg);
			break;
		case 'b':
			dbBase = malloc(strlen(optarg));
			strcpy(dbBase, optarg);
			break;
		case 'T':
			dbTableName = malloc(strlen(optarg));
			strcpy(dbTableName, optarg);
			break;
		case 'U':
			dbUserColName = malloc(strlen(optarg));
			strcpy(dbUserColName, optarg);
			break;
		case 'P':
			dbPasswordColName = malloc(strlen(optarg));
			strcpy(dbPasswordColName, optarg);
			break;
		case '?':
			if (isprint (optopt)) {
				snprintf (message, MESSAGESIZE, "Unknown option '-%c'.\n", optopt);
				logmsg(ALERT_LEVEL, message);
			}	else {
				snprintf (message, MESSAGESIZE, "Unknown option character '\\x%x'.\n", optopt);
				logmsg(ALERT_LEVEL, message);
			}
			exit(EXIT_FAILURE);
		default:
			exit(EXIT_FAILURE);
    }
	}

	if (!(dbHost && dbUser && dbPassword && dbTableName && dbBase && dbUserColName && dbPasswordColName)) {
		snprintf (message, MESSAGESIZE, "Error, -u -p -h -U -P -b and -T are all mandatory\n", optopt);
		logmsg(ALERT_LEVEL, message);
			exit(EXIT_FAILURE);
	}

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
      logmsg(ALERT_LEVEL, "time out waiting for data"); 
      
      // close mysql
			logmsg(INFO_LEVEL, "closing db connection"); 
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
			logmsg(INFO_LEVEL, "invalid data");
			(void) printf("ERR\n");
			continue;
		}
		*p++ = '\0';

		/* buf is username and p is password now */
		snprintf(message, MESSAGESIZE, "checking %s/****** ", buf);
		logmsg(ALERT_LEVEL, message);

#ifdef MYSQL_SUX
		/* close the connection... */
		logmsg(INFO_LEVEL, "MYSQL_SUX mode on - closing db connection"); 
		if (sock) {
			mysql_close(sock);
			sock = NULL;
		}
		/* ... and ... reopen thanks to the sordid blocking API
		 * and unsupported MYSQL_OPT_*_TIMEOUTs options
		 */ 
#endif /* MYSQL_SUX */
  
		/* check if db connection is ok */
		sock = check_connection(sock);
		if (!sock) {
			logmsg(DEBUG_LEVEL, "no connection - check aborted");
			(void) printf("ERR\n");
			continue;	
		}

		sprintf(qbuf, "SELECT %s FROM %s WHERE %s ='%s' AND %s ='%s'", 
						dbUserColName, dbTableName, dbUserColName, buf, dbPasswordColName, p);

		if(mysql_query(sock,qbuf) || !(res=mysql_store_result(sock)))
			{
				/* query failed */
				if (mysql_errno(sock)) {
					snprintf(message, MESSAGESIZE, "database connection error : %d %s", mysql_errno(sock), mysql_error(sock));
					logmsg(ALERT_LEVEL, message);
				} else {
					logmsg(ALERT_LEVEL, "database connection error : query failed but mysql error not set !!");
				}
				logmsg(ALERT_LEVEL, "auth failed");
				(void) printf("ERR\n");
				mysql_close(sock);
				sock = NULL;
				continue;
			}
		if ( res->row_count !=0 ) {
			logmsg(ALERT_LEVEL, "auth succeeded");
			(void) printf("OK\n");
		} else {
			logmsg(ALERT_LEVEL, "auth failed");
			(void) printf("ERR\n");
		}
  }
  mysql_free_result(res);
  mysql_close(sock);
  exit(0);
}



