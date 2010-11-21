#
# Makefile for mysql_auth
#

all: mysql_auth

mysql_auth: mysql_auth.c
	gcc  -I /usr/include/mysql/ -O -o mysql_auth mysql_auth.c -lmysqlclient -lconfuse

clean:
	@rm -f mysql_auth