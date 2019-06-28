CC=gcc
EXEC=main

build: data.c data.h dns.h main.c
	${CC} -o ${EXEC} -I. data.c main.c
