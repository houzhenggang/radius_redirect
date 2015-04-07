all:radius
radius:radius.o slist.o
	gcc radius.o slist.o -lpthread -o radius
radius.o:radius.c
	gcc -c radius.c -o radius.o
slist.o:./_slist/slist.c ./_slist/slist.h
	gcc -c ./_slist/slist.c -o slist.o
clean:
	rm -rf *.o radius 
