all:idcfg init_id urlcfg init_url idipcfg
idcfg:idcfg.o
	gcc idcfg.o -o idcfg
idcfg.o: idcfg.c idcfg.h
	gcc -c idcfg.c -o idcfg.o
init_id:init_id.o
	gcc init_id.o -o init_id
init_id.o:init_id.c idcfg.h
	gcc -c init_id.c -o init_id.o
urlcfg:urlcfg.o
	gcc urlcfg.o -o urlcfg
urlcfg.o:urlcfg.c
	gcc -c urlcfg.c -o urlcfg.o
init_url:init_url.o
	gcc init_url.o -o init_url
init_url.o:init_url.c
	gcc -c init_url.c -o init_url.o
idipcfg:idipcfg.o
	gcc idipcfg.o -o idipcfg
idipcfg.o:idipcfg.c idcfg.h
	gcc -c idipcfg.c -o idipcfg.o
clean:
	rm -rf *.o idcfg init_id urlcfg init_url
