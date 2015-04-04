TARGET  = json_parser

JSON_C_DIR = /usr/local/
CFLAGS += ./_slist/slist.c

CC = gcc
STRIP = strip

SOURCE = radius.c

OBJS = $(SOURCE:%.c=obj/%.o)

$(TARGET): clean $(OBJS)	
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(STRIP) $(TARGET)
	
obj/%.o:%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) $(SOURCE) -c $< -o $@

clean:	
	rm -fr obj $(OBJS) $(TARGET)
