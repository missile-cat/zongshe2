CC       := gcc
NGINX_SRC:= /usr/local/src/nginx-1.24.0
NGX_CC_OPT := $(shell nginx -V 2>&1 | sed -n "s/.*--with-cc-opt='\([^']*\)'.*/\1/p")
CFLAGS   := -fPIC -O2 $(NGX_CC_OPT) \
    -I$(NGINX_SRC)/src/core \
    -I$(NGINX_SRC)/src/event \
    -I$(NGINX_SRC)/src/http \
    -I$(NGINX_SRC)/src/os/unix
LDFLAGS  := -shared

SRCS     := $(wildcard *.c)
OBJS     := $(SRCS:.c=.o)
TARGET   := ngx_http_waf_module.so

.PHONY: all clean

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET)
