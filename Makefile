NAME = tcp_tracker

$(NAME) :
	@clang main.c -o tcp_tracker -lpcap -lpthread
	@echo "\033[31m> \033[32m$(NAME): Compiled\033[0m"

clean:

	@echo "\033[31m> \033[33m$(NAME): Directory cleaned\033[0m"

all: $(NAME)
