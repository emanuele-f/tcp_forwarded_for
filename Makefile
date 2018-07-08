proxy_rewriter: proxy_rewriter.c
	gcc -O2 -Wall -o proxy_rewriter $^ -lnetfilter_queue
