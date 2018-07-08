proxy_rewriter: proxy_rewriter.c
	gcc -O2 -Wall -o proxy_rewriter $^ -lcap -lnetfilter_queue
