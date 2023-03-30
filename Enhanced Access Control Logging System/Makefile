all: logger acmonitor test_aclog

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -lgmp

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -lgmp

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog -lgmp

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor

