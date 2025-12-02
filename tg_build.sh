gcc -g -Wall -DTG_TEST_POLL tg_poll.c tg_send.c https.c -I . ./libubox.a ./libustream-ssl.so ./libwolfssl.so 
