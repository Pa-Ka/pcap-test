# 변수 선언
CC=g++
CFLAGS= -o
LIB= -lpcap
OBJS=pcap-test.o
TARGET=pcap-test

# 실행 파일 만드는 타겟팅
all: $(TARGET)

# make clean의 명령어를 수행.
clean:
	rm -rf *.o
	rm -rf $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $@ $(OBJS) $(LIB)
# 의존성 오브젝트 생성
pcap-test.o: pcap-test.cpp
