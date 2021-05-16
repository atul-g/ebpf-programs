APP=ret_check

CC=clang
CPP=clang++

LIBS=-lbcc_bpf -lelf -lbcc

$(APP): $(APP).cpp
	$(CPP) $(CPP_FLAGS) -o $@ $^ $(LIBS)

.PHONY: clean
clean:
	rm -rf $(APP) *.o
