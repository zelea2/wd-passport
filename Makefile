CFLAGS = -Wall -O2
INC = inc/sg_lib_data.h inc/sg_pr2serr.h inc/sg_pt_linux.h inc/sg_lib.h inc/sg_pt.h inc/sg_unaligned.h
PROGS = wd-passport
OBJ = wd-passport.o lib/sg_lib.o lib/sg_lib_data.o lib/sg_pt_linux.o lib/lsscsi.o lib/sha256.o

all: $(PROGS)

%.o: %.c $(INC)
	gcc -Iinc -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 \
	 	$(CFLAGS) -c $< -o $@	

wd-passport: $(OBJ)
	gcc $(CFLAGS) -o $@ $^ -lbsd
	sudo chown 0:0 $@
	sudo chmod 4755 $@

clean:
	rm -f *~ $(PROGS) $(OBJ) 
