output = tt.out

cc = gcc

cflags = -std=c99 -g
lflags = -lcrypto

base_dir = src
tt_dir = src/tt
externals_dir = src/externals

targets = $(base_dir)/main.o \
	  $(tt_dir)/api.o \
	  $(tt_dir)/util.o \
	  $(tt_dir)/base64.o \
	  $(output)

# remove out $(output) as part of $(targets)
linking_targets = $(filter-out $(output), $(targets))

all: $(targets)

$(output): $(linking_targets)
	$(cc) $(lflags) $^ -o $(output)

$(base_dir)/main.o: $(base_dir)/main.c
	$(cc) -c $< $(cflags) -o $@

$(tt_dir)/api.o: $(tt_dir)/api.c $(tt_dir)/api.h
	$(cc) -c $< $(cflags) -o $@

$(tt_dir)/util.o: $(tt_dir)/util.c $(tt_dir)/util.h
	$(cc) -c $< $(cflags) -o $@

$(tt_dir)/base64.o: $(tt_dir)/base64.c $(tt_dir)/base64.h
	$(cc) -c $< $(cflags) -o $@

clean:
	rm -rf *.out
	find . -type f -name *.o -exec rm -rf {} +
