output = tt

cc = gcc

cflags = -std=c99 -Isrc/tt -Isrc/externals
lflags = -lcrypto -lcurl

base_dir = src
tt_dir = src/tt
externals_dir = src/externals

required_headers = $(tt_dir)/tt.h $(tt_dir)/tt_types.h $(externals_dir)/mjson.h

targets = $(base_dir)/main.o \
	  $(tt_dir)/tt_api.o \
	  $(tt_dir)/tt_util.o \
	  $(output)

# remove out $(output) as part of $(targets)
linking_targets = $(filter-out $(output), $(targets))

all: $(targets)

$(output): $(linking_targets)
	$(cc) $(lflags) $^ -o $(output)

$(base_dir)/main.o: $(base_dir)/main.c
	$(cc) -c $< $(cflags) -o $@

$(tt_dir)/tt_api.o: $(tt_dir)/tt_api.c $(tt_dir)/tt_api.h $(required_headers)
	$(cc) -c $< $(cflags) -o $@

$(tt_dir)/tt_util.o: $(tt_dir)/tt_util.c $(tt_dir)/tt_util.h $(required_headers)
	$(cc) -c $< $(cflags) -o $@

install:
	cp -p tt /usr/local/bin/tt

clean:
	rm -rf $(output)
	find . -type f -name *.o -exec rm -rf {} +
