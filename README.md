<a href="https://github.com/haxpor/donate"><img src="https://img.shields.io/badge/$-donate-ff69b4.svg?maxAge=2592000&amp;style=flat" alt="donate"></a>

# tt

Simple and minimalistic Twitter client implemented in C.

# Dependencies

You will need

* [openssl](https://www.openssl.org/)
* [curl](https://github.com/curl/curl)

Make sure you install these in your system.

# Build and Installation

Use `CMake` to build the project.

* Go to this project directory
* `mkdir build`
* `cmake ..` or for RELEASE build `cmake -DCMAKE_BUILD_TYPE=RELEASE ..`
* `make -j4`
* `sudo make install`

Done

# Install via published packages

## Debian/Ubuntu

* `sudo add-apt-repository ppa:haxpor/combined`
* `sudo apt install tt`

# Setup

> If you install via PPA, it bundled with its own manpage. Just `man tt` to see the instruction on how to set up your environment.

Create a new Twitter app on [https://developer.twitter.com/en/apps](https://developer.twitter.com/en/apps).

Make sure permissions are set to _Read and write_. If you change permissions, you have to regenerate _Keys and tokens_.

Set the following environment variables i.e. `~/.bash_profile` for your _Keys and tokens_ via syntax `export NAME=VALUE`

* `TT_CONSUMER_KEY` - consumer key
* `TT_CONSUMER_SECRET` - consumer secret
* `TT_ACCESS_TOKEN` - access token
* `TT_ACCESS_TOKEN_SECRET` - access token secret

Then on terminal window you're going to execute the program, remember to source the file via `source ~/.bash_profile`.

# Commands Support

- `tt update <tweet text>` - update tweet
- `tt update <tweet text> -f /your/image/path` - update tweet along with a single image file
- `tt update <tweet text> -f /your/image/path1 /your/image/path2 /your/image/pathN` - update tweet along with multiple images up to 4 as supported by Twitter

# License

MIT, Wasin Thonkaew.
