# tt

Simple and minimalistic Twitter client implemented in C.

# Note

Tested and built on macOS 10.14. But it should work on Linux. On Windows, there might be slightly more effort needed.

# Setup

Create a new Twitter app on [https://developer.twitter.com/en/apps](https://developer.twitter.com/en/apps).

Make sure permissions are set to _Read and write_. If you change permissions, you have to regenerate _Keys and tokens_.

Set the following environment variables i.e. `~/.bash_profile` for your _Keys and tokens_ via syntax `export NAME=VALUE`

* `TT_CONSUMER_KEY` - consumer key
* `TT_CONSUMER_SECRET` - consumer secret
* `TT_ACCESS_TOKEN` - access token
* `TT_ACCESS_TOKEN_SECRET` - access token secret

Then on terminal window you're going to execute the program, remember to source the file via `source ~/.bash_profile`.

# Requirement

You will need

* [openssl](https://www.openssl.org/)
* [curl](https://github.com/curl/curl)

installed on your system. In most case, you won't need to do anything as they are likely to be installed already.

But if building the project doesn't work for you, try to install them.
The recommend way is to compile and build it from source to install it. Follow instruction on each of requirement above.

# Build and Installation

Execute `make` to build the project.

Then

Execute `make install` to install it on your system (at `/usr/local/bin`).

# Support Command

- `tt update <tweet text>` - update tweet

# License

MIT, Wasin Thonkaew.
