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

# License

MIT, Wasin Thonkaew.
