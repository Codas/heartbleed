# Heartbleed exploit implementation

## Installing

### Installing GHC (Haskell)

Install the [Haskell Platform](https://www.haskell.org/platform).

open a terminal and updated cabal packages and install a new version:
~~~
$ cabal update
$ cabal install cabal-install
~~~

Also make sure to add the new cabal install binary location to your path
(~/.cabal/bin on Mac OS).

### Build the exploit
~~~
$ git clone https://github.com/Codas/heartbleed
$ cd heartbleed
$ cabal sandbox init && cabal install && cabal build
~~~

### Run the exploit binary
~~~
$ ./dist/build/heartbleed/heartbleed --help
~~~

